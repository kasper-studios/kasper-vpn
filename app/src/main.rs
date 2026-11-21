mod config;
mod parser;

use std::{env, io, path::PathBuf, process::Stdio, time::Duration};

use config::SplitTunnel;
use parser::Result;
use tokio::process::Command;

const HELP: &str = "kasper-vpn — whitelist split tunneling using sing-box >= 1.12

USAGE:
  kasper-vpn [generate|update|run] [OPTIONS]

COMMANDS:
  generate  Write sing-box JSON (default); does not change system networking
  update    Refresh the local hosts cache, falling back to it on network failure
  run       Generate, validate, then run sing-box in foreground; Ctrl-C stops it

OPTIONS:
  --hosts PATH           Local hosts/cache path (default: lists/hosts)
  --output PATH          Generated config (default: sing-box.json)
  --offline              Only read the local hosts file; never contact GitHub
  --proxy-server HOST    Existing SOCKS5 upstream (default: 127.0.0.1)
  --proxy-port PORT      Existing SOCKS5 upstream port (default: 1080)
  --domain DOMAIN        Add a whitelist domain suffix (repeatable)
  --app PROCESS          Add an exact process name (repeatable, case-sensitive)
  --sing-box PATH        sing-box executable (default: sing-box)
  -h, --help             Show help

Relative paths are resolved from the current working directory.
run requires sing-box, an existing SOCKS5 proxy, and TUN/network privileges.
The proxy must support UDP for Discord voice. Other traffic remains DIRECT.
Process matching depends on OS permissions; encrypted DNS may bypass domain matching.
";

#[derive(Debug)]
struct Options {
    command: String,
    hosts: PathBuf,
    output: PathBuf,
    offline: bool,
    server: String,
    port: u16,
    domains: Vec<String>,
    apps: Vec<String>,
    sing_box: String,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

impl Options {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>> {
        let mut options = Self {
            command: "generate".into(),
            hosts: "lists/hosts".into(),
            output: "sing-box.json".into(),
            offline: false,
            server: "127.0.0.1".into(),
            port: 1080,
            domains: Vec::new(),
            apps: Vec::new(),
            sing_box: "sing-box".into(),
        };
        let mut args = args.into_iter().peekable();
        if args.peek().is_some_and(|arg| !arg.starts_with('-')) {
            options.command = args.next().unwrap();
        }
        if !matches!(options.command.as_str(), "generate" | "update" | "run") {
            return Err(invalid(format!("unknown command: {}", options.command)).into());
        }
        while let Some(arg) = args.next() {
            if matches!(arg.as_str(), "-h" | "--help") {
                return Ok(None);
            }
            if arg == "--offline" {
                options.offline = true;
                continue;
            }
            if !matches!(
                arg.as_str(),
                "--hosts"
                    | "--output"
                    | "--proxy-server"
                    | "--proxy-port"
                    | "--domain"
                    | "--app"
                    | "--sing-box"
            ) {
                return Err(invalid(format!("unknown option: {arg}")).into());
            }
            let value = args
                .next()
                .filter(|value| !value.is_empty() && !value.starts_with("--"))
                .ok_or_else(|| invalid(format!("missing value for {arg}")))?;
            match arg.as_str() {
                "--hosts" => options.hosts = value.into(),
                "--output" => options.output = value.into(),
                "--proxy-server" => {
                    if value.contains(char::is_whitespace) || value.contains('/') {
                        return Err(
                            invalid("proxy server must be a hostname or IP, not a URL").into()
                        );
                    }
                    options.server = value;
                }
                "--proxy-port" => {
                    options.port = value
                        .parse()
                        .map_err(|_| invalid("proxy port must be 1..65535"))?;
                    if options.port == 0 {
                        return Err(invalid("proxy port must be 1..65535").into());
                    }
                }
                "--domain" => options.domains.push(
                    parser::normalize_domain(&value)
                        .ok_or_else(|| invalid(format!("invalid domain: {value}")))?,
                ),
                "--app" => options.apps.push(value),
                "--sing-box" => options.sing_box = value,
                _ => unreachable!(),
            }
        }
        let absolute = |path: &PathBuf| -> Result<PathBuf> {
            let path = std::path::absolute(path)?;
            if path.exists() {
                Ok(path.canonicalize()?)
            } else {
                Ok(path)
            }
        };
        if absolute(&options.hosts)? == absolute(&options.output)? {
            return Err(invalid("hosts and output must be different files").into());
        }
        Ok(Some(options))
    }
}

async fn run_engine(options: &Options) -> Result<()> {
    let status = Command::new(&options.sing_box)
        .arg("check")
        .arg("-c")
        .arg(&options.output)
        .status()
        .await?;
    if !status.success() {
        return Err(io::Error::other(format!("sing-box check failed: {status}")).into());
    }
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut child = Command::new(&options.sing_box)
        .arg("run")
        .arg("-c")
        .arg(&options.output)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    eprintln!(
        "sing-box running (PID {}); Ctrl-C to stop",
        child.id().unwrap_or_default()
    );
    let shutdown = async {
        #[cfg(unix)]
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await?;
        Ok::<(), io::Error>(())
    };
    tokio::select! {
        status = child.wait() => {
            let status = status?;
            if !status.success() {
                return Err(io::Error::other(format!("sing-box exited: {status}")).into());
            }
        }
        result = shutdown => {
            result?;
            // Allow sing-box to remove TUN routes before forcing termination.
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                let _ = Command::new("kill").arg("-TERM").arg(pid.to_string()).status().await;
            }
            if tokio::time::timeout(Duration::from_secs(5), child.wait()).await.is_err() {
                child.kill().await?;
            }
        }
    }
    Ok(())
}

async fn execute() -> Result<()> {
    let Some(options) = Options::parse(env::args().skip(1))? else {
        print!("{HELP}");
        return Ok(());
    };
    let list = parser::load(&options.hosts, options.offline).await?;
    if let Some(warning) = &list.warning {
        eprintln!("warning: {warning}");
    }
    eprintln!("Loaded {} domains ({})", list.domains.len(), list.source);
    if options.command == "update" {
        return Ok(());
    }
    let mut policy = SplitTunnel::whitelist(list.domains, options.server.clone(), options.port);
    policy.domains.extend(options.domains.iter().cloned());
    policy.applications.extend(options.apps.iter().cloned());
    let text = serde_json::to_string_pretty(&policy.generate())? + "\n";
    parser::write_atomic(&options.output, &text).await?;
    eprintln!(
        "Wrote {}: {} domain suffixes, {} process names; default DIRECT",
        options.output.display(),
        policy.domains.len(),
        policy.applications.len()
    );
    if options.command == "run" {
        run_engine(&options).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match execute().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kasper-vpn: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Options>> {
        Options::parse(args.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn defaults_and_whitelist_extensions() {
        let options = parse(&[
            "generate",
            "--offline",
            "--domain",
            "*.EXAMPLE.COM",
            "--app",
            "custom",
            "--proxy-port",
            "1081",
        ])
        .unwrap()
        .unwrap();
        assert!(options.offline);
        assert_eq!(options.domains, ["example.com"]);
        assert_eq!(options.apps, ["custom"]);
        assert_eq!(options.port, 1081);
        assert_eq!(parse(&[]).unwrap().unwrap().command, "generate");
        assert!(parse(&["--help"]).unwrap().is_none());
    }

    #[test]
    fn rejects_invalid_cli_and_overwriting_hosts() {
        for args in [
            vec!["bad"],
            vec!["--proxy-port", "0"],
            vec!["--proxy-port", "65536"],
            vec!["--domain", "https://bad.com"],
            vec!["--app"],
            vec!["--unknown"],
            vec!["--output", "lists/hosts"],
            vec!["--proxy-server", "https://proxy"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }
}
