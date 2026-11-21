use std::{collections::BTreeSet, error::Error, io, net::IpAddr, path::Path, time::Duration};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
pub const HOSTS_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/hosts";
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct DomainList {
    pub domains: BTreeSet<String>,
    pub source: &'static str,
    pub warning: Option<String>,
}

pub fn normalize_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('\u{feff}');
    let domain = value
        .strip_prefix("*.")
        .unwrap_or(value)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain.len() > 253
        || !domain.contains('.')
        || domain.parse::<IpAddr>().is_ok()
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some(domain)
}

pub fn parse_domains(input: &str) -> BTreeSet<String> {
    let mut domains = BTreeSet::new();
    for line in input.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('!') || line.starts_with(';') {
            continue;
        }
        domains.extend(line.split_whitespace().filter_map(normalize_domain));
    }
    domains
}

fn nonempty(input: &str) -> Result<BTreeSet<String>> {
    let domains = parse_domains(input);
    if domains.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hosts list contains no valid domains",
        )
        .into());
    }
    Ok(domains)
}

async fn download() -> Result<String> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(25))
        .user_agent(concat!("kasper-vpn/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut response = client.get(HOSTS_URL).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_BYTES {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "hosts response exceeds 4 MiB").into(),
            );
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(bytes)?)
}

pub async fn write_atomic(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    tokio::fs::write(&temporary, content).await?;
    if let Err(error) = tokio::fs::rename(&temporary, path).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error.into());
    }
    Ok(())
}

pub async fn load(path: &Path, offline: bool) -> Result<DomainList> {
    load_with_fetch(path, offline, download()).await
}

async fn load_with_fetch<F>(path: &Path, offline: bool, fetch: F) -> Result<DomainList>
where
    F: std::future::Future<Output = Result<String>>,
{
    let warning = if offline {
        None
    } else {
        match fetch
            .await
            .and_then(|text| nonempty(&text).map(|domains| (text, domains)))
        {
            Ok((text, domains)) => {
                let warning = write_atomic(path, &text)
                    .await
                    .err()
                    .map(|error| format!("cannot cache hosts at {}: {error}", path.display()));
                return Ok(DomainList {
                    domains,
                    source: "github",
                    warning,
                });
            }
            Err(error) => Some(format!(
                "GitHub unavailable or invalid: {error}; using {}",
                path.display()
            )),
        }
    };
    let text = tokio::fs::read_to_string(path).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "{}; cannot read {}: {error}",
                warning.as_deref().unwrap_or("offline mode"),
                path.display()
            ),
        )
    })?;
    Ok(DomainList {
        domains: nonempty(&text)?,
        source: "local",
        warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_aliases_ipv6_comments_and_plain_domains() {
        let input = "\u{feff}# comment\r\n0.0.0.0 Discord.COM cdn.discord.com # ignore.me\r\n::1 localhost\n2606:50c0::154 raw.githubusercontent.com\n*.Spotify.com.\nrutracker.org\n! ignore.com\n; ignore.org\n";
        let domains = parse_domains(input);
        assert_eq!(
            domains,
            BTreeSet::from([
                "cdn.discord.com".into(),
                "discord.com".into(),
                "raw.githubusercontent.com".into(),
                "rutracker.org".into(),
                "spotify.com".into(),
            ])
        );
    }

    #[test]
    fn rejects_ips_urls_malformed_domains_and_deduplicates() {
        for invalid in [
            "127.0.0.1",
            "::1",
            "localhost",
            "https://example.com",
            "-a.com",
            "a-.com",
            "a..com",
            "a_b.com",
            "<html>",
        ] {
            assert!(normalize_domain(invalid).is_none(), "{invalid}");
        }
        assert_eq!(parse_domains("EXAMPLE.com\nexample.com.").len(), 1);
        assert!(nonempty("# empty\n0.0.0.0 localhost").is_err());
    }

    #[tokio::test]
    async fn download_failure_and_invalid_response_use_local_fallback() {
        let path = std::env::temp_dir()
            .join(format!("kasper-fallback-{}", std::process::id()))
            .join("hosts");
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, "0.0.0.0 fallback.example\n")
            .await
            .unwrap();
        let failure = async { Err(io::Error::other("network down").into()) };
        let result = load_with_fetch(&path, false, failure).await.unwrap();
        assert_eq!(result.source, "local");
        assert!(result.warning.unwrap().contains("network down"));
        let invalid = async { Ok("<html>error</html>".into()) };
        assert_eq!(
            load_with_fetch(&path, false, invalid).await.unwrap().source,
            "local"
        );
        tokio::fs::remove_dir_all(path.parent().unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn offline_never_polls_network() {
        let path = std::env::temp_dir()
            .join(format!("kasper-offline-{}", std::process::id()))
            .join("hosts");
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, "0.0.0.0 discord.com\n")
            .await
            .unwrap();
        let fetch = async { panic!("network must not be polled") };
        let result = load_with_fetch(&path, true, fetch).await.unwrap();
        assert!(result.domains.contains("discord.com"));
        tokio::fs::remove_dir_all(path.parent().unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn missing_fallback_returns_error() {
        let path = std::env::temp_dir()
            .join(format!("kasper-missing-{}", std::process::id()))
            .join("hosts");
        let failure = async { Err(io::Error::other("network down").into()) };
        assert!(load_with_fetch(&path, false, failure).await.is_err());
    }

    #[tokio::test]
    async fn successful_download_is_cached() {
        let path = std::env::temp_dir()
            .join(format!("kasper-test-{}", std::process::id()))
            .join("hosts");
        let fetched = async { Ok("0.0.0.0 example.com\n".into()) };
        let result = load_with_fetch(&path, false, fetched).await.unwrap();
        assert_eq!(result.source, "github");
        assert!(result.warning.is_none());
        assert_eq!(
            tokio::fs::read_to_string(&path).await.unwrap(),
            "0.0.0.0 example.com\n"
        );
        tokio::fs::remove_dir_all(path.parent().unwrap())
            .await
            .unwrap();
    }
}
