//! Системный прокси на macOS через networksetup: все сетевые службы разом.
//! Не зависит от окружения рабочего стола.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProxy {
    pub http_enabled: bool,
    pub http_server: Option<String>,
    pub http_port: Option<u16>,
    pub https_enabled: bool,
    pub https_server: Option<String>,
    pub https_port: Option<u16>,
    pub socks_enabled: bool,
    pub socks_server: Option<String>,
    pub socks_port: Option<u16>,
    pub bypass_domains: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub services: Vec<(String, ServiceProxy)>,
}

const HOST: &str = "127.0.0.1";
const PORT: &str = "17890";

fn networksetup(args: &[&str]) -> Result<String, String> {
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .map_err(|e| format!("Не удалось вызвать networksetup: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn network_services() -> Result<Vec<String>, String> {
    let text = networksetup(&["-listallnetworkservices"])?;
    Ok(text
        .lines()
        .skip(1) // заголовок "An asterisk (*) denotes that a network service is disabled."
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_owned)
        .collect())
}

fn parse_get_proxy(text: &str) -> (bool, Option<String>, Option<u16>) {
    let mut enabled = false;
    let mut server = None;
    let mut port = None;
    for line in text.lines() {
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or("").trim().to_lowercase();
        let value = parts.next().unwrap_or("").trim().to_string();
        match key.as_str() {
            "enabled" => enabled = value.eq_ignore_ascii_case("yes"),
            "server" => server = (!value.is_empty()).then_some(value),
            "port" => port = value.parse().ok(),
            _ => {}
        }
    }
    (enabled, server, port)
}

fn service_snapshot(service: &str) -> Result<ServiceProxy, String> {
    let http = parse_get_proxy(&networksetup(&["-getwebproxy", service])?);
    let https = parse_get_proxy(&networksetup(&["-getsecurewebproxy", service])?);
    let socks = parse_get_proxy(&networksetup(&["-getsocksfirewallproxy", service])?);
    let bypass = networksetup(&["-getproxybypassdomains", service])?
        .lines()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    Ok(ServiceProxy {
        http_enabled: http.0,
        http_server: http.1,
        http_port: http.2,
        https_enabled: https.0,
        https_server: https.1,
        https_port: https.2,
        socks_enabled: socks.0,
        socks_server: socks.1,
        socks_port: socks.2,
        bypass_domains: (!bypass.is_empty()).then_some(bypass),
    })
}

fn service_apply(service: &str) -> Result<(), String> {
    networksetup(&["-setwebproxy", service, HOST, PORT])?;
    networksetup(&["-setsecurewebproxy", service, HOST, PORT])?;
    networksetup(&["-setsocksfirewallproxy", service, HOST, PORT])?;
    networksetup(&[
        "-setproxybypassdomains",
        service,
        "127.0.0.1",
        "localhost",
        "::1",
    ])?;
    Ok(())
}

fn service_restore(service: &str, proxy: &ServiceProxy) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();
    let restore_one = |enabled: bool,
                       server: &Option<String>,
                       port: Option<u16>,
                       setter: &str,
                       state_flag: &str,
                       errors: &mut Vec<String>| {
        // -setwebproxy включает прокси, состояние отдельно управляется
        // парным флагом -setwebproxystate/-setsecurewebproxystate/
        // -setsocksfirewallproxystate.
        let result = match (enabled, server.as_deref(), port) {
            (true, Some(server), Some(port)) => networksetup(&[state_flag, service, "on"]).and_then(|_| {
                networksetup(&[setter, service, server, &port.to_string()]).map(|_| ())
            }),
            _ => networksetup(&[state_flag, service, "off"]).map(|_| ()),
        };
        if let Err(error) = result {
            errors.push(format!("{service} {state_flag}: {error}"));
        }
    };
    restore_one(
        proxy.http_enabled,
        &proxy.http_server,
        proxy.http_port,
        "-setwebproxy",
        "-setwebproxystate",
        &mut errors,
    );
    restore_one(
        proxy.https_enabled,
        &proxy.https_server,
        proxy.https_port,
        "-setsecurewebproxy",
        "-setsecurewebproxystate",
        &mut errors,
    );
    restore_one(
        proxy.socks_enabled,
        &proxy.socks_server,
        proxy.socks_port,
        "-setsocksfirewallproxy",
        "-setsocksfirewallproxystate",
        &mut errors,
    );
    match proxy.bypass_domains.as_deref() {
        Some(domains) if !domains.is_empty() => {
            let mut args = vec!["-setproxybypassdomains", service];
            args.extend(domains.iter().map(String::as_str));
            if let Err(error) = networksetup(&args) {
                errors.push(format!("{service} bypass: {error}"));
            }
        }
        _ => {
            if let Err(error) = networksetup(&["-setproxybypassdomains", service, "Empty"]) {
                errors.push(format!("{service} bypass reset: {error}"));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub fn enable() -> Result<Snapshot, String> {
    let services = network_services()?;
    let mut snapshot = Snapshot::default();
    let mut applied: Vec<(String, ServiceProxy)> = Vec::new();
    for service in &services {
        match service_snapshot(service) {
            Ok(proxy) => {
                let points_at_inbound = [
                    proxy.http_server.as_deref(),
                    proxy.https_server.as_deref(),
                    proxy.socks_server.as_deref(),
                ]
                .iter()
                .any(|server| *server == Some(HOST))
                    && [
                        proxy.http_port,
                        proxy.https_port,
                        proxy.socks_port,
                    ]
                    .iter()
                    .any(|port| *port == Some(17890));
                if points_at_inbound {
                    return Err("Обнаружен системный прокси, уже направленный на локальный вход KasperVPN. Во избежание прокси-петли не подключаюсь; отключи внешний proxy chain.".into());
                }
                service_apply(service)?;
                applied.push((service.clone(), proxy));
            }
            Err(_) => continue,
        }
    }
    if applied.is_empty() {
        return Err("Не удалось изменить системный прокси macOS: нет доступных сетевых служб".into());
    }
    snapshot.services = applied;
    Ok(snapshot)
}

pub fn restore(snapshot: &Snapshot) -> Result<(), String> {
    let mut first_error: Option<String> = None;
    for (service, proxy) in &snapshot.services {
        if let Err(error) = service_restore(service, proxy) {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_proxy_output() {
        let text = "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\nAuthenticated Proxy Enabled: 0";
        let (enabled, server, port) = parse_get_proxy(text);
        assert!(enabled);
        assert_eq!(server.as_deref(), Some("10.0.0.1"));
        assert_eq!(port, Some(3128));
        let (enabled, server, port) = parse_get_proxy("Enabled: No\nServer: \nPort: 0");
        assert!(!enabled);
        assert_eq!(server, None);
        assert_eq!(port, Some(0));
    }

    #[test]
    #[ignore = "touches live macOS network settings; run explicitly on macOS"]
    fn live_roundtrip_applies_and_restores() {
        let snapshot = enable().expect("enable");
        let text = networksetup(&["-getwebproxy", &snapshot.services[0].0]).unwrap();
        let (enabled, server, port) = parse_get_proxy(&text);
        assert!(enabled);
        assert_eq!(server.as_deref(), Some(HOST));
        assert_eq!(port, Some(17890));
        restore(&snapshot).expect("restore");
    }
}
