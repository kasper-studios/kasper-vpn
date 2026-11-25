#[path = "../../src/config.rs"]
#[allow(dead_code)]
mod config;
#[path = "../../src/parser.rs"]
mod parser;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tauri::{Manager, State};
use tokio::{
    process::{Child, Command},
    sync::Mutex,
};
use url::Url;
mod account;
mod apps;
mod mtproto;
mod system_proxy;
use account::AccountClient;

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    #[serde(default)]
    key: String,
    #[serde(default = "default_applications")]
    applications: Vec<String>,
    domains: String,
    #[serde(default = "default_mode")]
    mode: String,
    sing_box_path: String,
    /// Порт встроенного MTProto-прокси для Telegram (режим «telegram»).
    #[serde(default = "default_mtproto_port")]
    mtproto_port: u16,
    /// Секрет MTProto-прокси (32 hex-символа). Генерируется при первом запуске.
    #[serde(default)]
    mtproto_secret: String,
    /// Маскировка TLS/Reality (SNI): "auto", "gateway.icloud.com", "www.samsung.com", "www.microsoft.com", либо свой домен.
    #[serde(default = "default_sni")]
    sni: String,
    /// Порт подключения VLESS: "auto", "443", "8443".
    #[serde(default = "default_port")]
    port: String,
    /// Сервер подключения VLESS: "auto", "84.235.165.153", "18.185.148.63", "92.5.238.211".
    #[serde(default = "default_server")]
    server: String,
    /// Сохранённый логин аккаунта для автоматической авторизации и автообновления ключа.
    #[serde(default)]
    account_username: Option<String>,
    /// Сохранённый пароль аккаунта для автоматической авторизации и автообновления ключа.
    #[serde(default)]
    account_password: Option<String>,
}
fn default_mode() -> String {
    "system".into()
}
fn default_applications() -> Vec<String> {
    vec!["discord".into(), "spotify".into()]
}
fn default_mtproto_port() -> u16 {
    17893
}
fn default_sni() -> String {
    "auto".into()
}
fn default_port() -> String {
    "auto".into()
}
fn default_server() -> String {
    "auto".into()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            key: String::new(),
            applications: default_applications(),
            domains: include_str!("../../lists/hosts").into(),
            mode: default_mode(),
            sing_box_path: "sing-box".into(),
            mtproto_port: default_mtproto_port(),
            mtproto_secret: mtproto::generate_secret(),
            sni: default_sni(),
            port: default_port(),
            server: default_server(),
            account_username: None,
            account_password: None,
        }
    }
}
fn migrate_mode(mode: &str) -> &str {
    if mode == "proxy" { "system" } else { mode }
}
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    connected: bool,
    uptime: u64,
    upload_bytes: u64,
    download_bytes: u64,
    upload_speed: u64,
    download_speed: u64,
    ping: Option<u64>,
    ip: Option<String>,
    error: Option<String>,
    mode: String,
}
struct Session {
    child: Option<Child>,
    started: Option<Instant>,
    status: Status,
    api_secret: String,
    last_sample: Instant,
    settings: Settings,
    mtproto: Option<tokio::task::JoinHandle<()>>,
}
struct Backend {
    dir: PathBuf,
    session: Mutex<Session>,
    account: Mutex<Option<AccountClient>>,
}

fn command(binary: &str) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(binary);
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    // Do not let the KasperVPN UI/backend itself inherit the machine proxy. In system
    // mode it must reach the VLESS API directly, never back into its own local inbound.
    cmd.env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy");
    cmd
}

fn is_loopback_target(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    host == "localhost"
        || host == "localhost.localdomain"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn vpn_http_client() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else if attempt.url().host_str().is_some_and(is_loopback_target) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
}

#[allow(dead_code)]
fn vless(key: &str) -> Result<Value> {
    vless_configured(key, "auto", "auto", "auto")
}

fn vless_configured(
    key: &str,
    sni_override: &str,
    port_override: &str,
    server_override: &str,
) -> Result<Value> {
    let url = Url::parse(key.trim()).map_err(|_| "Некорректная VLESS-ссылка")?;
    if url.scheme() != "vless" || url.password().is_some() {
        return Err("Нужна ссылка vless://UUID@server:port".into());
    }
    uuid::Uuid::parse_str(url.username()).map_err(|_| "Некорректный UUID VLESS")?;
    let orig_host = url
        .host_str()
        .ok_or("В VLESS отсутствует сервер")?
        .trim_matches(['[', ']']);
    let host = match server_override.trim() {
        "" | "auto" => orig_host,
        custom => custom,
    };
    let orig_port = url.port().ok_or("В VLESS отсутствует порт")?;
    let effective_port = match port_override.trim() {
        "" | "auto" => orig_port,
        p => p.parse::<u16>().unwrap_or(orig_port),
    };
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let get = |name: &str| params.get(name).map(String::as_str).unwrap_or("");
    let mut out = json!({"type":"vless", "tag":"proxy", "server":host, "server_port":effective_port, "uuid":url.username()});
    if !get("flow").is_empty() {
        out["flow"] = json!(get("flow"));
    }
    match get("security") {
        "" | "none" => {}
        "tls" | "reality" => {
            let sni = match sni_override.trim() {
                "" | "auto" => match get("sni") {
                    "" if get("security") == "reality" => "gateway.icloud.com",
                    "" => host,
                    "dl.delivery.mp.microsoft.com" | "www.microsoft.com" => "gateway.icloud.com",
                    other => other,
                },
                custom => custom,
            };
            let mut tls = json!({"enabled":true, "server_name": sni});
            if !get("fp").is_empty() {
                tls["utls"] = json!({"enabled":true,"fingerprint":get("fp")});
            }
            if !get("alpn").is_empty() {
                tls["alpn"] = json!(get("alpn").split(',').collect::<Vec<_>>());
            }
            if get("security") == "reality" {
                if get("pbk").is_empty() {
                    return Err("В Reality отсутствует pbk".into());
                }
                tls["reality"] =
                    json!({"enabled":true, "public_key":get("pbk"), "short_id":get("sid")});
                if tls.get("utls").is_none() {
                    tls["utls"] = json!({"enabled":true,"fingerprint":"chrome"});
                }
            }
            out["tls"] = tls;
        }
        _ => return Err("Неподдерживаемый security в VLESS".into()),
    }
    match get("type") {
        "" | "tcp" => {}
        "ws" => {
            let mut transport =
                json!({"type":"ws", "path":if get("path").is_empty() { "/" } else { get("path") }});
            if !get("host").is_empty() {
                transport["headers"] = json!({"Host":get("host")});
            }
            out["transport"] = transport;
        }
        "grpc" => out["transport"] = json!({"type":"grpc","service_name":get("serviceName")}),
        _ => return Err("Поддерживаются только TCP, WebSocket и gRPC".into()),
    }
    Ok(out)
}

#[cfg(any(windows, test))]
fn windows_tun_interface_name(secret: &str) -> String {
    let suffix: String = secret
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(6)
        .collect();
    if suffix.is_empty() {
        "kasper-tun".to_string()
    } else {
        format!("kasper-{suffix}")
    }
}

fn generate(settings: &Settings, secret: &str) -> Result<Value> {
    let normalized_mode = migrate_mode(&settings.mode).to_owned();
    let settings = Settings {
        mode: normalized_mode,
        ..settings.clone()
    };
    if !matches!(settings.mode.as_str(), "system" | "telegram" | "tun") {
        return Err("Неизвестный режим сети".into());
    }
    if settings.mode == "tun" || settings.mode == "system" {
        for line in settings
            .domains
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if parser::normalize_domain(line).is_none() {
                return Err(format!("Некорректный домен: {line}"));
            }
        }
    }
    let mut apps = BTreeSet::new();
    if settings.mode == "tun" || settings.mode == "system" {
        for app in &settings.applications {
            let app_trimmed = app.trim();
            if app_trimmed.is_empty() {
                continue;
            }
            match app_trimmed.to_ascii_lowercase().as_str() {
                "discord" => {
                    apps.extend(
                        [
                            "Discord",
                            "discord",
                            "Discord.exe",
                            "DiscordCanary",
                            "DiscordCanary.exe",
                            "DiscordPTB",
                            "DiscordPTB.exe",
                        ]
                        .iter()
                        .map(|s| s.to_string()),
                    );
                }
                "spotify" => {
                    apps.extend(
                        ["spotify", "Spotify", "Spotify.exe"]
                            .iter()
                            .map(|s| s.to_string()),
                    );
                }
                "steam" => {
                    apps.extend(
                        ["steam", "steam.exe", "steamwebhelper", "steamwebhelper.exe"]
                            .iter()
                            .map(|s| s.to_string()),
                    );
                }
                "browser" => {
                    apps.extend(
                        [
                            "firefox",
                            "firefox.exe",
                            "chrome",
                            "chrome.exe",
                            "chromium",
                            "chromium-browser",
                            "msedge.exe",
                            "brave",
                            "brave.exe",
                        ]
                        .iter()
                        .map(|s| s.to_string()),
                    );
                }
                "telegram" => {
                    apps.extend(
                        ["telegram-desktop", "Telegram", "Telegram.exe", "telegram"]
                            .iter()
                            .map(|s| s.to_string()),
                    );
                }
                _ => {
                    apps.insert(app_trimmed.to_string());
                    if !app_trimmed.ends_with(".exe") {
                        apps.insert(format!("{app_trimmed}.exe"));
                    }
                }
            }
        }
    }
    let mut parsed_domains = if settings.mode == "tun" || settings.mode == "system" {
        parser::parse_domains(&settings.domains)
    } else {
        BTreeSet::new()
    };
    if !parsed_domains.is_empty() {
        for d in config::DEFAULT_DOMAINS {
            parsed_domains.insert((*d).to_string());
        }
    }
    let policy = config::SplitTunnel {
        domains: parsed_domains.clone(),
        applications: apps.clone(),
        proxy_server: String::new(),
        proxy_port: 0,
    };
    let mut cfg = serde_json::to_value(policy.generate()).map_err(|e| e.to_string())?;
    cfg["outbounds"][1] = vless_configured(&settings.key, &settings.sni, &settings.port, &settings.server)?;
    cfg["route"]["find_process"] = json!(true);
    let original_route_rules = cfg["route"]["rules"].as_array().unwrap().clone();
    if settings.mode == "tun" {
        #[cfg(windows)]
        if let Some(tun) = cfg["inbounds"].as_array_mut().and_then(|arr| arr.get_mut(0)) {
            tun["interface_name"] = json!(windows_tun_interface_name(secret));
        }
        cfg["route"]["auto_detect_interface"] = json!(true);
        cfg["route"]["default_domain_resolver"] = json!({"server":"local-dns"});
        cfg["outbounds"][1]["domain_resolver"] = json!({"server":"local-dns"});
        cfg["inbounds"].as_array_mut().unwrap().push(json!({
            "type":"mixed", "tag":"metrics-in", "listen":"127.0.0.1", "listen_port":17892
        }));
        cfg["route"]["rules"].as_array_mut().unwrap().insert(
            1,
            json!({
                "inbound": "metrics-in", "action": "route", "outbound": "proxy"
            }),
        );
    } else {
        cfg["dns"]["rules"] = json!([]);
        cfg["dns"]["servers"] = json!([{"type":"local", "tag":"local-dns"}]);
        cfg["dns"].as_object_mut().unwrap().remove("final");
        cfg["dns"]
            .as_object_mut()
            .unwrap()
            .remove("reverse_mapping");
        cfg["route"]["final"] = json!("direct");
        cfg["route"]["auto_detect_interface"] = json!(true);
        cfg["route"]["default_domain_resolver"] = json!({"server":"local-dns"});
        cfg["outbounds"][1]["domain_resolver"] = json!({"server":"local-dns"});
        cfg["inbounds"] = json!([{
            "type":"mixed", "tag":"local-in", "listen":"127.0.0.1", "listen_port":17890,
            "set_system_proxy": false
        }]);
        cfg["inbounds"].as_array_mut().unwrap().push(json!({
            "type":"mixed", "tag":"metrics-in", "listen":"127.0.0.1", "listen_port":17892
        }));
        // In system mode, localhost traffic is intentionally excluded from the proxy so
        // the VLESS socket and KasperVPN's control plane never re-enter this inbound.
    }
    if settings.mode != "tun" {
        cfg["route"]["rules"] = if settings.mode == "system" {
            let mut rules = vec![
                json!({"action": "sniff"}),
                json!({"ip_cidr":["127.0.0.0/8", "::1/128"], "action":"route", "outbound":"direct"}),
                json!({"inbound":"metrics-in", "action":"route", "outbound":"proxy"}),
                json!({"type": "logical", "mode": "or", "rules": [{"protocol": "dns"}, {"port": 53}], "action": "hijack-dns"}),
            ];
            let has_domains = !parsed_domains.is_empty();
            let has_apps = !apps.is_empty();
            if has_domains {
                let dom_vec: Vec<_> = parsed_domains.iter().collect();
                rules.push(
                    json!({"domain_suffix": dom_vec, "action": "route", "outbound": "proxy"}),
                );
            }
            if has_apps {
                let app_vec: Vec<_> = apps.iter().collect();
                rules
                    .push(json!({"process_name": app_vec, "action": "route", "outbound": "proxy"}));
            }
            if !has_domains && !has_apps {
                rules.push(json!({"inbound": "local-in", "action": "route", "outbound": "proxy"}));
            }
            json!(rules)
        } else {
            let mut rules = vec![
                json!({"action": "sniff"}),
                json!({"ip_cidr":["127.0.0.0/8", "::1/128"], "action":"route", "outbound":"direct"}),
                json!({"inbound":"metrics-in", "action":"route", "outbound":"proxy"}),
                json!({"inbound":"local-in", "action":"route", "outbound":"proxy"}),
                json!({"process_name":["telegram-desktop", "Telegram", "Telegram.exe"], "action":"route", "outbound":"proxy"}),
                json!({"domain_suffix":["t.me", "telegram.me", "telegram.org", "telegram.dog", "telegra.ph", "telegram.space"], "action":"route", "outbound":"proxy"}),
            ];
            rules.extend(
                original_route_rules
                    .iter()
                    .filter(|r| {
                        r.get("domain_suffix").is_none()
                            && r.get("process_name").is_none()
                            && r.get("action") != Some(&json!("sniff"))
                    })
                    .cloned(),
            );
            json!(rules)
        };
    }
    cfg["experimental"] =
        json!({"clash_api":{"external_controller":"127.0.0.1:17891", "secret":secret}});
    Ok(cfg)
}

async fn private_write(path: &Path, text: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await.map_err(|e| e.to_string())?;
    #[cfg(unix)]
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .await
        .map_err(|e| e.to_string())?;
    file.write_all(text.as_bytes())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn load_settings(state: State<'_, Backend>) -> Result<Settings> {
    Ok(state.session.lock().await.settings.clone())
}

#[tauri::command]
async fn login_account(
    username: String,
    password: String,
    state: State<'_, Backend>,
) -> Result<account::LoginResult> {
    let client = AccountClient::new()?;
    let result = client.login(&username, &password).await?;
    let account_info = client.me().await?;
    *state.account.lock().await = Some(client);

    let mut session = state.session.lock().await;
    session.settings.account_username = Some(username);
    session.settings.account_password = Some(password);
    if !account_info.vless_link.is_empty() {
        session.settings.key = account_info.vless_link;
    }
    let _ = private_write(
        &state.dir.join("config.json"),
        &serde_json::to_string_pretty(&session.settings).unwrap_or_default(),
    )
    .await;

    Ok(result)
}

#[tauri::command]
async fn auto_login_saved_account(state: State<'_, Backend>) -> Result<account::Account> {
    let (u, p) = {
        let session = state.session.lock().await;
        (
            session.settings.account_username.clone(),
            session.settings.account_password.clone(),
        )
    };
    if let (Some(username), Some(password)) = (u, p) {
        if !username.trim().is_empty() && !password.trim().is_empty() {
            let client = AccountClient::new()?;
            let _ = client.login(&username, &password).await?;
            let account_info = client.me().await?;
            *state.account.lock().await = Some(client);

            let mut session = state.session.lock().await;
            if !account_info.vless_link.is_empty() {
                session.settings.key = account_info.vless_link.clone();
                let _ = private_write(
                    &state.dir.join("config.json"),
                    &serde_json::to_string_pretty(&session.settings).unwrap_or_default(),
                )
                .await;
            }
            return Ok(account_info);
        }
    }
    Err("Сохранённый аккаунт не найден".into())
}

#[tauri::command]
async fn current_account(state: State<'_, Backend>) -> Result<account::Account> {
    let account = state.account.lock().await;
    if account.is_none() {
        drop(account);
        return auto_login_saved_account(state).await;
    }
    account
        .as_ref()
        .ok_or_else(|| "Войдите в аккаунт KasperVPN".to_string())?
        .me()
        .await
}

#[tauri::command]
async fn logout_account(state: State<'_, Backend>) -> Result<()> {
    let client = state.account.lock().await.take();
    if let Some(client) = client {
        let _ = client.logout().await;
    }
    let mut session = state.session.lock().await;
    session.settings.account_username = None;
    session.settings.account_password = None;
    session.settings.key.clear();
    let _ = private_write(
        &state.dir.join("config.json"),
        &serde_json::to_string_pretty(&session.settings).unwrap_or_default(),
    )
    .await;
    Ok(())
}

#[tauri::command]
async fn clear_account_vless(state: State<'_, Backend>) -> Result<()> {
    let mut session = state.session.lock().await;
    let mut settings = session.settings.clone();
    settings.key.clear();
    private_write(
        &state.dir.join("config.json"),
        &serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?,
    )
    .await?;
    session.settings = settings;
    Ok(())
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountTraffic {
    pub username: String,
    pub used_mb: String,
    pub used_gb: String,
    pub total_gb: String,
    pub percentage: u8,
    pub has_active_subscription: bool,
    pub is_admin: bool,
}

#[tauri::command]
async fn get_account_traffic(state: State<'_, Backend>) -> Result<AccountTraffic> {
    let key = {
        let session = state.session.lock().await;
        session.settings.key.clone()
    };
    if key.trim().is_empty() {
        return Err("Ключ VLESS не указан".into());
    }
    let url = Url::parse(key.trim()).map_err(|_| "Некорректная VLESS-ссылка")?;
    let uuid = url.username();
    if uuid.is_empty() {
        return Err("В ссылке VLESS отсутствует UUID".into());
    }
    let client = vpn_http_client()
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|e| e.to_string())?;
    let mut response = None;
    let mut last_err = String::new();
    for base in &["https://vpn.kasperstudios.xyz", "https://vpn.kasperstudios.xyz:8443"] {
        match client.get(format!("{base}/api/traffic-status?uuid={uuid}")).send().await {
            Ok(res) if res.status().is_success() => {
                response = Some(res);
                break;
            }
            Ok(res) => {
                last_err = format!("Сервер вернул статус {}", res.status());
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }
    let response = response.ok_or_else(|| {
        if last_err.is_empty() {
            "Аккаунт по данному ключу не найден".to_string()
        } else {
            format!("Ошибка связи с сервером: {last_err}")
        }
    })?;
    let data: Value = response.json().await.map_err(|e| e.to_string())?;
    Ok(AccountTraffic {
        username: data["username"].as_str().unwrap_or("").to_string(),
        used_mb: data["usedMB"].as_str().unwrap_or("0.00").to_string(),
        used_gb: data["usedGB"].as_str().unwrap_or("0.00").to_string(),
        total_gb: data["totalGB"].as_str().unwrap_or("0").to_string(),
        percentage: data["percentage"].as_u64().unwrap_or(0) as u8,
        has_active_subscription: data["hasActiveSubscription"].as_bool().unwrap_or(false),
        is_admin: data["isAdmin"].as_bool().unwrap_or(false),
    })
}

#[tauri::command]
async fn save_settings(settings: Settings, state: State<'_, Backend>) -> Result<()> {
    let mut session = state.session.lock().await;
    let mut settings = settings;
    settings.mode = migrate_mode(&settings.mode).to_owned();
    if !matches!(settings.mode.as_str(), "system" | "telegram" | "tun") {
        return Err("Неизвестный режим сети".into());
    }
    private_write(
        &state.dir.join("config.json"),
        &serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?,
    )
    .await?;
    session.settings = settings;
    Ok(())
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingBoxStatus {
    pub installed: bool,
    pub path: String,
    pub version: String,
}

async fn test_sing_box_version(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let mut cmd = command(&path.to_string_lossy());
    cmd.arg("version");
    if let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(3), cmd.output()).await {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let first_line = out_str.lines().next().unwrap_or("sing-box").trim();
            return Some(first_line.to_string());
        }
    }
    None
}

async fn test_sing_box_command(binary: &str) -> Option<String> {
    let mut cmd = command(binary);
    cmd.arg("version");
    if let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(3), cmd.output()).await {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let first_line = out_str.lines().next().unwrap_or("sing-box").trim();
            return Some(first_line.to_string());
        }
    }
    None
}

async fn find_existing_sing_box(
    configured_path: &str,
    backend: &Backend,
) -> Option<(PathBuf, String)> {
    let trimmed = configured_path.trim();
    if !trimmed.is_empty() && trimmed != "sing-box" && trimmed != "sing-box.exe" {
        let p = PathBuf::from(trimmed);
        if let Some(v) = test_sing_box_version(&p).await {
            return Some((p, v));
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            #[cfg(windows)]
            candidates.push(parent.join("sing-box.exe"));
            #[cfg(not(windows))]
            candidates.push(parent.join("sing-box"));
        }
    }

    #[cfg(windows)]
    candidates.push(backend.dir.join("sing-box.exe"));
    #[cfg(not(windows))]
    candidates.push(backend.dir.join("sing-box"));

    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            candidates.push(
                PathBuf::from(local)
                    .join("KasperVPN")
                    .join("bin")
                    .join("sing-box.exe"),
            );
        }
    }

    for candidate in &candidates {
        if let Some(v) = test_sing_box_version(candidate).await {
            return Some((candidate.clone(), v));
        }
    }

    let path_bin = if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    };
    if let Some(v) = test_sing_box_command(path_bin).await {
        return Some((PathBuf::from(path_bin), v));
    }

    None
}

async fn download_sing_box(dest: &Path) -> Result<PathBuf> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(120))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Ошибка создания HTTP клиента: {e}"))?;

    let filename = if cfg!(windows) {
        "sing-box-windows-x64.exe"
    } else {
        "sing-box-linux-x64"
    };

    let urls = [
        format!("https://vpn.kasperstudios.xyz/downloads/{}", filename),
        format!("http://92.5.238.211:3000/downloads/{}", filename),
    ];

    let mut last_err = String::new();
    let mut success_bytes: Option<Vec<u8>> = None;

    for url in urls {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(b) => {
                    success_bytes = Some(b.to_vec());
                    break;
                }
                Err(e) => {
                    last_err = format!("Ошибка загрузки {url}: {e}");
                }
            },
            Ok(resp) => {
                last_err = format!("Сервер {url} вернул статус {}", resp.status());
            }
            Err(e) => {
                last_err = format!("Ошибка соединения с {url}: {e}");
            }
        }
    }

    let bytes = success_bytes
        .ok_or_else(|| format!("Не удалось автоматически скачать sing-box: {last_err}"))?;

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| e.to_string())?;
    }

    let tmp = dest.with_extension("downloading");
    tokio::fs::write(&tmp, &bytes)
        .await
        .map_err(|e| format!("Ошибка сохранения sing-box: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }

    let _ = tokio::fs::remove_file(dest).await;
    tokio::fs::rename(&tmp, dest)
        .await
        .map_err(|e| format!("Ошибка переименования: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755));
    }

    Ok(dest.to_path_buf())
}

async fn ensure_sing_box(configured_path: &str, backend: &Backend) -> Result<PathBuf> {
    if let Some((path, _)) = find_existing_sing_box(configured_path, backend).await {
        return Ok(path);
    }

    #[cfg(windows)]
    let target_path = {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let bin_dir = PathBuf::from(local).join("KasperVPN").join("bin");
            let _ = tokio::fs::create_dir_all(&bin_dir).await;
            bin_dir.join("sing-box.exe")
        } else {
            backend.dir.join("sing-box.exe")
        }
    };

    #[cfg(windows)]
    if let Some(parent) = target_path.parent() {
        let wintun = parent.join("wintun.dll");
        if !wintun.exists() {
            let client = reqwest::Client::builder().no_proxy().build().ok();
            if let Some(c) = client {
                if let Ok(resp) = c
                    .get("https://vpn.kasperstudios.xyz/downloads/wintun.dll")
                    .send()
                    .await
                {
                    if resp.status().is_success() {
                        if let Ok(b) = resp.bytes().await {
                            let _ = tokio::fs::write(&wintun, &b).await;
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    let target_path = backend.dir.join("sing-box");

    download_sing_box(&target_path).await?;

    if let Some((path, _)) = find_existing_sing_box(&target_path.to_string_lossy(), backend).await {
        return Ok(path);
    }

    Ok(target_path)
}

#[tauri::command]
async fn get_sing_box_status(state: State<'_, Backend>) -> Result<SingBoxStatus> {
    let settings = state.session.lock().await.settings.clone();
    if let Some((path, version)) = find_existing_sing_box(&settings.sing_box_path, &state).await {
        Ok(SingBoxStatus {
            installed: true,
            path: path.to_string_lossy().to_string(),
            version,
        })
    } else {
        Ok(SingBoxStatus {
            installed: false,
            path: String::new(),
            version: String::new(),
        })
    }
}

#[tauri::command]
async fn install_sing_box(state: State<'_, Backend>) -> Result<SingBoxStatus> {
    let settings = state.session.lock().await.settings.clone();
    let path = ensure_sing_box(&settings.sing_box_path, &state).await?;
    let version = test_sing_box_version(&path)
        .await
        .unwrap_or_else(|| "sing-box (установлен)".to_string());
    Ok(SingBoxStatus {
        installed: true,
        path: path.to_string_lossy().to_string(),
        version,
    })
}

async fn cleanup_stale_sing_box(dir: &Path) {
    let pid_path = dir.join("sing-box.pid");
    let Ok(raw) = tokio::fs::read_to_string(&pid_path).await else {
        return;
    };
    let _ = tokio::fs::remove_file(&pid_path).await;
    let Ok(pid) = raw.trim().parse::<u32>() else {
        return;
    };

    #[cfg(windows)]
    {
        if let Ok(out) = command("taskkill")
            .args([
                "/FI",
                "IMAGENAME eq sing-box.exe",
                "/PID",
                &pid.to_string(),
                "/T",
                "/F",
            ])
            .output()
            .await
        {
            if out.status.success() {
                tokio::time::sleep(Duration::from_millis(350)).await;
            }
        }
    }

    #[cfg(unix)]
    {
        if let Ok(out) = command("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .await
        {
            if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("sing-box") {
                let _ = command("kill")
                    .args(["-TERM", &pid.to_string()])
                    .status()
                    .await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
}

fn is_tun_adapter_collision(err_msg: &str) -> bool {
    let lower = err_msg.to_ascii_lowercase();
    lower.contains("cannot create a file when that file already exists")
        || lower.contains("open existing adapter")
        || lower.contains("configure tun interface")
}

async fn wait_sing_box_ready(child: &mut Child, dir: &Path, mode: &str) -> Result<()> {
    let timeout = if mode == "tun" {
        Duration::from_secs(18)
    } else {
        Duration::from_secs(4)
    };
    let deadline = Instant::now() + timeout;
    let log_path = dir.join("sing-box.log");
    let pid_path = dir.join("sing-box.pid");

    tokio::time::sleep(Duration::from_millis(200)).await;
    loop {
        if let Some(exit) = child.try_wait().map_err(|e| e.to_string())? {
            let _ = tokio::fs::remove_file(&pid_path).await;
            let log = tokio::fs::read_to_string(&log_path).await.unwrap_or_default();
            return Err(format!(
                "sing-box завершился ({exit}). {log}\nДля TUN нужны права администратора / CAP_NET_ADMIN; без них используйте локальный прокси."
            ));
        }

        if let Ok(log) = tokio::fs::read_to_string(&log_path).await {
            if log.contains("sing-box started (") {
                return Ok(());
            }
        }

        if Instant::now() >= deadline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

async fn spawn_sing_box_attempt(
    settings: &Settings,
    backend: &Backend,
    secret: &str,
) -> Result<Child> {
    let cfg = generate(settings, secret)?;
    let path = backend.dir.join("sing-box.json");
    private_write(
        &path,
        &serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?,
    )
    .await?;

    let check = command(&settings.sing_box_path)
        .arg("check")
        .arg("-c")
        .arg(&path)
        .output();
    let checked = tokio::time::timeout(Duration::from_secs(15), check)
        .await
        .map_err(|_| "Проверка sing-box превысила 15 секунд")?
        .map_err(|e| format!("Ошибка запуска sing-box ({}): {e}", settings.sing_box_path))?;
    if !checked.status.success() {
        return Err(format!(
            "sing-box check: {}",
            String::from_utf8_lossy(&checked.stderr)
        ));
    }

    private_write(&backend.dir.join("sing-box.log"), "").await?;
    let log = std::fs::OpenOptions::new()
        .append(true)
        .open(backend.dir.join("sing-box.log"))
        .map_err(|e| e.to_string())?;
    let mut child = command(&settings.sing_box_path)
        .args(["run", "-c"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;

    if let Some(pid) = child.id() {
        let _ = private_write(&backend.dir.join("sing-box.pid"), &pid.to_string()).await;
    }

    if let Err(err) = wait_sing_box_ready(&mut child, &backend.dir, &settings.mode).await {
        let _ = child.kill().await;
        let _ = tokio::fs::remove_file(backend.dir.join("sing-box.pid")).await;
        return Err(err);
    }

    Ok(child)
}

async fn launch(key: String, mut settings: Settings, backend: &Backend) -> Result<()> {
    let mut key = key;
    if key.trim().is_empty() {
        if let (Some(u), Some(p)) = (&settings.account_username, &settings.account_password) {
            if let Ok(client) = AccountClient::new() {
                if client.login(u, p).await.is_ok() {
                    if let Ok(acc) = client.me().await {
                        if !acc.vless_link.is_empty() {
                            key = acc.vless_link.clone();
                            settings.key = acc.vless_link;
                        }
                    }
                }
            }
        }
    }
    let mut session = backend.session.lock().await;
    if let Some(child) = session.child.as_mut() {
        if child.try_wait().map_err(|e| e.to_string())?.is_none() {
            return Err("VPN уже запущен".into());
        }
    }
    session.child = None;
    cleanup_stale_sing_box(&backend.dir).await;

    if settings.mode == "proxy" {
        settings.mode = "system".into();
    }
    settings.key = key;
    // Секрет MTProto генерируется один раз и сохраняется вместе с настройками,
    // чтобы ссылка для Telegram не менялась между запусками.
    if settings.mode == "telegram" && mtproto::parse_secret(&settings.mtproto_secret).is_none() {
        settings.mtproto_secret = mtproto::generate_secret();
    }

    let resolved_sing_box = ensure_sing_box(&settings.sing_box_path, backend).await?;
    settings.sing_box_path = resolved_sing_box.to_string_lossy().to_string();

    let mut secret = uuid::Uuid::new_v4().to_string();
    let mut child = match spawn_sing_box_attempt(&settings, backend, &secret).await {
        Ok(c) => c,
        Err(first_err) if settings.mode == "tun" && is_tun_adapter_collision(&first_err) => {
            // If Windows Wintun reports a torn-down or wedged adapter, retry immediately with a new interface name.
            tokio::time::sleep(Duration::from_millis(350)).await;
            secret = uuid::Uuid::new_v4().to_string();
            spawn_sing_box_attempt(&settings, backend, &secret).await?
        }
        Err(err) => return Err(err),
    };

    private_write(
        &backend.dir.join("config.json"),
        &serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?,
    )
    .await?;

    if settings.mode == "system" {
        if let Err(error) = system_proxy::enable() {
            let _ = child.kill().await;
            let _ = tokio::fs::remove_file(backend.dir.join("sing-box.pid")).await;
            return Err(error);
        }
    }
    if settings.mode == "telegram" {
        let Some(mtproto_secret) = mtproto::parse_secret(&settings.mtproto_secret) else {
            let _ = child.kill().await;
            let _ = tokio::fs::remove_file(backend.dir.join("sing-box.pid")).await;
            return Err("Некорректный секрет MTProto".into());
        };
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", settings.mtproto_port)).await
        {
            Ok(l) => l,
            Err(e) => {
                let _ = child.kill().await;
                let _ = tokio::fs::remove_file(backend.dir.join("sing-box.pid")).await;
                return Err(format!(
                    "Не удалось занять порт {} для MTProto-прокси: {e}",
                    settings.mtproto_port
                ));
            }
        };
        // Трафик MTProto уходит в mixed-вход sing-box и дальше через VLESS.
        let task = tokio::spawn(async move {
            let _ = mtproto::run(listener, mtproto_secret, Some((String::from("127.0.0.1"), 17890))).await;
        });
        session.mtproto = Some(task);
    }
    session.child = Some(child);
    session.started = Some(Instant::now());
    session.last_sample = Instant::now();
    session.api_secret = secret;
    session.status = Status {
        connected: true,
        mode: settings.mode.clone(),
        ..Default::default()
    };
    session.settings = settings;
    Ok(())
}
#[tauri::command]
async fn connect_vpn(
    key: String,
    split_settings: Settings,
    state: State<'_, Backend>,
) -> Result<()> {
    launch(key, split_settings, &state).await
}
#[tauri::command]
async fn start_vpn(key: String, split_settings: Settings, state: State<'_, Backend>) -> Result<()> {
    launch(key, split_settings, &state).await
}

#[tauri::command]
fn set_system_proxy(enabled: bool) -> Result<()> {
    if enabled {
        system_proxy::enable().map(|_| ())
    } else if system_proxy::active() {
        system_proxy::restore()
    } else {
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MtprotoLink {
    link: Option<String>,
    running: bool,
}
#[tauri::command]
async fn mtproto_link(state: State<'_, Backend>) -> Result<MtprotoLink> {
    let mut session = state.session.lock().await;
    let running = session.mtproto.is_some();
    if mtproto::parse_secret(&session.settings.mtproto_secret).is_none() {
        session.settings.mtproto_secret = mtproto::generate_secret();
    }
    let secret = session.settings.mtproto_secret.trim().to_owned();
    let link = mtproto::parse_secret(&secret)
        .map(|_| mtproto::proxy_link("127.0.0.1", session.settings.mtproto_port, &secret));
    Ok(MtprotoLink { link, running })
}

async fn stop(backend: &Backend) -> Result<()> {
    let mut session = backend.session.lock().await;
    if let Some(mtproto) = session.mtproto.take() {
        mtproto.abort();
    }
    let was_tun = session.settings.mode == "tun";
    if let Some(mut child) = session.child.take() {
        #[cfg(unix)]
        if let Some(id) = child.id() {
            let _ = command("kill")
                .args(["-TERM", &id.to_string()])
                .status()
                .await;
        }
        #[cfg(windows)]
        child.start_kill().map_err(|e| e.to_string())?;
        if tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .is_err()
        {
            child.kill().await.map_err(|e| e.to_string())?;
        }
        #[cfg(windows)]
        if was_tun {
            // Give Windows Wintun kernel driver a moment to release the adapter handle before reconnect.
            tokio::time::sleep(Duration::from_millis(350)).await;
        }
    }
    let _ = was_tun;
    let _ = tokio::fs::remove_file(backend.dir.join("sing-box.pid")).await;
    if system_proxy::active() {
        system_proxy::restore()?;
    }
    session.started = None;
    session.status = Status::default();
    Ok(())
}
#[tauri::command]
async fn disconnect_vpn(state: State<'_, Backend>) -> Result<()> {
    stop(&state).await
}
#[tauri::command]
async fn stop_vpn(state: State<'_, Backend>) -> Result<()> {
    stop(&state).await
}
#[tauri::command]
async fn get_status(state: State<'_, Backend>) -> Result<Status> {
    status(&state).await
}

async fn status(backend: &Backend) -> Result<Status> {
    let mut session = backend.session.lock().await;
    if let Some(child) = session.child.as_mut() {
        if let Some(exit) = child.try_wait().map_err(|e| e.to_string())? {
            session.child = None;
            session.status.connected = false;
            session.status.error = Some(format!(
                "sing-box остановлен: {exit}. {}",
                tokio::fs::read_to_string(backend.dir.join("sing-box.log"))
                    .await
                    .unwrap_or_default()
                    .chars()
                    .rev()
                    .take(1500)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>()
            ));
        }
    }
    if session.status.connected {
        session.status.uptime = session.started.map(|t| t.elapsed().as_secs()).unwrap_or(0);
        let client = vpn_http_client()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| e.to_string())?;
        if let Ok(res) = client
            .get("http://127.0.0.1:17891/connections")
            .bearer_auth(&session.api_secret)
            .send()
            .await
        {
            if let Ok(data) = res.json::<Value>().await {
                let up = data["uploadTotal"].as_u64().unwrap_or(0);
                let down = data["downloadTotal"].as_u64().unwrap_or(0);
                let elapsed = session.last_sample.elapsed().as_secs_f64().max(0.001);
                session.status.upload_speed =
                    (up.saturating_sub(session.status.upload_bytes) as f64 / elapsed) as u64;
                session.status.download_speed =
                    (down.saturating_sub(session.status.download_bytes) as f64 / elapsed) as u64;
                session.status.upload_bytes = up;
                session.status.download_bytes = down;
                session.last_sample = Instant::now();
            }
        }
    }
    Ok(session.status.clone())
}

#[derive(Serialize)]
struct Probe {
    ping: Option<u64>,
    ip: Option<String>,
    error: Option<String>,
}
#[tauri::command]
async fn measure_connection(state: State<'_, Backend>) -> Result<Probe> {
    let generation = {
        let session = state.session.lock().await;
        if !session.status.connected {
            return Ok(Probe {
                ping: None,
                ip: None,
                error: None,
            });
        }
        session.api_secret.clone()
    };
    let client = vpn_http_client()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:17892").map_err(|e| e.to_string())?)
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    let probe = match client.get("https://api.ipify.org?format=json").send().await {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<Value>().await {
                Ok(data) => Probe {
                    ping: Some(start.elapsed().as_millis() as u64),
                    ip: data["ip"].as_str().map(str::to_owned),
                    error: None,
                },
                Err(e) => Probe {
                    ping: None,
                    ip: None,
                    error: Some(e.to_string()),
                },
            },
            Err(e) => Probe {
                ping: None,
                ip: None,
                error: Some(e.to_string()),
            },
        },
        Err(e) => Probe {
            ping: None,
            ip: None,
            error: Some(e.to_string()),
        },
    };
    let mut session = state.session.lock().await;
    if session.status.connected && session.api_secret == generation {
        session.status.ping = probe.ping;
        session.status.ip = probe.ip.clone();
    }
    Ok(probe)
}

#[derive(Serialize)]
struct DomainUpdate {
    domains: Vec<String>,
    source: String,
    warning: Option<String>,
}
async fn sync_domains(backend: &Backend) -> Result<DomainUpdate> {
    let _guard = backend.session.lock().await;
    let result = parser::load(&backend.dir.join("hosts"), false)
        .await
        .map_err(|e| e.to_string())?;
    Ok(DomainUpdate {
        domains: result.domains.into_iter().collect(),
        source: result.source.into(),
        warning: result.warning,
    })
}
#[tauri::command]
async fn update_domains_from_zapret(state: State<'_, Backend>) -> Result<DomainUpdate> {
    sync_domains(&state).await
}
#[tauri::command]
async fn sync_zapret_domains(state: State<'_, Backend>) -> Result<DomainUpdate> {
    sync_domains(&state).await
}

#[tauri::command]
async fn list_installed_applications() -> Result<Vec<apps::InstalledApp>> {
    Ok(apps::list_installed_apps())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let dir = app.path().app_config_dir()?;
            std::fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
            let mut settings = match std::fs::read_to_string(dir.join("config.json")) {
                Ok(text) => serde_json::from_str(&text)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
                Err(e) => return Err(e.into()),
            };
            if mtproto::parse_secret(&settings.mtproto_secret).is_none() {
                settings.mtproto_secret = mtproto::generate_secret();
            }
            let settings = Settings {
                mode: migrate_mode(&settings.mode).into(),
                ..settings
            };
            if !dir.join("hosts").exists() {
                std::fs::write(dir.join("hosts"), include_str!("../../lists/hosts"))?;
            }
            app.manage(Backend {
                dir,
                account: Mutex::new(None),
                session: Mutex::new(Session {
                    child: None,
                    started: None,
                    status: Status::default(),
                    api_secret: String::new(),
                    last_sample: Instant::now(),
                    settings,
                    mtproto: None,
                }),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect_vpn,
            disconnect_vpn,
            get_status,
            update_domains_from_zapret,
            save_settings,
            load_settings,
            measure_connection,
            start_vpn,
            stop_vpn,
            sync_zapret_domains,
            login_account,
            auto_login_saved_account,
            current_account,
            logout_account,
            clear_account_vless,
            list_installed_applications,
            set_system_proxy,
            mtproto_link,
            get_account_traffic,
            get_sing_box_status,
            install_sing_box
        ])
        .build(tauri::generate_context!())
        .expect("Не удалось запустить KasperVPN")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                tauri::async_runtime::block_on(stop(&app.state::<Backend>())).ok();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings {
        Settings { key: "vless://6d14a7a9-5ba1-4534-aed8-6c4a619ce294@example.com:443?security=tls&type=ws&path=%2Fvpn&host=example.com".into(), domains: "example.org".into(), applications: vec!["steam".into()], ..Default::default() }
    }
    #[test]
    fn parses_vless_and_respects_exact_selection() {
        let mut s = settings();
        s.mode = "tun".into();
        let cfg = generate(&s, "test-secret").unwrap();
        assert_eq!(cfg["route"]["final"], "direct");
        assert!(
            cfg["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| rule["domain_suffix"].is_array())
        );
        let text = cfg.to_string();
        assert!(text.contains("steam.exe"));
        assert!(!text.contains("Discord.exe"));
        assert_eq!(cfg["inbounds"][0]["type"], "tun");
    }
    #[test]
    fn rejects_bad_links_and_domains() {
        for key in [
            "",
            "https://example.com",
            "vless://bad@example.com:443",
            "vless://6d14a7a9-5ba1-4534-aed8-6c4a619ce294@example.com:443?type=xhttp",
        ] {
            assert!(vless(key).is_err());
        }
        let mut s = settings();
        s.mode = "tun".into();
        s.domains = "https://example.com".into();
        assert!(generate(&s, "secret").is_err());
    }
    #[test]
    fn vless_reality_migrates_blocked_snis() {
        let vless_ms = "vless://4a46d4cd-eebd-405e-a1d0-1666202c8fdc@92.5.238.211:443?security=reality&pbk=EsETgEgCcqwqVq7lGNRlN79ElfE9ekWERL9JWy_i8hY&sid=23&sni=www.microsoft.com";
        let parsed_ms = vless(vless_ms).unwrap();
        assert_eq!(parsed_ms["tls"]["server_name"], "gateway.icloud.com");

        let vless_empty_sni = "vless://4a46d4cd-eebd-405e-a1d0-1666202c8fdc@92.5.238.211:443?security=reality&pbk=EsETgEgCcqwqVq7lGNRlN79ElfE9ekWERL9JWy_i8hY&sid=23";
        let parsed_empty = vless(vless_empty_sni).unwrap();
        assert_eq!(parsed_empty["tls"]["server_name"], "gateway.icloud.com");

        let vless_custom = "vless://4a46d4cd-eebd-405e-a1d0-1666202c8fdc@92.5.238.211:443?security=reality&pbk=EsETgEgCcqwqVq7lGNRlN79ElfE9ekWERL9JWy_i8hY&sid=23&sni=custom.cdn.com";
        let parsed_custom = vless(vless_custom).unwrap();
        assert_eq!(parsed_custom["tls"]["server_name"], "custom.cdn.com");

        // Test explicit SNI overrides
        let parsed_samsung = vless_configured(vless_ms, "www.samsung.com", "auto", "auto").unwrap();
        assert_eq!(parsed_samsung["tls"]["server_name"], "www.samsung.com");
        assert_eq!(parsed_samsung["server_port"], 443);
        assert_eq!(parsed_samsung["server"], "92.5.238.211");

        let parsed_port8443 = vless_configured(vless_ms, "gateway.icloud.com", "8443", "auto").unwrap();
        assert_eq!(parsed_port8443["tls"]["server_name"], "gateway.icloud.com");
        assert_eq!(parsed_port8443["server_port"], 8443);
        assert_eq!(parsed_port8443["server"], "92.5.238.211");

        let parsed_server = vless_configured(vless_ms, "auto", "auto", "84.235.165.153").unwrap();
        assert_eq!(parsed_server["server"], "84.235.165.153");
        assert_eq!(parsed_server["server_port"], 443);
        assert_eq!(parsed_server["tls"]["server_name"], "gateway.icloud.com");
    }

    #[test]
    fn tun_and_empty_selection() {
        let mut s = settings();
        s.mode = "tun".into();
        s.domains.clear();
        s.applications.clear();
        let cfg = generate(&s, "secret").unwrap();
        assert_eq!(cfg["inbounds"][0]["type"], "tun");
        assert_eq!(cfg["route"]["rules"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn system_proxy_and_telegram_proxy_are_separate_and_never_loop() {
        for mode in ["system", "telegram", "proxy"] {
            let mut s = settings();
            s.mode = mode.into();
            let cfg = generate(&s, "secret").unwrap();
            assert_eq!(cfg["inbounds"][0]["listen"], "127.0.0.1");
            assert_eq!(cfg["inbounds"][0]["listen_port"], 17890);
            assert_eq!(cfg["inbounds"][0]["set_system_proxy"], json!(false));
            assert_eq!(cfg["route"]["final"], "direct");
            assert_eq!(cfg["route"]["rules"][0]["action"], "sniff");
            assert_eq!(cfg["route"]["rules"][1]["outbound"], "direct");
            assert!(
                cfg["route"]["rules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r.get("inbound") == Some(&json!("metrics-in"))
                        && r["outbound"] == "proxy")
            );
            assert_eq!(cfg["outbounds"][1]["type"], "vless");
            assert_eq!(cfg["outbounds"][1]["server"], "example.com");
            assert_ne!(cfg["outbounds"][1]["server_port"], 17890);
        }
    }

    #[test]
    fn system_mode_without_whitelist_routes_all_local_in_to_proxy() {
        let mut s = settings();
        s.mode = "system".into();
        s.domains.clear();
        s.applications.clear();
        let cfg = generate(&s, "secret").unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(
            rules
                .iter()
                .any(|r| r.get("inbound") == Some(&json!("local-in")) && r["outbound"] == "proxy")
        );
    }

    #[test]
    fn legacy_local_proxy_mode_migrates_to_system_proxy() {
        assert_eq!(migrate_mode("proxy"), "system");
        assert_eq!(migrate_mode("telegram"), "telegram");
    }

    #[test]
    fn custom_installed_apps_are_supported() {
        let mut s = settings();
        s.mode = "tun".into();
        s.applications = vec!["custom_game".into(), "my_tool.exe".into()];
        let cfg = generate(&s, "secret").unwrap();
        let text = cfg.to_string();
        assert!(text.contains("custom_game"));
        assert!(text.contains("my_tool.exe"));
    }
    #[tokio::test]
    async fn real_process_lifecycle_and_local_api() {
        if std::env::var_os("KASPER_TEST_SING_BOX").is_none() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("kasper-lifecycle-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let backend = Backend {
            dir: dir.clone(),
            account: Mutex::new(None),
            session: Mutex::new(Session {
                child: None,
                started: None,
                status: Status::default(),
                api_secret: String::new(),
                last_sample: Instant::now(),
                settings: Settings::default(),
                mtproto: None,
            }),
        };
        let s = settings();
        launch(s.key.clone(), s, &backend).await.unwrap();
        assert!(status(&backend).await.unwrap().connected);
        let secret = backend.session.lock().await.api_secret.clone();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let response = client
            .get("http://127.0.0.1:17891/connections")
            .bearer_auth(secret)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let data = response.json::<Value>().await.unwrap();
        assert!(data["uploadTotal"].is_number());
        assert!(
            tokio::net::TcpStream::connect("127.0.0.1:17890")
                .await
                .is_ok()
        );
        assert!(launch(settings().key, settings(), &backend).await.is_err());
        stop(&backend).await.unwrap();
        assert!(!status(&backend).await.unwrap().connected);
        assert!(
            tokio::net::TcpStream::connect("127.0.0.1:17890")
                .await
                .is_err()
        );
        stop(&backend).await.unwrap();
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn generated_configs_pass_real_sing_box_check() {
        if std::env::var_os("KASPER_TEST_SING_BOX").is_none() {
            return;
        }
        for mode in ["system", "telegram", "tun"] {
            let mut s = settings();
            s.mode = mode.into();
            let path =
                std::env::temp_dir().join(format!("kasper-test-{}.json", uuid::Uuid::new_v4()));
            private_write(&path, &generate(&s, "test").unwrap().to_string())
                .await
                .unwrap();
            let output = command("sing-box")
                .args(["check", "-c"])
                .arg(&path)
                .output()
                .await
                .unwrap();
            let _ = tokio::fs::remove_file(path).await;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn windows_tun_interface_names_are_distinct_and_collisions_detected() {
        let a = windows_tun_interface_name("7e69bfba-5367-4ef1-ad72-215d20230bd4");
        let b = windows_tun_interface_name("4a46d4cd-eebd-405e-a1d0-1666202c8fdc");
        assert_eq!(a, "kasper-7e69bf");
        assert_eq!(b, "kasper-4a46d4");
        assert_ne!(a, b);
        assert!(a.len() <= 15);
        assert_eq!(windows_tun_interface_name("---"), "kasper-tun");

        assert!(is_tun_adapter_collision(
            "FATAL[0015] start service: start inbound/tun[tun-in]: configure tun interface: (create adapter: Cannot create a file when that file already exists. | open existing adapter: Element not found.)"
        ));
        assert!(!is_tun_adapter_collision("sing-box exited: unknown host"));
    }
}
