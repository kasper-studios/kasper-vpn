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

impl Default for Settings {
    fn default() -> Self {
        Self {
            key: String::new(),
            applications: default_applications(),
            domains: include_str!("../../lists/hosts").into(),
            mode: default_mode(),
            sing_box_path: "sing-box".into(),
            mtproto_port: default_mtproto_port(),
            mtproto_secret: String::new(),
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
        || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
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

fn vless(key: &str) -> Result<Value> {
    let url = Url::parse(key.trim()).map_err(|_| "Некорректная VLESS-ссылка")?;
    if url.scheme() != "vless" || url.password().is_some() {
        return Err("Нужна ссылка vless://UUID@server:port".into());
    }
    uuid::Uuid::parse_str(url.username()).map_err(|_| "Некорректный UUID VLESS")?;
    let host = url
        .host_str()
        .ok_or("В VLESS отсутствует сервер")?
        .trim_matches(['[', ']']);
    let port = url.port().ok_or("В VLESS отсутствует порт")?;
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let get = |name: &str| params.get(name).map(String::as_str).unwrap_or("");
    let mut out = json!({"type":"vless", "tag":"proxy", "server":host, "server_port":port, "uuid":url.username()});
    if !get("flow").is_empty() {
        out["flow"] = json!(get("flow"));
    }
    match get("security") {
        "" | "none" => {}
        "tls" | "reality" => {
            let mut tls = json!({"enabled":true, "server_name": if get("sni").is_empty() { host } else { get("sni") }});
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

fn generate(settings: &Settings, secret: &str) -> Result<Value> {
    let normalized_mode = migrate_mode(&settings.mode).to_owned();
    let settings = Settings {
        mode: normalized_mode,
        ..settings.clone()
    };
    if !matches!(settings.mode.as_str(), "system" | "telegram" | "tun") {
        return Err("Неизвестный режим сети".into());
    }
    if settings.mode == "tun" {
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
    if settings.mode == "tun" {
        for app in &settings.applications {
            let names: &[&str] = match app.as_str() {
                "discord" => &[
                    "Discord",
                    "discord",
                    "Discord.exe",
                    "DiscordCanary",
                    "DiscordCanary.exe",
                    "DiscordPTB",
                    "DiscordPTB.exe",
                ],
                "spotify" => &["spotify", "Spotify", "Spotify.exe"],
                "steam" => &["steam", "steam.exe", "steamwebhelper", "steamwebhelper.exe"],
                "browser" => &[
                    "firefox",
                    "firefox.exe",
                    "chrome",
                    "chrome.exe",
                    "chromium",
                    "chromium-browser",
                    "msedge.exe",
                    "brave",
                    "brave.exe",
                ],
                _ => return Err(format!("Неизвестное приложение: {app}")),
            };
            apps.extend(names.iter().map(|name| (*name).to_string()));
        }
    }
    let policy = config::SplitTunnel {
        domains: if settings.mode == "tun" {
            parser::parse_domains(&settings.domains)
        } else {
            BTreeSet::new()
        },
        applications: apps,
        proxy_server: String::new(),
        proxy_port: 0,
    };
    let mut cfg = serde_json::to_value(policy.generate()).map_err(|e| e.to_string())?;
    cfg["outbounds"][1] = vless(&settings.key)?;
    let original_route_rules = cfg["route"]["rules"].as_array().unwrap().clone();
    if settings.mode == "tun" {
        cfg["route"]["auto_detect_interface"] = json!(true);
        cfg["route"]["default_domain_resolver"] = json!({"server":"local-dns"});
        cfg["outbounds"][1]["domain_resolver"] = json!({"server":"local-dns"});
    } else {
        cfg["dns"]["rules"] = json!([]);
        cfg["dns"]["servers"] = json!([{"type":"local", "tag":"local-dns"}]);
        cfg["dns"].as_object_mut().unwrap().remove("final");
        cfg["dns"]
            .as_object_mut()
            .unwrap()
            .remove("reverse_mapping");
        cfg["route"]["rules"] = json!([
            {"inbound":"local-in", "action":"route", "outbound":"proxy"},
            {"protocol":"dns", "action":"hijack-dns"}
        ]);
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
                json!({"ip_cidr":["127.0.0.0/8", "::1/128"], "action":"route", "outbound":"direct"}),
                json!({"inbound":"local-in", "action":"route", "outbound":"proxy"}),
            ];
            rules.extend(
                original_route_rules
                    .iter()
                    .filter(|r| r.get("domain_suffix").is_none() && r.get("process_name").is_none())
                    .cloned(),
            );
            json!(rules)
        } else {
            let mut rules = vec![
                json!({"inbound":"local-in", "action":"route", "outbound":"proxy"}),
                json!({"process_name":["telegram-desktop", "Telegram", "Telegram.exe"], "action":"route", "outbound":"proxy"}),
                json!({"domain_suffix":["t.me", "telegram.me", "telegram.org", "telegram.dog", "telegra.ph", "telegram.space"], "action":"route", "outbound":"proxy"}),
            ];
            rules.extend(
                original_route_rules
                    .iter()
                    .filter(|r| r.get("domain_suffix").is_none() && r.get("process_name").is_none())
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
    *state.account.lock().await = Some(client);
    Ok(result)
}

#[tauri::command]
async fn current_account(state: State<'_, Backend>) -> Result<account::Account> {
    let account = state.account.lock().await;
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
        client.logout().await?;
    }
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

async fn launch(key: String, mut settings: Settings, backend: &Backend) -> Result<()> {
    let mut session = backend.session.lock().await;
    if let Some(child) = session.child.as_mut() {
        if child.try_wait().map_err(|e| e.to_string())?.is_none() {
            return Err("VPN уже запущен".into());
        }
    }
    session.child = None;
    if settings.mode == "proxy" {
        settings.mode = "system".into();
    }
    settings.key = key;
    // Секрет MTProto генерируется один раз и сохраняется вместе с настройками,
    // чтобы ссылка для Telegram не менялась между запусками.
    if settings.mode == "telegram" && mtproto::parse_secret(&settings.mtproto_secret).is_none() {
        settings.mtproto_secret = mtproto::generate_secret();
    }
    let secret = uuid::Uuid::new_v4().to_string();
    let cfg = generate(&settings, &secret)?;
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
        .map_err(|e| {
            format!("Не найден sing-box. Установите sing-box ≥ 1.12 или укажите полный путь: {e}")
        })?;
    if !checked.status.success() {
        return Err(format!(
            "sing-box check: {}",
            String::from_utf8_lossy(&checked.stderr)
        ));
    }
    private_write(
        &backend.dir.join("config.json"),
        &serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?,
    )
    .await?;
    private_write(&backend.dir.join("sing-box.log"), "").await?;
    let log = std::fs::OpenOptions::new()
        .append(true)
        .open(backend.dir.join("sing-box.log"))
        .map_err(|e| e.to_string())?;
    let mut child = command(&settings.sing_box_path)
        .args(["run", "-c"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    tokio::time::sleep(Duration::from_millis(700)).await;
    if let Some(exit) = child.try_wait().map_err(|e| e.to_string())? {
        let log = tokio::fs::read_to_string(backend.dir.join("sing-box.log"))
            .await
            .unwrap_or_default();
        return Err(format!(
            "sing-box завершился ({exit}). {log}\nДля TUN нужны права администратора / CAP_NET_ADMIN; без них используйте локальный прокси."
        ));
    }
    if settings.mode == "system" {
        if let Err(error) = system_proxy::enable() {
            let _ = child.kill().await;
            return Err(error);
        }
    }
    if settings.mode == "telegram" {
        let secret = mtproto::parse_secret(&settings.mtproto_secret)
            .ok_or("Некорректный секрет MTProto")?;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", settings.mtproto_port))
            .await
            .map_err(|e| {
                let _ = child.start_kill();
                format!(
                    "Не удалось занять порт {} для MTProto-прокси: {e}",
                    settings.mtproto_port
                )
            })?;
        // Трафик MTProto уходит в mixed-вход sing-box и дальше через VLESS.
        let task = tokio::spawn(async move {
            let _ = mtproto::run(listener, secret, Some((String::from("127.0.0.1"), 17890))).await;
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
    let session = state.session.lock().await;
    let running = session.mtproto.is_some();
    let secret = session.settings.mtproto_secret.trim().to_owned();
    let link = mtproto::parse_secret(&secret).map(|_| {
        mtproto::proxy_link("127.0.0.1", session.settings.mtproto_port, &secret)
    });
    Ok(MtprotoLink { link, running })
}

async fn stop(backend: &Backend) -> Result<()> {
    let mut session = backend.session.lock().await;
    if let Some(mtproto) = session.mtproto.take() {
        mtproto.abort();
    }
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
    }
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

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let dir = app.path().app_config_dir()?;
            std::fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
            let settings = match std::fs::read_to_string(dir.join("config.json")) {
                Ok(text) => serde_json::from_str(&text)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
                Err(e) => return Err(e.into()),
            };
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
            current_account,
            logout_account,
            clear_account_vless,
            set_system_proxy,
            mtproto_link
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
    fn tun_and_empty_selection() {
        let mut s = settings();
        s.mode = "tun".into();
        s.domains.clear();
        s.applications.clear();
        let cfg = generate(&s, "secret").unwrap();
        assert_eq!(cfg["inbounds"][0]["type"], "tun");
        assert_eq!(cfg["route"]["rules"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn system_proxy_and_telegram_proxy_are_separate_and_never_loop() {
        for mode in ["system", "telegram", "proxy"] {
            let mut s = settings();
            s.mode = mode.into();
            let cfg = generate(&s, "secret").unwrap();
            let expected_system_proxy = mode == "system" || mode == "proxy";
            assert_eq!(cfg["inbounds"][0]["listen"], "127.0.0.1");
            assert_eq!(cfg["inbounds"][0]["listen_port"], 17890);
            assert_eq!(cfg["inbounds"][0]["set_system_proxy"], json!(false));
            assert_eq!(cfg["route"]["final"], "direct");
            if expected_system_proxy {
                assert_eq!(cfg["route"]["rules"][0]["outbound"], "direct");
                assert_eq!(cfg["route"]["rules"][1]["inbound"], "local-in");
                assert_eq!(cfg["route"]["rules"][1]["outbound"], "proxy");
            } else {
                assert_eq!(cfg["route"]["rules"][0]["inbound"], "local-in");
                assert_eq!(cfg["route"]["rules"][0]["outbound"], "proxy");
            }
            assert_eq!(cfg["outbounds"][1]["type"], "vless");
            assert_eq!(cfg["outbounds"][1]["server"], "example.com");
            assert_ne!(cfg["outbounds"][1]["server_port"], 17890);
        }
    }

    #[test]
    fn legacy_local_proxy_mode_migrates_to_system_proxy() {
        assert_eq!(migrate_mode("proxy"), "system");
        assert_eq!(migrate_mode("telegram"), "telegram");
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
}
