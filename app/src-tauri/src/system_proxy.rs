// Linux-бэкенды системного прокси (gsettings, KDE, dconf, systemd, environment.d)
// на Windows/macOS не участвуют в исполнении — их неиспользованность там ожидаема.
#![cfg_attr(any(windows, target_os = "macos"), allow(dead_code, unused_imports))]

use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::Mutex,
};

#[cfg(windows)]
#[path = "system_proxy_windows.rs"]
mod windows_proxy;

#[cfg(target_os = "macos")]
#[path = "system_proxy_macos.rs"]
mod macos_proxy;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Какие бэкенды были применены: только они восстанавливаются.
    #[serde(default)]
    pub backends: Vec<String>,
    // --- GNOME / gsettings ---
    pub gnome_mode: Option<String>,
    pub gnome_use_same_proxy: Option<String>,
    pub gnome_ftp_host: Option<String>,
    pub gnome_ftp_port: Option<u16>,
    pub gnome_ignore_hosts: Option<String>,
    pub gnome_http_host: Option<String>,
    pub gnome_http_port: Option<u16>,
    pub gnome_https_host: Option<String>,
    pub gnome_https_port: Option<u16>,
    pub gnome_socks_host: Option<String>,
    pub gnome_socks_port: Option<u16>,
    // --- KDE / kioslaverc ---
    pub kde_proxy_type: Option<String>,
    pub kde_http: Option<String>,
    pub kde_https: Option<String>,
    pub kde_socks: Option<String>,
    pub kde_ftp: Option<String>,
    pub kde_no_proxy_for: Option<String>,
    /// Какой инструмент применён: kwriteconfig6 или kwriteconfig5.
    #[serde(default)]
    pub kde_tool: Option<String>,
    // --- Портал / dconf, когда gsettings недоступен ---
    #[serde(default)]
    pub dconf_dump: Option<String>,
    // --- Консольные утилиты ---
    #[serde(default)]
    pub env_file: Option<String>,
    #[serde(default)]
    pub env_previous: Option<String>,
    /// Proxy-переменные, ранее экспортированные systemd-менеджером пользователя:
    /// новые пользовательские сервисы сразу видят прокси без перелогина.
    #[serde(default)]
    pub systemd_user_env: Option<std::collections::BTreeMap<String, Option<String>>>,
}

const PROXY_HTTP: &str = "http://127.0.0.1:17890";
const PROXY_SOCKS: &str = "socks5://127.0.0.1:17890";
const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Session/systemd environment file so CLI tools (curl, git, wget, npm) pick the
/// proxy up without any per-app configuration. GUI apps use the desktop backends.
fn environment_file_content() -> String {
    let mut text = String::new();
    for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
        text.push_str(&format!("{key}={PROXY_HTTP}\n"));
    }
    for key in ["all_proxy", "ALL_PROXY"] {
        text.push_str(&format!("{key}={PROXY_SOCKS}\n"));
    }
    for key in ["no_proxy", "NO_PROXY"] {
        text.push_str(&format!("{key}={NO_PROXY}\n"));
    }
    text
}

fn environment_file_path() -> Option<std::path::PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|home| std::path::PathBuf::from(home).join(".config"))
        })?;
    Some(base.join("environment.d").join("90-kaspervpn.conf"))
}

fn apply_environment(path: &Path) -> Result<Option<String>, String> {
    let previous = std::fs::read_to_string(path).ok();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, environment_file_content())
        .map_err(|e| format!("Не удалось записать {}: {e}", path.display()))?;
    Ok(previous)
}

fn restore_environment(path: &Path, previous: &Option<String>) -> Result<(), String> {
    match previous {
        Some(text) => std::fs::write(path, text)
            .map_err(|e| format!("Не удалось восстановить {}: {e}", path.display())),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("Не удалось удалить {}: {e}", path.display())),
        },
    }
}

fn proxy_environment_keys() -> &'static [&'static str] {
    &[
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ]
}

fn systemd_user_environment_snapshot()
-> Result<std::collections::BTreeMap<String, Option<String>>, String> {
    let output = command("systemctl", &["--user", "show-environment"])?;
    let current: std::collections::BTreeMap<String, String> = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    Ok(proxy_environment_keys()
        .iter()
        .map(|key| ((*key).to_owned(), current.get(*key).cloned()))
        .collect())
}

fn run_systemctl_user(args: &[String]) -> Result<(), String> {
    let output = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(|e| format!("Не удалось вызвать systemctl --user: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if args.first().is_some_and(|arg| arg == "set-environment") {
            let mut fallback = vec!["import-environment".to_owned()];
            fallback.extend(
                args.iter()
                    .skip(1)
                    .filter_map(|value| value.split_once('=').map(|(key, _)| key.to_owned())),
            );
            let imported = Command::new("systemctl")
                .arg("--user")
                .args(&fallback)
                .status()
                .map_err(|e| format!("{message}; import-environment failed: {e}"))?;
            if imported.success() {
                return Ok(());
            }
        }
        Err(format!(
            "systemctl --user {}: {message}",
            args.first().map(String::as_str).unwrap_or("")
        ))
    }
}

fn apply_systemd_user_environment() -> Result<(), String> {
    let values = [
        ("http_proxy", PROXY_HTTP),
        ("https_proxy", PROXY_HTTP),
        ("HTTP_PROXY", PROXY_HTTP),
        ("HTTPS_PROXY", PROXY_HTTP),
        ("all_proxy", PROXY_SOCKS),
        ("ALL_PROXY", PROXY_SOCKS),
        ("no_proxy", NO_PROXY),
        ("NO_PROXY", NO_PROXY),
    ];
    let mut args = vec!["set-environment".to_owned()];
    args.extend(values.iter().map(|(key, value)| format!("{key}={value}")));
    run_systemctl_user(&args)
}

fn restore_systemd_user_environment(
    previous: &std::collections::BTreeMap<String, Option<String>>,
) -> Result<(), String> {
    let keys = proxy_environment_keys();
    let mut unset = vec!["unset-environment".to_owned()];
    unset.extend(keys.iter().map(|key| (*key).to_owned()));
    run_systemctl_user(&unset)?;

    let mut set = vec!["set-environment".to_owned()];
    set.extend(
        previous
            .iter()
            .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}={value}"))),
    );
    if set.len() > 1 {
        run_systemctl_user(&set)?;
    }
    Ok(())
}

static PREVIOUS: Mutex<Option<Snapshot>> = Mutex::new(None);
#[cfg(windows)]
static WINDOWS_PREVIOUS: Mutex<Option<windows_proxy::Snapshot>> = Mutex::new(None);
#[cfg(target_os = "macos")]
static MACOS_PREVIOUS: Mutex<Option<macos_proxy::Snapshot>> = Mutex::new(None);
const HOST: &str = "127.0.0.1";
const PORT: &str = "17890";
const LOOPBACKS: &str = "['127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1']";

fn command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Доступен ли инструмент: успешный запуск важнее переменных окружения,
/// потому что приложение может работать под любым WM без XDG_CURRENT_DESKTOP.
fn tool_available(program: &str, probe: &[&str]) -> bool {
    Command::new(program)
        .args(probe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn gsettings_available() -> bool {
    tool_available("gsettings", &["list-schemas"])
        && command("gsettings", &["list-schemas"])
            .map(|schemas| schemas.lines().any(|line| line == "org.gnome.system.proxy"))
            .unwrap_or(false)
}

fn dconf_available() -> bool {
    tool_available("dconf", &["list", "/system/proxy/"])
}

fn kde_tools() -> Option<&'static str> {
    // Возвращаем суффикс версии: сначала новый kwriteconfig6, затем 5.
    if tool_available("kwriteconfig6", &["--help"]) {
        Some("6")
    } else if tool_available("kwriteconfig5", &["--help"]) {
        Some("5")
    } else {
        None
    }
}

fn unquote(s: String) -> String {
    s.trim().trim_matches('\'').trim_matches('"').to_string()
}
fn gget(schema: &str, key: &str) -> Result<String, String> {
    command("gsettings", &["get", schema, key]).map(unquote)
}
fn gset(schema: &str, key: &str, value: &str) -> Result<(), String> {
    command("gsettings", &["set", schema, key, value]).map(|_| ())
}
fn gset_best_effort(schema: &str, key: &str, value: &str) -> Result<(), String> {
    let status = Command::new("gsettings")
        .args(["set", schema, key, value])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Could not restore GNOME {schema} {key}"))
    }
}

fn kde_read(tool: &str, key: &str) -> Result<String, String> {
    command(
        &format!("kreadconfig{tool}"),
        &["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key],
    )
}

fn kde_write(tool: &str, key: &str, value: &str) -> Result<(), String> {
    command(
        &format!("kwriteconfig{tool}"),
        &[
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            key,
            value,
        ],
    )
    .map(|_| ())
}

fn kde_reparse() {
    // Лучшее усилие: перечитываем конфигурацию KIO без перезапуска приложений.
    for qdbus in ["qdbus6", "qdbus"] {
        let _ = command(qdbus, &["org.kde.KIO", "/KIO", "reparseConfiguration"]);
    }
}

fn gnome_snapshot() -> Result<(Option<String>, Snapshot), String> {
    let mut snapshot = Snapshot {
        gnome_mode: Some(gget("org.gnome.system.proxy", "mode")?),
        gnome_use_same_proxy: gget("org.gnome.system.proxy", "use-same-proxy").ok(),
        gnome_ftp_host: gget("org.gnome.system.proxy.ftp", "host").ok(),
        gnome_ftp_port: gget("org.gnome.system.proxy.ftp", "port")
            .ok()
            .and_then(|v| v.parse().ok()),
        gnome_ignore_hosts: command(
            "gsettings",
            &["get", "org.gnome.system.proxy", "ignore-hosts"],
        )
        .ok(),
        gnome_http_host: gget("org.gnome.system.proxy.http", "host").ok(),
        gnome_http_port: gget("org.gnome.system.proxy.http", "port")
            .ok()
            .and_then(|v| v.parse().ok()),
        gnome_https_host: gget("org.gnome.system.proxy.https", "host").ok(),
        gnome_https_port: gget("org.gnome.system.proxy.https", "port")
            .ok()
            .and_then(|v| v.parse().ok()),
        gnome_socks_host: gget("org.gnome.system.proxy.socks", "host").ok(),
        gnome_socks_port: gget("org.gnome.system.proxy.socks", "port")
            .ok()
            .and_then(|v| v.parse().ok()),
        ..Snapshot::default()
    };
    let mode = snapshot.gnome_mode.clone();
    snapshot.gnome_mode = mode;
    Ok((snapshot.gnome_mode.clone(), snapshot))
}

fn gnome_apply() -> Result<(), String> {
    gset("org.gnome.system.proxy.ftp", "host", "'127.0.0.1'")?;
    gset("org.gnome.system.proxy.ftp", "port", PORT)?;
    gset("org.gnome.system.proxy.http", "host", "'127.0.0.1'")?;
    gset("org.gnome.system.proxy.http", "port", PORT)?;
    gset("org.gnome.system.proxy.https", "host", "'127.0.0.1'")?;
    gset("org.gnome.system.proxy.https", "port", PORT)?;
    gset("org.gnome.system.proxy.socks", "host", "'127.0.0.1'")?;
    gset("org.gnome.system.proxy.socks", "port", PORT)?;
    gset("org.gnome.system.proxy", "ignore-hosts", LOOPBACKS)?;
    gset("org.gnome.system.proxy", "use-same-proxy", "true")?;
    gset("org.gnome.system.proxy", "mode", "'manual'")?;
    Ok(())
}

fn gnome_restore(snapshot: &Snapshot) -> Result<(), String> {
    // Сначала конечные точки прокси, режим — последним. Ошибки собираем:
    // частичный успех лучше полной остановки.
    let mut first_error: Option<String> = None;
    for (schema, key, value) in [
        (
            "org.gnome.system.proxy",
            "use-same-proxy",
            snapshot.gnome_use_same_proxy.clone(),
        ),
        (
            "org.gnome.system.proxy",
            "ignore-hosts",
            snapshot.gnome_ignore_hosts.clone(),
        ),
        (
            "org.gnome.system.proxy.ftp",
            "host",
            snapshot.gnome_ftp_host.clone(),
        ),
        (
            "org.gnome.system.proxy.ftp",
            "port",
            snapshot.gnome_ftp_port.map(|n| n.to_string()),
        ),
        (
            "org.gnome.system.proxy.http",
            "host",
            snapshot.gnome_http_host.clone(),
        ),
        (
            "org.gnome.system.proxy.http",
            "port",
            snapshot.gnome_http_port.map(|n| n.to_string()),
        ),
        (
            "org.gnome.system.proxy.https",
            "host",
            snapshot.gnome_https_host.clone(),
        ),
        (
            "org.gnome.system.proxy.https",
            "port",
            snapshot.gnome_https_port.map(|n| n.to_string()),
        ),
        (
            "org.gnome.system.proxy.socks",
            "host",
            snapshot.gnome_socks_host.clone(),
        ),
        (
            "org.gnome.system.proxy.socks",
            "port",
            snapshot.gnome_socks_port.map(|n| n.to_string()),
        ),
        ("org.gnome.system.proxy", "mode", snapshot.gnome_mode.clone()),
    ] {
        if let Some(value) = value {
            if let Err(error) = gset_best_effort(schema, key, &value) {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn kde_snapshot(tool: &str) -> Result<Snapshot, String> {
    Ok(Snapshot {
        kde_proxy_type: kde_read(tool, "ProxyType").ok(),
        kde_http: kde_read(tool, "httpProxy").ok(),
        kde_https: kde_read(tool, "httpsProxy").ok(),
        kde_socks: kde_read(tool, "socksProxy").ok(),
        kde_ftp: kde_read(tool, "ftpProxy").ok(),
        kde_no_proxy_for: kde_read(tool, "NoProxyFor").ok(),
        kde_tool: Some(tool.to_owned()),
        ..Snapshot::default()
    })
}

fn kde_apply(tool: &str) -> Result<(), String> {
    kde_write(tool, "httpProxy", PROXY_HTTP)?;
    kde_write(tool, "httpsProxy", PROXY_HTTP)?;
    kde_write(tool, "socksProxy", "socks://127.0.0.1:17890")?;
    kde_write(tool, "ftpProxy", PROXY_HTTP)?;
    kde_write(tool, "NoProxyFor", "127.0.0.1,localhost,::1")?;
    kde_write(tool, "ProxyType", "1")?;
    kde_reparse();
    Ok(())
}

fn kde_restore(snapshot: &Snapshot) -> Result<(), String> {
    let tool = snapshot
        .kde_tool
        .as_deref()
        .ok_or("Не указан инструмент для восстановления KDE proxy")?;
    for (key, value) in [
        ("httpProxy", snapshot.kde_http.clone()),
        ("httpsProxy", snapshot.kde_https.clone()),
        ("socksProxy", snapshot.kde_socks.clone()),
        ("ftpProxy", snapshot.kde_ftp.clone()),
        ("NoProxyFor", snapshot.kde_no_proxy_for.clone()),
        ("ProxyType", snapshot.kde_proxy_type.clone()),
    ] {
        if let Some(value) = value {
            kde_write(tool, key, &value)?;
        }
    }
    kde_reparse();
    Ok(())
}

/// dconf напрямую (без gsettings): услуги портала и Firefox читают /system/proxy.
fn dconf_snapshot_dump() -> Result<String, String> {
    command("dconf", &["dump", "/system/proxy/"])
}

fn dconf_apply() -> Result<(), String> {
    let values = [
        "/system/proxy/mode", "'manual'",
        "/system/proxy/http/host", "'127.0.0.1'",
        "/system/proxy/http/port", "17890",
        "/system/proxy/https/host", "'127.0.0.1'",
        "/system/proxy/https/port", "17890",
        "/system/proxy/socks/host", "'127.0.0.1'",
        "/system/proxy/socks/port", "17890",
        "/system/proxy/ftp/host", "'127.0.0.1'",
        "/system/proxy/ftp/port", "17890",
        "/system/proxy/ignore-hosts", LOOPBACKS,
    ];
    for pair in values.chunks(2) {
        command("dconf", &["write", pair[0], pair[1]])?;
    }
    Ok(())
}

fn dconf_restore(dump: &Option<String>) -> Result<(), String> {
    // Сбрасываем поддерево и загружаем сохранённый дамп: так убираются и
    // изменённые, и добавленные нами ключи.
    command("dconf", &["reset", "-f", "/system/proxy/"])?;
    let Some(text) = dump else {
        return Ok(());
    };
    if text.trim().is_empty() {
        return Ok(());
    }
    let mut child = Command::new("dconf")
        .args(["load", "/system/proxy/"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("Не удалось вызвать dconf load: {error}"))?;
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .ok_or("Не удалось открыть stdin dconf")?
        .write_all(text.as_bytes())
        .map_err(|error| format!("Не удалось передать snapshot dconf: {error}"))?;
    let status = child.wait().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("Не удалось восстановить настройки dconf system proxy".into())
    }
}

fn proxy_values_point_at_local_inbound(snapshot: &Snapshot) -> bool {
    let gnome_hit = snapshot.gnome_mode.as_deref() == Some("manual")
        && [
            snapshot.gnome_http_host.as_deref(),
            snapshot.gnome_https_host.as_deref(),
            snapshot.gnome_socks_host.as_deref(),
            snapshot.gnome_ftp_host.as_deref(),
        ].contains(&Some(HOST));
    let kde_hit = snapshot.kde_proxy_type.as_deref() == Some("1")
        && [
            snapshot.kde_http.as_deref(),
            snapshot.kde_https.as_deref(),
            snapshot.kde_socks.as_deref(),
            snapshot.kde_ftp.as_deref(),
        ]
        .iter()
        .any(|v| v.is_some_and(|value| value.contains("127.0.0.1:17890")));
    gnome_hit || kde_hit
}

pub fn restore() -> Result<(), String> {
    #[cfg(windows)]
    {
        let snapshot = WINDOWS_PREVIOUS
            .lock()
            .map_err(|_| "Windows proxy snapshot mutex poisoned")?
            .clone();
        if let Some(snapshot) = snapshot {
            windows_proxy::restore(&snapshot)?;
            *WINDOWS_PREVIOUS
                .lock()
                .map_err(|_| "Windows proxy snapshot mutex poisoned")? = None;
        }
        // Windows таргет всегда выходит здесь: restore идемпотентен, без снимка — нечего
        // восстанавливать. Явный return нужен, иначе блок становится хвостовым выражением.
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let snapshot = MACOS_PREVIOUS
            .lock()
            .map_err(|_| "macOS proxy snapshot mutex poisoned")?
            .clone();
        if let Some(snapshot) = snapshot {
            macos_proxy::restore(&snapshot)?;
            *MACOS_PREVIOUS
                .lock()
                .map_err(|_| "macOS proxy snapshot mutex poisoned")? = None;
        }
        return Ok(());
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let snapshot = PREVIOUS
            .lock()
            .map_err(|_| "proxy snapshot mutex poisoned")?
            .clone();
        let Some(s) = snapshot else {
            return Ok(());
        };
        let mut first_error: Option<String> = None;
        for backend in &s.backends {
            let result = match backend.as_str() {
                "gsettings" => gnome_restore(&s),
                "kde" => kde_restore(&s),
                "dconf" => dconf_restore(&s.dconf_dump),
                "systemd" => match s.systemd_user_env.as_ref() {
                    Some(previous) => restore_systemd_user_environment(previous),
                    None => Ok(()),
                },
                "environment" => match s.env_file.as_deref() {
                    Some(path) => restore_environment(Path::new(path), &s.env_previous),
                    None => Ok(()),
                },
                other => Err(format!("Неизвестный proxy-бэкенд '{other}'")),
            };
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        *PREVIOUS.lock().map_err(|_| "proxy snapshot mutex poisoned")? = None;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

pub fn enable() -> Result<(), String> {
    #[cfg(windows)]
    {
        if WINDOWS_PREVIOUS
            .lock()
            .map_err(|_| "Windows proxy snapshot mutex poisoned")?
            .is_some()
        {
            return Ok(());
        }
        let snapshot = windows_proxy::enable()?;
        *WINDOWS_PREVIOUS
            .lock()
            .map_err(|_| "Windows proxy snapshot mutex poisoned")? = Some(snapshot);
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        if MACOS_PREVIOUS
            .lock()
            .map_err(|_| "macOS proxy snapshot mutex poisoned")?
            .is_some()
        {
            return Ok(());
        }
        let snapshot = macos_proxy::enable()?;
        *MACOS_PREVIOUS
            .lock()
            .map_err(|_| "macOS proxy snapshot mutex poisoned")? = Some(snapshot);
        return Ok(());
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        if PREVIOUS
            .lock()
            .map_err(|_| "proxy snapshot mutex poisoned")?
            .is_some()
        {
            return Ok(());
        }
        // Работаем на любом Linux — от GNOME и KDE до niri, sway, Hyprland и
        // чистого TTY: применяем все доступные бэкенды независимо от DE/WM.
        let mut snapshot = Snapshot::default();
        let mut backends: Vec<String> = Vec::new();

        let gsettings_ok = gsettings_available();
        if gsettings_ok {
            match gnome_snapshot() {
                Ok((_, snap)) => snapshot = merge_snapshots(snapshot, snap),
                Err(error) => return Err(error),
            }
        }
        let kde_tool = kde_tools();
        if let Some(tool) = kde_tool {
            snapshot = merge_snapshots(snapshot, kde_snapshot(tool)?);
        }
        let dconf_ok = dconf_available() && !gsettings_ok;
        if dconf_ok {
            {
                let dump = dconf_snapshot_dump()?;
                snapshot.dconf_dump = Some(dump)
            }
        }
        if tool_available("systemctl", &["--user", "show-environment"]) {
            {
                let previous = systemd_user_environment_snapshot()?;
                snapshot.systemd_user_env = Some(previous)
            }
        }

        if proxy_values_point_at_local_inbound(&snapshot) {
            return Err("Обнаружен системный прокси, уже направленный на локальный вход KasperVPN. Во избежание прокси-петли не подключаюсь; отключи внешний proxy chain.".into());
        }

        let mut failures: Vec<String> = Vec::new();
        if gsettings_ok && gnome_apply().is_ok() {
            backends.push("gsettings".into());
        } else if gsettings_ok {
            failures.push("gsettings".into());
        }
        if let Some(tool) = kde_tool {
            if kde_apply(tool).is_ok() {
                backends.push("kde".into());
            } else {
                failures.push("kwriteconfig".into());
            }
        }
        if dconf_ok && dconf_apply().is_ok() {
            backends.push("dconf".into());
        } else if dconf_ok {
            failures.push("dconf".into());
        }
        if apply_systemd_user_environment().is_ok() {
            backends.push("systemd".into());
        }
        if let Some(path) = environment_file_path() {
            match apply_environment(&path) {
                Ok(previous) => {
                    snapshot.env_file = Some(path.to_string_lossy().into_owned());
                    snapshot.env_previous = previous;
                    backends.push("environment".into());
                }
                Err(error) => failures.push(format!("environment.d: {error}")),
            }
        }

        if backends.is_empty() {
            return Err(format!(
                "Не найдено ни одного способа настроить системный прокси (gsettings, dconf, kwriteconfig, systemctl, environment.d). {failures:?}"
            ));
        }
        snapshot.backends = backends;
        *PREVIOUS
            .lock()
            .map_err(|_| "proxy snapshot mutex poisoned")? = Some(snapshot);
        if !failures.is_empty() {
            return Err(format!(
                "Системный прокси включён частично; не удалось применить: {}. Отключение восстановит применённое.",
                failures.join(", ")
            ));
        }
        Ok(())
    }
}

/// Слияние снапшотов разных бэкендов: непустые значения побеждают.
fn merge_snapshots(mut base: Snapshot, other: Snapshot) -> Snapshot {
    if base.gnome_mode.is_none() {
        base.gnome_mode = other.gnome_mode;
    }
    if base.gnome_use_same_proxy.is_none() {
        base.gnome_use_same_proxy = other.gnome_use_same_proxy;
    }
    if base.gnome_ftp_host.is_none() {
        base.gnome_ftp_host = other.gnome_ftp_host;
    }
    if base.gnome_ftp_port.is_none() {
        base.gnome_ftp_port = other.gnome_ftp_port;
    }
    if base.gnome_ignore_hosts.is_none() {
        base.gnome_ignore_hosts = other.gnome_ignore_hosts;
    }
    if base.gnome_http_host.is_none() {
        base.gnome_http_host = other.gnome_http_host;
    }
    if base.gnome_http_port.is_none() {
        base.gnome_http_port = other.gnome_http_port;
    }
    if base.gnome_https_host.is_none() {
        base.gnome_https_host = other.gnome_https_host;
    }
    if base.gnome_https_port.is_none() {
        base.gnome_https_port = other.gnome_https_port;
    }
    if base.gnome_socks_host.is_none() {
        base.gnome_socks_host = other.gnome_socks_host;
    }
    if base.gnome_socks_port.is_none() {
        base.gnome_socks_port = other.gnome_socks_port;
    }
    if base.kde_proxy_type.is_none() {
        base.kde_proxy_type = other.kde_proxy_type;
    }
    if base.kde_http.is_none() {
        base.kde_http = other.kde_http;
    }
    if base.kde_https.is_none() {
        base.kde_https = other.kde_https;
    }
    if base.kde_socks.is_none() {
        base.kde_socks = other.kde_socks;
    }
    if base.kde_ftp.is_none() {
        base.kde_ftp = other.kde_ftp;
    }
    if base.kde_no_proxy_for.is_none() {
        base.kde_no_proxy_for = other.kde_no_proxy_for;
    }
    if base.kde_tool.is_none() {
        base.kde_tool = other.kde_tool;
    }
    if base.dconf_dump.is_none() {
        base.dconf_dump = other.dconf_dump;
    }
    base
}

pub fn active() -> bool {
    #[cfg(windows)]
    {
        WINDOWS_PREVIOUS
            .lock()
            .map(|s| s.is_some())
            .unwrap_or(false)
    }
    #[cfg(target_os = "macos")]
    {
        MACOS_PREVIOUS
            .lock()
            .map(|s| s.is_some())
            .unwrap_or(false)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        PREVIOUS.lock().map(|s| s.is_some()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_default_is_empty() {
        assert!(Snapshot::default().backends.is_empty());
    }

    #[test]
    fn merge_keeps_first_nonempty_value() {
        let base = Snapshot {
            gnome_mode: Some("none".into()),
            ..Snapshot::default()
        };
        let other = Snapshot {
            gnome_mode: Some("manual".into()),
            kde_http: Some("http://old:1".into()),
            ..Snapshot::default()
        };
        let merged = merge_snapshots(base, other);
        assert_eq!(merged.gnome_mode.as_deref(), Some("none"));
        assert_eq!(merged.kde_http.as_deref(), Some("http://old:1"));
    }

    #[test]
    fn local_inbound_detection_covers_both_backends() {
        let snapshot = Snapshot {
            gnome_mode: Some("manual".into()),
            gnome_http_host: Some(HOST.into()),
            ..Snapshot::default()
        };
        assert!(proxy_values_point_at_local_inbound(&snapshot));
        let snapshot = Snapshot {
            kde_proxy_type: Some("1".into()),
            kde_socks: Some("socks://127.0.0.1:17890".into()),
            ..Snapshot::default()
        };
        assert!(proxy_values_point_at_local_inbound(&snapshot));
        let snapshot = Snapshot {
            gnome_mode: Some("none".into()),
            gnome_http_host: Some("proxy.corp".into()),
            kde_proxy_type: Some("1".into()),
            kde_http: Some("http://10.0.0.1:3128".into()),
            ..Snapshot::default()
        };
        assert!(!proxy_values_point_at_local_inbound(&snapshot));
    }

    #[test]
    fn environment_file_points_tools_at_local_inbound_and_excludes_loopback() {
        let text = environment_file_content();
        for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
            assert!(
                text.contains(&format!("{key}={PROXY_HTTP}\n")),
                "missing {key}"
            );
        }
        for key in ["all_proxy", "ALL_PROXY"] {
            assert!(
                text.contains(&format!("{key}={PROXY_SOCKS}\n")),
                "missing {key}"
            );
        }
        for key in ["no_proxy", "NO_PROXY"] {
            assert!(
                text.contains(&format!("{key}={NO_PROXY}\n")),
                "missing {key}"
            );
        }
    }

    #[test]
    fn environment_file_roundtrip_restores_absent_file() {
        let dir = std::env::temp_dir().join(format!("kasper-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("90-kaspervpn.conf");
        let _ = std::fs::remove_file(&path);
        let previous = apply_environment(&path).unwrap();
        assert!(previous.is_none());
        assert!(path.exists());
        restore_environment(&path, &previous).unwrap();
        assert!(!path.exists());
        std::fs::write(&path, "http_proxy=http://old:1\n").unwrap();
        let previous = apply_environment(&path).unwrap();
        assert_eq!(previous.as_deref(), Some("http_proxy=http://old:1\n"));
        restore_environment(&path, &previous).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "http_proxy=http://old:1\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "touches live desktop settings; run explicitly to verify Linux system proxy"]
    fn live_desktop_roundtrip_applies_and_restores() {
        let before_mode = gget("org.gnome.system.proxy", "mode").unwrap_or_default();
        let before_host = gget("org.gnome.system.proxy.http", "host").unwrap_or_default();
        enable().expect("enable system proxy");
        assert!(active(), "snapshot must be recorded");
        if gsettings_available() {
            assert_eq!(gget("org.gnome.system.proxy", "mode").unwrap(), "manual");
            assert_eq!(
                gget("org.gnome.system.proxy.http", "host").unwrap(),
                "127.0.0.1"
            );
            assert_eq!(gget("org.gnome.system.proxy.http", "port").unwrap(), PORT);
            assert_eq!(gget("org.gnome.system.proxy.socks", "port").unwrap(), PORT);
        }
        if let Some(path) = environment_file_path() {
            let text = std::fs::read_to_string(&path).expect("environment.d file written");
            assert!(text.contains(PROXY_HTTP));
        }
        restore().expect("restore system proxy");
        assert!(!active(), "snapshot cleared after restore");
        if gsettings_available() {
            assert_eq!(gget("org.gnome.system.proxy", "mode").unwrap(), before_mode);
            assert_eq!(
                gget("org.gnome.system.proxy.http", "host").unwrap(),
                before_host
            );
        }
        if let Some(path) = environment_file_path() {
            let restored = std::fs::read_to_string(&path).ok();
            assert!(
                restored
                    .as_deref()
                    .is_none_or(|text| !text.contains(PROXY_HTTP)),
                "environment.d must not keep pointing at the local proxy"
            );
        }
    }
}
