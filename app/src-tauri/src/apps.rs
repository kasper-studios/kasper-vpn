use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledApp {
    pub id: String,
    pub name: String,
    pub exec: String,
}

pub fn list_installed_apps() -> Vec<InstalledApp> {
    let mut map: BTreeMap<String, InstalledApp> = BTreeMap::new();

    #[cfg(target_os = "linux")]
    scan_linux_desktop_entries(&mut map);

    #[cfg(target_os = "windows")]
    scan_windows_apps(&mut map);

    #[cfg(target_os = "macos")]
    scan_macos_apps(&mut map);

    // Default presets always available as fallback or primary quick options
    let defaults = [
        ("discord", "Discord", "Discord"),
        ("spotify", "Spotify", "spotify"),
        ("steam", "Steam", "steam"),
        ("browser", "Браузеры (Chrome, Firefox, Edge, Brave)", "firefox"),
        ("telegram", "Telegram", "telegram-desktop"),
    ];

    for (id, name, exec) in defaults {
        let key = id.to_lowercase();
        if !map.contains_key(&key) {
            map.insert(
                key,
                InstalledApp {
                    id: id.to_string(),
                    name: name.to_string(),
                    exec: exec.to_string(),
                },
            );
        }
    }

    let mut list: Vec<InstalledApp> = map.into_values().collect();
    list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    list
}

#[cfg(target_os = "linux")]
fn scan_linux_desktop_entries(map: &mut BTreeMap<String, InstalledApp>) {
    let mut dirs: Vec<PathBuf> = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        PathBuf::from("/var/lib/flatpak/exports/share/applications"),
        PathBuf::from("/var/lib/snapd/desktop/applications"),
    ];

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);
        dirs.push(home_path.join(".local/share/applications"));
        dirs.push(home_path.join(".local/share/flatpak/exports/share/applications"));
    }

    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("desktop") {
                continue;
            }
            if let Some(app) = parse_desktop_file(&path) {
                let key = app.exec.to_lowercase();
                if !map.contains_key(&key) {
                    map.insert(key, app);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_desktop_file(path: &Path) -> Option<InstalledApp> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut in_desktop_entry = false;
    let mut name = None;
    let mut exec = None;
    let mut no_display = false;
    let mut is_application = true;

    for line in content.lines() {
        let line = line.trim();
        if line == "[Desktop Entry]" {
            in_desktop_entry = true;
            continue;
        } else if line.starts_with('[') {
            in_desktop_entry = false;
            continue;
        }
        if !in_desktop_entry {
            continue;
        }

        if let Some(val) = line.strip_prefix("Name=") {
            if name.is_none() {
                name = Some(val.trim().to_string());
            }
        } else if let Some(val) = line.strip_prefix("Exec=") {
            if exec.is_none() {
                let first_word = val
                    .trim()
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches(['"', '\'']);
                let file_name = Path::new(first_word)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("");
                if !file_name.is_empty() {
                    exec = Some(file_name.to_string());
                }
            }
        } else if line == "NoDisplay=true" {
            no_display = true;
        } else if let Some(val) = line.strip_prefix("Type=") {
            if val.trim() != "Application" {
                is_application = false;
            }
        }
    }

    if no_display || !is_application {
        return None;
    }

    let name = name?;
    let exec = exec?;
    if exec.is_empty() {
        return None;
    }

    Some(InstalledApp {
        id: exec.clone(),
        name,
        exec,
    })
}

#[cfg(target_os = "windows")]
fn scan_windows_apps(map: &mut BTreeMap<String, InstalledApp>) {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(pd) = std::env::var("ProgramData") {
        dirs.push(PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    if let Ok(ad) = std::env::var("APPDATA") {
        dirs.push(PathBuf::from(ad).join(r"Microsoft\Windows\Start Menu\Programs"));
    }

    fn scan_dir_recursive(dir: &Path, map: &mut BTreeMap<String, InstalledApp>, depth: usize) {
        if depth > 4 {
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir_recursive(&path, map, depth + 1);
            } else if path.extension().and_then(|s| s.to_str()) == Some("lnk") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let name = stem.to_string();
                    let exec = format!("{name}.exe");
                    let key = exec.to_lowercase();
                    if !map.contains_key(&key) {
                        map.insert(
                            key,
                            InstalledApp {
                                id: exec.clone(),
                                name,
                                exec,
                            },
                        );
                    }
                }
            }
        }
    }

    for dir in dirs {
        scan_dir_recursive(&dir, map, 0);
    }
}

#[cfg(target_os = "macos")]
fn scan_macos_apps(map: &mut BTreeMap<String, InstalledApp>) {
    let mut dirs = vec![PathBuf::from("/Applications")];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join("Applications"));
    }

    for dir in dirs {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("app") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let name = stem.to_string();
                    let exec = name.clone();
                    let key = exec.to_lowercase();
                    if !map.contains_key(&key) {
                        map.insert(
                            key,
                            InstalledApp {
                                id: exec.clone(),
                                name,
                                exec,
                            },
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_installed_apps_returns_non_empty_list() {
        let apps = list_installed_apps();
        assert!(!apps.is_empty());
        // Defaults must be present
        assert!(apps.iter().any(|a| a.id == "discord" || a.exec == "Discord"));
        assert!(apps.iter().any(|a| a.id == "telegram" || a.exec.contains("telegram")));
    }
}
