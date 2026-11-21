use std::ptr;
use windows_sys::Win32::{
    Networking::WinInet::{
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
    },
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ, RegCloseKey,
        RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    },
};

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Clone, Debug)]
pub struct Snapshot {
    proxy_enable: Option<u32>,
    proxy_server: Option<String>,
    proxy_override: Option<String>,
    auto_config_url: Option<String>,
    auto_detect: Option<u32>,
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn open(access: u32) -> Result<Key, String> {
    let mut handle = ptr::null_mut();
    let path = wide(INTERNET_SETTINGS);
    let result = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut handle) };
    if result != 0 {
        return Err(format!(
            "Не удалось открыть настройки proxy Windows (код {result})"
        ));
    }
    Ok(Key(handle))
}

fn read_dword(key: HKEY, name: &str) -> Result<Option<u32>, String> {
    let name = wide(name);
    let mut ty = 0;
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    let result = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            &mut ty,
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    match result {
        0 if ty == REG_DWORD && size == 4 => Ok(Some(value)),
        2 => Ok(None),
        0 => Err("Неверный тип DWORD в настройках proxy Windows".into()),
        _ => Err(format!(
            "Не удалось прочитать DWORD proxy Windows (код {result})"
        )),
    }
}

fn read_string(key: HKEY, name: &str) -> Result<Option<String>, String> {
    let name = wide(name);
    let mut ty = 0;
    let mut size = 0u32;
    let first = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            &mut ty,
            ptr::null_mut(),
            &mut size,
        )
    };
    if first == 2 {
        return Ok(None);
    }
    if first != 0 {
        return Err(format!(
            "Не удалось прочитать размер настройки proxy Windows (код {first})"
        ));
    }
    if ty != REG_SZ {
        return Err("Неверный тип строки в настройках proxy Windows".into());
    }
    let mut value = vec![0u16; (size as usize / 2).max(1)];
    let result = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            &mut ty,
            value.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(format!(
            "Не удалось прочитать настройку proxy Windows (код {result})"
        ));
    }
    let len = value.iter().position(|&c| c == 0).unwrap_or(value.len());
    Ok(Some(String::from_utf16_lossy(&value[..len])))
}

fn set_dword(key: HKEY, name: &str, value: u32) -> Result<(), String> {
    let name = wide(name);
    let bytes = value.to_le_bytes();
    let result = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_DWORD,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "Не удалось записать DWORD proxy Windows (код {result})"
        ))
    }
}

fn set_string(key: HKEY, name: &str, value: &str) -> Result<(), String> {
    let name = wide(name);
    let value = wide(value);
    let result = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_SZ,
            value.as_ptr().cast(),
            (value.len() * 2) as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "Не удалось записать строку proxy Windows (код {result})"
        ))
    }
}

fn delete(key: HKEY, name: &str) -> Result<(), String> {
    let name = wide(name);
    let result =
        unsafe { windows_sys::Win32::System::Registry::RegDeleteValueW(key, name.as_ptr()) };
    if result == 0 || result == 2 {
        Ok(())
    } else {
        Err(format!(
            "Не удалось удалить настройку proxy Windows (код {result})"
        ))
    }
}

fn restore_dword(key: HKEY, name: &str, value: Option<u32>) -> Result<(), String> {
    match value {
        Some(v) => set_dword(key, name, v),
        None => delete(key, name),
    }
}

fn restore_string(key: HKEY, name: &str, value: Option<String>) -> Result<(), String> {
    match value {
        Some(v) => set_string(key, name, &v),
        None => delete(key, name),
    }
}

fn broadcast() -> Result<(), String> {
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        // WinINet notifications are advisory and may return FALSE when no consumer is attached.
        let _ = unsafe { InternetSetOptionW(ptr::null(), option, ptr::null(), 0) };
    }
    Ok(())
}

pub fn enable() -> Result<Snapshot, String> {
    let key = open(KEY_QUERY_VALUE)?;
    let snapshot = Snapshot {
        proxy_enable: read_dword(key.0, "ProxyEnable")?,
        proxy_server: read_string(key.0, "ProxyServer")?,
        proxy_override: read_string(key.0, "ProxyOverride")?,
        auto_config_url: read_string(key.0, "AutoConfigURL")?,
        auto_detect: read_dword(key.0, "AutoDetect")?,
    };
    if snapshot.proxy_enable == Some(1)
        && snapshot
            .proxy_server
            .as_deref()
            .is_some_and(|v| v.contains("127.0.0.1:17890") || v.contains("localhost:17890"))
    {
        return Err("Обнаружен системный proxy Windows, уже указывающий на KasperVPN. Во избежание proxy-петли подключение отменено.".into());
    }
    let key = open(KEY_SET_VALUE)?;
    let applied = (|| {
        set_string(
            key.0,
            "ProxyServer",
            "http=127.0.0.1:17890;https=127.0.0.1:17890;ftp=127.0.0.1:17890;socks=127.0.0.1:17890",
        )?;
        set_string(key.0, "ProxyOverride", "<local>;localhost;127.*;[::1]")?;
        set_dword(key.0, "ProxyEnable", 1)?;
        broadcast()
    })();
    if let Err(error) = applied {
        let _ = restore(&snapshot);
        return Err(format!(
            "Не удалось включить системный proxy Windows; попробовал восстановить настройки: {error}"
        ));
    }
    Ok(snapshot)
}

pub fn restore(snapshot: &Snapshot) -> Result<(), String> {
    let key = open(KEY_SET_VALUE)?;
    restore_string(key.0, "ProxyServer", snapshot.proxy_server.clone())?;
    restore_string(key.0, "ProxyOverride", snapshot.proxy_override.clone())?;
    restore_string(key.0, "AutoConfigURL", snapshot.auto_config_url.clone())?;
    restore_dword(key.0, "AutoDetect", snapshot.auto_detect)?;
    restore_dword(key.0, "ProxyEnable", snapshot.proxy_enable)?;
    broadcast()
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_override_covers_localhost_ipv4_and_ipv6() {
        let bypass = "<local>;localhost;127.*;[::1]";
        for token in ["<local>", "localhost", "127.*", "[::1]"] {
            assert!(bypass.split(';').any(|entry| entry == token));
        }
    }

    #[test]
    fn upstream_settings_use_local_mixed_inbound_for_each_scheme() {
        let servers =
            "http=127.0.0.1:17890;https=127.0.0.1:17890;ftp=127.0.0.1:17890;socks=127.0.0.1:17890";
        assert_eq!(servers.matches("127.0.0.1:17890").count(), 4);
    }
}
