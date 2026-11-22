#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::Command;
use flate2::read::GzDecoder;

const GZ_DESKTOP: &[u8] = include_bytes!("../payload/desktop.exe.gz");
const GZ_LOADER: &[u8] = include_bytes!("../payload/WebView2Loader.dll.gz");
const GZ_SING_BOX: &[u8] = include_bytes!("../payload/sing-box.exe.gz");
const GZ_WINTUN: &[u8] = include_bytes!("../payload/wintun.dll.gz");

const DESKTOP_SIZE: u64 = 29808460;
const LOADER_SIZE: u64 = 160320;
const SING_BOX_SIZE: u64 = 82074624;
const WINTUN_SIZE: u64 = 427552;

fn unpack_if_needed(target: &PathBuf, gz_data: &[u8], expected_size: u64) -> io::Result<()> {
    if let Ok(meta) = fs::metadata(target) {
        if meta.len() == expected_size {
            return Ok(());
        }
    }

    let mut decoder = GzDecoder::new(gz_data);
    let mut decompressed = Vec::with_capacity(expected_size as usize);
    decoder.read_to_end(&mut decompressed)?;

    let tmp_path = target.with_extension("tmp");
    fs::write(&tmp_path, &decompressed)?;
    let _ = fs::remove_file(target);
    fs::rename(&tmp_path, target)?;

    Ok(())
}

fn resolve_bin_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("KasperVPN").join("bin");
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata).join("KasperVPN").join("bin");
    }
    std::env::temp_dir().join("KasperVPN_bin")
}

fn main() {
    let bin_dir = resolve_bin_dir();
    let _ = fs::create_dir_all(&bin_dir);

    let exe_path = bin_dir.join("KasperVPN.exe");
    let dll_path = bin_dir.join("WebView2Loader.dll");
    let sing_box_path = bin_dir.join("sing-box.exe");
    let wintun_path = bin_dir.join("wintun.dll");

    let _ = unpack_if_needed(&exe_path, GZ_DESKTOP, DESKTOP_SIZE);
    let _ = unpack_if_needed(&dll_path, GZ_LOADER, LOADER_SIZE);
    let _ = unpack_if_needed(&sing_box_path, GZ_SING_BOX, SING_BOX_SIZE);
    let _ = unpack_if_needed(&wintun_path, GZ_WINTUN, WINTUN_SIZE);

    let mut cmd = Command::new(&exe_path);
    cmd.args(std::env::args().skip(1));
    cmd.current_dir(&bin_dir);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW
        cmd.creation_flags(0x08000000);
    }

    let _ = cmd.spawn();
}
