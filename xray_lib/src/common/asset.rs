use std::env;
use std::path::{Path, PathBuf};

pub fn get_asset_location(file: &str) -> PathBuf {
    let asset_path = env::var("XRAY_ASSET_LOCATION")
        .ok()
        .map(PathBuf::from)
        .or_else(|| get_executable_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));

    let def_path = asset_path.join(file);

    if def_path.exists() {
        return def_path;
    }

    def_path
}

fn get_executable_dir() -> std::io::Result<PathBuf> {
    let exe = env::current_exe()?;
    Ok(exe.parent().unwrap_or(Path::new(".")).to_path_buf())
}