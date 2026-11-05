use std::fs;
use std::path::Path;

use rand::RngCore;
use rusqlite::Connection;

pub fn create(db: &Connection, path: &str, key: &[u8]) -> anyhow::Result<String> {
    let p = Path::new(path);
    let dir = p.parent().unwrap_or_else(|| Path::new("."));
    let base = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("veilink.db");
    fs::create_dir_all(dir)?;

    let mut rand_bytes = [0u8; 6];
    rand::rng().fill_bytes(&mut rand_bytes);
    let suffix = hex::encode(rand_bytes);
    let dest_path = dir.join(format!("{base}.pre-upgrade-{suffix}.db"));
    if dest_path.exists() {
        let _ = fs::remove_file(&dest_path);
    }
    let dest_str = dest_path.to_string_lossy().to_string();
    if let Err(e) = db.execute("VACUUM INTO ?1", [&dest_str]) {
        let _ = fs::remove_file(&dest_path);
        return Err(e.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&dest_path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&dest_path);
            return Err(e.into());
        }
    }
    if !key.is_empty() {
        let key_path = Path::new(&format!("{dest_str}.key")).to_path_buf();
        if let Err(e) = fs::write(&key_path, key) {
            let _ = fs::remove_file(&dest_path);
            let _ = fs::remove_file(&key_path);
            return Err(e.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)) {
                let _ = fs::remove_file(&dest_path);
                let _ = fs::remove_file(&key_path);
                return Err(e.into());
            }
        }
    }
    Ok(dest_str)
}
