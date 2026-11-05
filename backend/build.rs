use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=VEILINK_VERSION");
    println!("cargo:rerun-if-env-changed=VEILINK_COMMIT");
    println!("cargo:rerun-if-changed=../VERSION");
    println!("cargo:rerun-if-changed=../frontend/dist");
    println!("cargo:rerun-if-changed=internal/webui/dist");

    let dist_dir = Path::new("internal/webui/dist");
    let _ = fs::create_dir_all(dist_dir);
    let index_path = dist_dir.join("index.html");
    let frontend_dist = Path::new("../frontend/dist");
    if frontend_dist.join("index.html").exists() {
        let _ = fs::remove_dir_all(dist_dir.join("assets"));
        copy_dir_all(frontend_dist, dist_dir);
    } else if !index_path.exists() {
        let _ = fs::write(&index_path, "<!doctype html><html><body>Veilink</body></html>\n");
    }

    let version = std::env::var("VEILINK_VERSION")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            fs::read_to_string("../VERSION")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "dev".to_string());
    let commit = std::env::var("VEILINK_COMMIT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=VEILINK_BUILD_VERSION={version}");
    println!("cargo:rustc-env=VEILINK_BUILD_COMMIT={commit}");
}

fn copy_dir_all(src: &Path, dst: &Path) {
    let _ = fs::create_dir_all(dst);
    if let Ok(entries) = fs::read_dir(src) {
        for entry in entries.flatten() {
            let ty = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let dest_path = dst.join(entry.file_name());
            if ty.is_dir() {
                copy_dir_all(&entry.path(), &dest_path);
            } else if ty.is_file() {
                let _ = fs::copy(entry.path(), dest_path);
            }
        }
    }
}
