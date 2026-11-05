pub fn version() -> &'static str {
    let v = option_env!("VEILINK_BUILD_VERSION")
        .unwrap_or("dev")
        .trim();
    if v.is_empty() {
        "dev"
    } else {
        v
    }
}

pub fn commit() -> &'static str {
    let c = option_env!("VEILINK_BUILD_COMMIT")
        .unwrap_or("unknown")
        .trim();
    if c.is_empty() {
        "unknown"
    } else {
        c
    }
}
