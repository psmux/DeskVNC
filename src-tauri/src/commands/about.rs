//! Build and system fingerprint for the About dialog (PRD/11 §3.4).
//!
//! Two audiences share this one struct: a user pasting "what exactly am I
//! running" into a bug report, and whoever reads that report needing to check
//! out the precise commit. The git fields are stamped into the binary at
//! compile time by `build.rs` (never read at runtime, an installed app has no
//! repository), so they identify the build even when the version number
//! hasn't moved, including local `-dirty` builds that match no commit at all.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AboutInfo {
    // identity
    pub app_version: String,
    /// `git describe --tags --always --dirty`: the one-line fingerprint.
    pub git_describe: String,
    pub git_hash: String,
    pub git_hash_short: String,
    pub git_branch: String,
    pub git_commit_date: String,
    /// "clean" | "dirty" | "unknown"
    pub git_dirty: String,
    // toolchain
    pub build_profile: String,
    pub rustc_version: String,
    pub tauri_version: String,
    // host system
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub webview_version: String,
}

#[tauri::command]
pub fn about_info() -> AboutInfo {
    let info = os_info::get();
    AboutInfo {
        app_version: env!("CARGO_PKG_VERSION").into(),
        git_describe: env!("DESKVNC_GIT_DESCRIBE").into(),
        git_hash: env!("DESKVNC_GIT_HASH").into(),
        git_hash_short: env!("DESKVNC_GIT_HASH_SHORT").into(),
        git_branch: env!("DESKVNC_GIT_BRANCH").into(),
        git_commit_date: env!("DESKVNC_GIT_COMMIT_DATE").into(),
        git_dirty: env!("DESKVNC_GIT_DIRTY").into(),
        build_profile: env!("DESKVNC_BUILD_PROFILE").into(),
        rustc_version: env!("DESKVNC_RUSTC_VERSION").into(),
        tauri_version: tauri::VERSION.into(),
        os: info.os_type().to_string(),
        os_version: info.version().to_string(),
        arch: std::env::consts::ARCH.into(),
        webview_version: tauri::webview_version().unwrap_or_else(|_| "unknown".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stamp_is_never_empty() {
        // build.rs degrades every field to "unknown" rather than "", so an
        // empty string here means the stamping pipeline itself broke.
        let a = about_info();
        for (name, v) in [
            ("app_version", &a.app_version),
            ("git_describe", &a.git_describe),
            ("git_hash", &a.git_hash),
            ("git_branch", &a.git_branch),
            ("git_dirty", &a.git_dirty),
            ("build_profile", &a.build_profile),
            ("rustc_version", &a.rustc_version),
            ("tauri_version", &a.tauri_version),
            ("os", &a.os),
            ("arch", &a.arch),
        ] {
            assert!(!v.is_empty(), "{name} is empty");
        }
    }

    #[test]
    fn a_repo_build_carries_a_real_commit() {
        // This test runs from the repository, so the stamp must be a hash,
        // not the tarball fallback, and the dirty flag must be decided.
        let a = about_info();
        assert_eq!(a.git_hash.len(), 40, "full hash expected: {}", a.git_hash);
        assert!(matches!(a.git_dirty.as_str(), "clean" | "dirty"));
        assert!(a.git_describe.contains(&a.git_hash_short) || a.git_describe.starts_with('v'));
    }
}
