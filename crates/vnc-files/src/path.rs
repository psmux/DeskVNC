//! Path safety (PRD/08 §4).
//!
//! **Everything a remote server tells us about its filesystem is untrusted.**
//! A directory listing is attacker-controlled data: names can contain `..`,
//! absolute prefixes, `\` separators, NUL bytes, Windows drive letters or
//! UNC prefixes. If any of that reached `Path::join` we would happily write
//! outside the directory the user picked.
//!
//! The rules here are deliberately *lexical*, we never call `canonicalize`
//! on an attacker-controlled path, because that both touches the filesystem
//! and follows symlinks. Instead:
//!
//! * [`normalize_remote`] cleans a POSIX remote path and rejects any `..`.
//! * [`component`] validates a single path element.
//! * [`safe_local_join`] maps a *relative, server-supplied* path onto a local
//!   root and guarantees the result stays under that root.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// Longest single path element we will accept. Real filesystems cap at 255
/// bytes; anything longer is either a bug or an attempt to blow a buffer.
pub const MAX_COMPONENT_LEN: usize = 255;

/// Longest whole path we will accept.
pub const MAX_PATH_LEN: usize = 4096;

/// Windows device names that can never be used as a file name, whatever the
/// extension (`con.txt` is still `CON`). Checked only when the *local* side is
/// Windows, but exposed unconditionally so it can be unit-tested everywhere.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn reject(what: impl std::fmt::Display) -> Error {
    Error::UnsafePath(what.to_string())
}

/// Is `name` a reserved Windows device name (case-insensitive, extension
/// ignored)?
pub fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.trim_end_matches([' ', '.']).to_ascii_uppercase();
    WINDOWS_RESERVED.contains(&upper.as_str())
}

/// Validate one path element (a file or directory name, never a path).
///
/// Rejects: empty, `.`, `..`, embedded separators of either flavour, NUL and
/// other C0 control characters, over-long names, and, when the local side is
/// Windows, reserved device names and trailing dots/spaces.
pub fn component(name: &str) -> Result<&str> {
    if name.is_empty() {
        return Err(reject("empty path component"));
    }
    if name.len() > MAX_COMPONENT_LEN {
        return Err(reject(format!("path component too long ({})", name.len())));
    }
    // `.`, `..` and the classic filter-evasion shapes `...` / `....`. A name
    // made only of dots is never legitimate and is exactly what naive
    // `../`-stripping filters get fooled by.
    if name.chars().all(|c| c == '.') {
        return Err(reject(format!("dots-only path component `{name}`")));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(reject(format!("path separator in name `{name}`")));
    }
    if name.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
        return Err(reject("control character in name"));
    }
    if cfg!(windows) {
        if is_windows_reserved(name) {
            return Err(reject(format!("reserved device name `{name}`")));
        }
        if name.ends_with('.') || name.ends_with(' ') {
            return Err(reject(format!("trailing dot or space in `{name}`")));
        }
        if name.contains(':') {
            return Err(reject(format!("colon in name `{name}`")));
        }
    }
    Ok(name)
}

/// Does `path` look absolute to *any* filesystem we might be talking to?
///
/// Deliberately paranoid: a POSIX client must still reject `C:\Windows` and
/// `\\server\share` because the string may be replayed to a Windows peer, and
/// a Windows client must still reject `/etc/passwd`.
pub fn looks_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    if path.starts_with('/') || path.starts_with('\\') {
        return true;
    }
    // Drive-relative (`C:foo`) and drive-absolute (`C:\foo`) alike.
    if bytes.len() >= 2 && bytes[1] == b':' && (bytes[0] as char).is_ascii_alphabetic() {
        return true;
    }
    false
}

/// Normalise a POSIX remote path, rejecting traversal.
///
/// Collapses `//` and `.`, keeps a leading `/` (remote absolute paths are
/// perfectly normal), strips trailing slashes, and returns
/// [`Error::UnsafePath`] on any `..` element. We never *resolve* `..`
/// ourselves, `a/b/../c` could be `a/c` or something else entirely if `b` is
/// a symlink, so the only safe answer is to refuse.
pub fn normalize_remote(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(reject("empty path"));
    }
    if path.len() > MAX_PATH_LEN {
        return Err(reject(format!("path too long ({})", path.len())));
    }
    if path.contains('\0') {
        return Err(reject("NUL byte in path"));
    }

    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(reject(format!("`..` traversal in `{path}`"))),
            other if other.chars().all(|c| c == '.') => {
                return Err(reject(format!("dots-only component in `{path}`")))
            }
            other => {
                if other.len() > MAX_COMPONENT_LEN {
                    return Err(reject("path component too long"));
                }
                if other.chars().any(|c| (c as u32) < 0x20) {
                    return Err(reject("control character in path"));
                }
                parts.push(other);
            }
        }
    }

    if parts.is_empty() {
        return Ok(if absolute { "/".into() } else { ".".into() });
    }
    let joined = parts.join("/");
    Ok(if absolute {
        format!("/{joined}")
    } else {
        joined
    })
}

/// Join a normalised remote directory with one server-supplied element.
pub fn join_remote(dir: &str, name: &str) -> Result<String> {
    let dir = normalize_remote(dir)?;
    let name = component(name)?;
    Ok(if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    })
}

/// The last element of a remote path, validated as a usable local file name.
pub fn remote_file_name(path: &str) -> Result<String> {
    let normalized = normalize_remote(path)?;
    let name = normalized.rsplit('/').next().unwrap_or_default();
    Ok(component(name)?.to_string())
}

/// The parent directory of a remote path (`/` stays `/`).
pub fn remote_parent(path: &str) -> Result<String> {
    let normalized = normalize_remote(path)?;
    if normalized == "/" || normalized == "." {
        return Ok(normalized);
    }
    match normalized.rfind('/') {
        Some(0) => Ok("/".into()),
        Some(i) => Ok(normalized[..i].to_string()),
        None => Ok(".".into()),
    }
}

/// Map a **server-supplied relative path** onto a local directory.
///
/// This is the function that stops a malicious listing from writing outside
/// the directory the user chose in the file dialog. It:
///
/// 1. refuses anything that looks absolute on any platform,
/// 2. splits on both `/` and `\` so a Windows-flavoured payload can't smuggle
///    an element past a POSIX split,
/// 3. validates every element with [`component`] (which rejects `..`),
/// 4. re-checks the assembled path with `std::path::Component` so a
///    platform-specific parse can't disagree with ours, and
/// 5. asserts the result is still prefixed by `root`.
pub fn safe_local_join(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty() {
        return Err(reject("empty relative path"));
    }
    if relative.len() > MAX_PATH_LEN {
        return Err(reject("relative path too long"));
    }
    if relative.contains('\0') {
        return Err(reject("NUL byte in path"));
    }
    if looks_absolute(relative) {
        return Err(reject(format!("absolute path `{relative}`")));
    }

    let mut out = root.to_path_buf();
    let mut depth = 0usize;
    for part in relative.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        out.push(component(part)?);
        depth += 1;
    }
    if depth == 0 {
        return Err(reject(format!("no usable components in `{relative}`")));
    }

    // Belt and braces: whatever the host OS made of the assembled path, it
    // must contain no parent/root/prefix components beyond `root` itself and
    // must still start with `root`.
    let tail = out
        .strip_prefix(root)
        .map_err(|_| reject("path escaped the destination directory"))?;
    for c in tail.components() {
        match c {
            Component::Normal(_) => {}
            _ => return Err(reject("path escaped the destination directory")),
        }
    }
    Ok(out)
}

/// Build the local destination for a downloaded remote path.
///
/// `remote` is the full remote path, `remote_root` the directory the download
/// was rooted at; the portion in between becomes the relative path under
/// `local_root`.
pub fn local_destination(local_root: &Path, remote_root: &str, remote: &str) -> Result<PathBuf> {
    let root = normalize_remote(remote_root)?;
    let full = normalize_remote(remote)?;
    let relative = if full == root {
        // Downloading the root itself: use its own name.
        remote_file_name(&full)?
    } else {
        let prefix = if root == "/" {
            "/".to_string()
        } else {
            format!("{root}/")
        };
        full.strip_prefix(&prefix)
            .ok_or_else(|| reject(format!("`{remote}` is outside `{remote_root}`")))?
            .to_string()
    };
    safe_local_join(local_root, &relative)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------- traversal

    /// PRD/08 §5: "No path traversal is possible from a malicious server's
    /// directory listing." Every one of these is a real-world payload shape.
    const HOSTILE: &[&str] = &[
        "..",
        "../etc/passwd",
        "../../../../../../etc/passwd",
        "a/../../b",
        "a/b/../../../c",
        "./../x",
        "foo/./../../bar",
        "..\\..\\windows\\system32",
        "a\\..\\..\\b",
        "/etc/passwd",
        "/",
        "\\\\server\\share\\evil",
        "\\windows\\system32",
        "C:\\Windows\\System32\\evil.dll",
        "c:evil",
        "Z:/x",
        "sub/../../..",
        "....//....//etc",
        "a/\0/b",
        "\0",
        "sub/..",
        "..//..//..",
    ];

    #[test]
    fn safe_local_join_rejects_every_traversal_payload() {
        let root = Path::new("/tmp/deskvnc-downloads");
        for payload in HOSTILE {
            let result = safe_local_join(root, payload);
            assert!(
                result.is_err(),
                "safe_local_join accepted hostile path {payload:?} -> {:?}",
                result.ok()
            );
        }
    }

    #[test]
    fn safe_local_join_result_never_leaves_root() {
        let root = Path::new("/tmp/deskvnc-downloads");
        // Fuzz-ish: assemble paths from safe and hostile fragments and assert
        // that anything we accept is still inside the root.
        let fragments = [
            "..", ".", "a", "b.txt", "", "..\\", "/", "\\", "c:", "sub", "…", "a b",
        ];
        for a in fragments {
            for b in fragments {
                for c in fragments {
                    let candidate = format!("{a}/{b}/{c}");
                    if let Ok(path) = safe_local_join(root, &candidate) {
                        assert!(
                            path.starts_with(root),
                            "escaped root: {candidate:?} -> {path:?}"
                        );
                        assert!(
                            !path.components().any(|c| c == Component::ParentDir),
                            "kept a `..`: {candidate:?} -> {path:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn safe_local_join_accepts_ordinary_paths() {
        let root = Path::new("/tmp/dl");
        assert_eq!(
            safe_local_join(root, "notes.md").unwrap(),
            PathBuf::from("/tmp/dl/notes.md")
        );
        assert_eq!(
            safe_local_join(root, "projects/site/index.html").unwrap(),
            PathBuf::from("/tmp/dl/projects/site/index.html")
        );
        // Redundant separators and `.` are fine, they just collapse.
        assert_eq!(
            safe_local_join(root, "./a//b/./c").unwrap(),
            PathBuf::from("/tmp/dl/a/b/c")
        );
        // Unicode, spaces and dots inside a name are ordinary file names.
        assert_eq!(
            safe_local_join(root, "réunion 2024.v2.txt").unwrap(),
            PathBuf::from("/tmp/dl/réunion 2024.v2.txt")
        );
    }

    // ------------------------------------------------------------ remote

    #[test]
    fn normalize_remote_rejects_traversal() {
        for payload in [
            "..",
            "../",
            "/../etc",
            "/home/user/../../etc/shadow",
            "a/../b",
            "/a/b/..",
        ] {
            assert!(
                normalize_remote(payload).is_err(),
                "normalize_remote accepted {payload:?}"
            );
        }
        assert!(normalize_remote("/a\0b").is_err());
        assert!(normalize_remote("").is_err());
    }

    #[test]
    fn normalize_remote_cleans_ordinary_paths() {
        assert_eq!(normalize_remote("/home/user").unwrap(), "/home/user");
        assert_eq!(normalize_remote("/home//user/").unwrap(), "/home/user");
        assert_eq!(normalize_remote("/home/./user").unwrap(), "/home/user");
        assert_eq!(normalize_remote("/").unwrap(), "/");
        assert_eq!(normalize_remote("//").unwrap(), "/");
        assert_eq!(normalize_remote(".").unwrap(), ".");
        assert_eq!(normalize_remote("code/src").unwrap(), "code/src");
        // A backslash is a legal POSIX file-name character; keep it remote-side.
        assert_eq!(normalize_remote("/home/a\\b").unwrap(), "/home/a\\b");
    }

    #[test]
    fn join_remote_validates_the_name() {
        assert_eq!(
            join_remote("/home/user", "notes.md").unwrap(),
            "/home/user/notes.md"
        );
        assert_eq!(join_remote("/", "etc").unwrap(), "/etc");
        for evil in ["..", ".", "a/b", "a\\b", "", "\u{1}x"] {
            assert!(
                join_remote("/home/user", evil).is_err(),
                "accepted {evil:?}"
            );
        }
    }

    #[test]
    fn remote_parent_and_name() {
        assert_eq!(remote_parent("/home/user/notes.md").unwrap(), "/home/user");
        assert_eq!(remote_parent("/home").unwrap(), "/");
        assert_eq!(remote_parent("/").unwrap(), "/");
        assert_eq!(remote_file_name("/home/user/notes.md").unwrap(), "notes.md");
        assert!(remote_file_name("/").is_err());
    }

    #[test]
    fn local_destination_maps_a_subtree() {
        let root = Path::new("/tmp/dl");
        assert_eq!(
            local_destination(root, "/home/user/code", "/home/user/code/src/main.rs").unwrap(),
            PathBuf::from("/tmp/dl/src/main.rs")
        );
        assert_eq!(
            local_destination(root, "/home/user/code", "/home/user/code").unwrap(),
            PathBuf::from("/tmp/dl/code")
        );
        // A listing that claims a sibling path must not resolve at all.
        assert!(local_destination(root, "/home/user/code", "/etc/passwd").is_err());
        assert!(local_destination(root, "/home/user/code", "/home/user/codex/x").is_err());
    }

    // --------------------------------------------------------- components

    #[test]
    fn component_rules() {
        assert!(component("notes.md").is_ok());
        assert!(component("a b.txt").is_ok());
        for evil in ["", ".", "..", "a/b", "a\\b", "a\0b", "a\nb"] {
            assert!(component(evil).is_err(), "accepted {evil:?}");
        }
        assert!(component(&"x".repeat(MAX_COMPONENT_LEN + 1)).is_err());
    }

    #[test]
    fn windows_reserved_names() {
        for name in ["CON", "con", "con.txt", "NUL.tar.gz", "lpt9", "COM1 "] {
            assert!(is_windows_reserved(name), "{name} should be reserved");
        }
        for name in ["console", "connect.txt", "com10", "auxiliary"] {
            assert!(!is_windows_reserved(name), "{name} should be fine");
        }
    }

    #[test]
    fn absolute_detection_covers_every_flavour() {
        for p in ["/etc", "\\etc", "C:\\x", "c:x", "\\\\srv\\share", "a:b/c"] {
            assert!(looks_absolute(p), "{p} should be absolute");
        }
        for p in ["etc", "a/b", "1:x", "ab:c"] {
            assert!(!looks_absolute(p), "{p} should be relative");
        }
    }
}
