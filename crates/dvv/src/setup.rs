//! `dvv setup`: wire dvv into the agents a person actually has.
//!
//! Registering with Claude Code was one button, and every other agent was a
//! paragraph in a document. Most people driving a machine with a free model
//! use OpenCode or Pi, so this finds whichever of them are installed and
//! does the wiring itself:
//!
//! * OpenCode gets an MCP entry in its global config and the skill.
//! * Pi has no MCP client by design. It drives tools through its shell, so it
//!   gets the skill and a `dvv` on PATH, and uses the CLI.
//! * Codex gets an MCP entry in `config.toml`.
//! * Claude Code gets `claude mcp add` run for it, and the skill.
//!
//! A config file is edited by inserting text rather than parsed and written
//! back, because OpenCode's is JSONC and a round trip through a JSON parser
//! would delete every comment in it. The original is kept beside it. A file
//! that already names deskvnc has its command pointed at this `dvv` if it
//! names another one, and is otherwise left alone, so DeskVNCViewer runs this
//! at every launch: nothing changes on a launch with nothing to do, and after
//! an update every agent follows the new `dvv` without anyone touching it.

use std::path::{Path, PathBuf};

/// The skill every agent gets, compiled in so the binary is all a person
/// needs.
const SKILL: &str = include_str!("../../../skills/deskvnc/SKILL.md");

/// The agents this knows how to wire, in the order they are reported.
const AGENTS: &[&str] = &["opencode", "pi", "codex", "claude"];

/// Set up one agent, or every one that is installed.
pub fn run(target: Option<&str>) -> i32 {
    #[cfg(unix)]
    adopt_login_path();
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(exe) => stable(plain(exe)),
        Err(e) => {
            eprintln!("this binary cannot find itself, so there is no path to register: {e}");
            return 1;
        }
    };
    let Some(home) = home() else {
        eprintln!(
            "neither HOME nor USERPROFILE is set, so there is nowhere to write an agent's config"
        );
        return 1;
    };
    let chosen: Vec<&str> = match target {
        Some(name) if AGENTS.contains(&name) => vec![name],
        Some(other) => {
            eprintln!(
                "{other:?} is not an agent dvv setup knows. It knows {}. For anything else that speaks MCP, point it at: {} mcp --stdio",
                AGENTS.join(", "),
                exe.display()
            );
            return 2;
        }
        None => AGENTS
            .iter()
            .copied()
            .filter(|name| find_agent(name).is_some())
            .collect(),
    };
    if chosen.is_empty() {
        println!(
            "No supported agent is installed (looked for {}). Install one, then run dvv setup again. Any MCP client can also run: {} mcp --stdio",
            AGENTS.join(", "),
            exe.display()
        );
        return 0;
    }
    let mut failed = false;
    for name in chosen {
        let outcome = match name {
            "opencode" => opencode(&home, &exe),
            "pi" => pi(&home, &exe),
            "codex" => codex(&home, &exe),
            _ => claude(&home, &exe),
        };
        match outcome {
            Ok(lines) => {
                println!("{name}:");
                for line in lines {
                    println!("  {line}");
                }
            }
            Err(e) => {
                failed = true;
                println!("{name}: not set up: {e}");
            }
        }
    }
    println!();
    println!("Restart an agent that was already open so it picks this up. dvv starts DeskVNCViewer itself when an agent needs it.");
    i32::from(failed)
}

/// Put the user's login shell PATH ahead of this process's.
///
/// An app opened from the Dock, Finder or a Linux desktop menu gets a bare
/// PATH, `/usr/bin:/bin:/usr/sbin:/sbin`, because shell profiles never ran.
/// DeskVNCViewer runs this at launch with exactly that PATH, so an agent
/// installed through Homebrew, nvm, fnm, Volta or npm was not found, and a
/// `claude` that is a Node script could not find `node` when it was. The
/// login shell's PATH is what the person's own terminal has, so it is asked
/// for, the way editors launched from the Dock do it. Bounded, because a
/// profile that waits on input must not hang a launch.
#[cfg(unix)]
fn adopt_login_path() {
    use std::io::Read;
    const MARK: &str = "__DVV_PATH__";
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(account_shell)
        .unwrap_or_else(|| "/bin/sh".to_string());
    // fish keeps PATH as a list, and "$PATH" there joins it with spaces.
    let script = if shell.ends_with("fish") {
        format!("printf '{MARK}%s{MARK}' (string join : $PATH)")
    } else {
        format!("printf '{MARK}%s{MARK}' \"$PATH\"")
    };
    let Ok(mut child) = std::process::Command::new(&shell)
        .args(["-ilc", &script])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    let Some(login) = out.split(MARK).nth(1).filter(|p| !p.is_empty()) else {
        return;
    };
    let mut paths: Vec<PathBuf> = std::env::split_paths(login).collect();
    if let Some(own) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&own) {
            if !paths.contains(&dir) {
                paths.push(dir);
            }
        }
    }
    if let Ok(joined) = std::env::join_paths(paths) {
        std::env::set_var("PATH", joined);
    }
}

/// The login shell on the user's account, for a process started without
/// `SHELL`, which an app launched by launchd or a desktop menu can be.
#[cfg(unix)]
fn account_shell() -> Option<String> {
    let user = std::env::var("USER").ok()?;
    let output = if cfg!(target_os = "macos") {
        std::process::Command::new("dscl")
            .args([".", "-read", &format!("/Users/{user}"), "UserShell"])
            .output()
            .ok()?
    } else {
        std::process::Command::new("getent")
            .args(["passwd", &user])
            .output()
            .ok()?
    };
    let text = String::from_utf8_lossy(&output.stdout);
    // `UserShell: /bin/zsh` from dscl, and the seventh field from getent.
    let shell = if cfg!(target_os = "macos") {
        text.split_whitespace().last()?.to_string()
    } else {
        text.trim().rsplit(':').next()?.to_string()
    };
    shell.starts_with('/').then_some(shell)
}

/// A `dvv` path that will still exist after this process ends.
///
/// The Linux AppImage runs from a mount that disappears when the app quits,
/// so an agent pointed at the `dvv` inside it would find nothing next time.
/// Run from an AppImage (the runtime sets `APPIMAGE`), this `dvv` is copied
/// to `~/.local/share/DeskVNCViewer/bin` and that copy is what every agent is
/// pointed at. Anywhere else the path is already stable and comes back as is.
fn stable(exe: PathBuf) -> PathBuf {
    if std::env::var_os("APPIMAGE").is_none() {
        return exe;
    }
    let Some(home) = home() else {
        return exe;
    };
    let dir = home.join(".local/share/DeskVNCViewer/bin");
    let copy = dir.join("dvv");
    let current = std::fs::read(&copy).ok() == std::fs::read(&exe).ok();
    if !current {
        let tmp = dir.join("dvv.new");
        let placed = std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::copy(&exe, &tmp))
            .and_then(|_| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
                }
                // A rename over the old copy works while an agent is running it.
                std::fs::rename(&tmp, &copy)
            });
        if placed.is_err() {
            return exe;
        }
    }
    copy
}

/// The user's home. `HOME` first, because Git Bash and MSYS set it and the
/// agents run under them read it; `USERPROFILE` is what a Windows process
/// started from Explorer or cmd has instead.
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// A path without Windows' `\\?\` verbatim prefix.
///
/// `canonicalize` adds it, and the path is correct with it, but it ends up in
/// other programs' config files, where Node's `spawn` and a person reading
/// the file both do worse with it than without.
fn plain(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with(r"UNC\") => PathBuf::from(rest),
        _ => path,
    }
}

/// The file names a command called `name` can have here. On Windows that is
/// the name with each executable extension, since `opencode` is
/// `opencode.exe` and an npm installed `pi` is `pi.cmd`.
fn executable_names(name: &str) -> Vec<String> {
    if cfg!(windows) {
        ["exe", "cmd", "bat", "com"]
            .iter()
            .map(|ext| format!("{name}.{ext}"))
            .collect()
    } else {
        vec![name.to_string()]
    }
}

fn find_in(dir: &Path, name: &str) -> Option<PathBuf> {
    executable_names(name)
        .into_iter()
        .map(|file| dir.join(file))
        .find(|candidate| candidate.is_file())
}

fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .and_then(|paths| std::env::split_paths(&paths).find_map(|dir| find_in(&dir, name)))
}

/// Where an agent is installed, looking past PATH.
///
/// An app opened from the Dock gets a bare PATH, so the places these agents'
/// own installers use are checked too. Without that, the button in
/// DeskVNCViewer would report no agent on a machine that has three.
fn find_agent(name: &str) -> Option<PathBuf> {
    if let Some(found) = on_path(name) {
        return Some(found);
    }
    let home = home()?;
    let mut dirs = vec![
        home.join(".local/bin"),
        home.join(".bun/bin"),
        home.join(".opencode/bin"),
        home.join(".npm-global/bin"),
        home.join(".claude/local"),
        home.join(".cargo/bin"),
        home.join(".volta/bin"),
        home.join(".asdf/shims"),
        home.join(".local/share/mise/shims"),
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/snap/bin"),
    ];
    // nvm and fnm keep one folder per Node version. Newest name last, so it
    // is searched after the others and a stale version is not preferred.
    for versions in [
        home.join(".nvm/versions/node"),
        home.join(".local/share/fnm/node-versions"),
        home.join("Library/Application Support/fnm/node-versions"),
    ] {
        let mut found: Vec<PathBuf> = std::fs::read_dir(&versions)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .collect();
        found.sort();
        for version in found.into_iter().rev() {
            dirs.push(version.join("bin"));
            dirs.push(version.join("installation/bin"));
        }
    }
    // Where npm and scoop put commands on Windows.
    if let Some(appdata) = std::env::var_os("APPDATA") {
        dirs.push(PathBuf::from(appdata).join("npm"));
    }
    dirs.push(home.join("scoop/shims"));
    let found = dirs.into_iter().find_map(|dir| find_in(&dir, name))?;
    // Found off PATH, so its folder goes on PATH for what this runs next. An
    // npm installed agent is a Node script, and nvm and fnm keep `node` in
    // that same folder: without this, `claude mcp add` failed to find it.
    if let (Some(dir), Some(paths)) = (found.parent(), std::env::var_os("PATH")) {
        let mut all: Vec<PathBuf> = vec![dir.to_path_buf()];
        all.extend(std::env::split_paths(&paths).filter(|p| p != dir));
        if let Ok(joined) = std::env::join_paths(all) {
            std::env::set_var("PATH", joined);
        }
    }
    Some(found)
}

/// Write the skill, unless the file already holds exactly this text.
///
/// The app runs this at every launch, and rewriting a file that has not
/// changed is still a change to someone who keeps their agents' files under
/// a tool that reports drift (issue #73), and to anything watching mtimes.
fn write_skill(dir: &Path) -> Result<String, String> {
    let dir = dir.join("deskvnc");
    let file = dir.join("SKILL.md");
    if std::fs::read(&file).is_ok_and(|current| current == SKILL.as_bytes()) {
        return Ok(format!("skill at {} is current", file.display()));
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(&file, SKILL).map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(format!("skill written to {}", file.display()))
}

/// Take out the skill `write_skill` put in `dir`, and its folder when that
/// leaves it empty. A file of that name that is not ours is left.
fn remove_skill(dir: &Path) -> Option<String> {
    let folder = dir.join("deskvnc");
    let file = folder.join("SKILL.md");
    let text = std::fs::read_to_string(&file).ok()?;
    if !text.contains("name: deskvnc") {
        return Some(format!(
            "{} is not the DeskVNC skill, so it was left alone",
            file.display()
        ));
    }
    if let Err(e) = std::fs::remove_file(&file) {
        return Some(format!("could not remove {}: {e}", file.display()));
    }
    let _ = std::fs::remove_dir(&folder);
    // The skills folder too when setup made it and nothing else is in it.
    let _ = std::fs::remove_dir(dir);
    Some(format!("removed the skill at {}", file.display()))
}

/// A directory named by an environment variable, or `fallback` when the
/// variable is unset or empty.
fn dir_from(var: Option<std::ffi::OsString>, fallback: PathBuf) -> PathBuf {
    var.filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or(fallback)
}

/// Claude Code's config folder: `CLAUDE_CONFIG_DIR` when it is set, which is
/// where Claude Code then reads skills from, and `~/.claude` otherwise.
pub fn claude_dir(home: &Path, var: Option<std::ffi::OsString>) -> PathBuf {
    dir_from(var, home.join(".claude"))
}

/// Codex's home: `CODEX_HOME` when it is set, `~/.codex` otherwise. Its
/// `config.toml` and its `skills` both live there.
pub fn codex_dir(home: &Path, var: Option<std::ffi::OsString>) -> PathBuf {
    dir_from(var, home.join(".codex"))
}

/// OpenCode's global config folder: `$XDG_CONFIG_HOME/opencode`, or
/// `~/.config/opencode`.
fn opencode_dir(home: &Path) -> PathBuf {
    dir_from(std::env::var_os("XDG_CONFIG_HOME"), home.join(".config")).join("opencode")
}

/// Keep the original before the first edit, never overwriting an older copy.
fn backup(file: &Path) -> Result<(), String> {
    let copy = file.with_extension(format!(
        "{}.before-dvv",
        file.extension().and_then(|e| e.to_str()).unwrap_or("bak")
    ));
    if !copy.exists() {
        std::fs::copy(file, &copy).map_err(|e| format!("backing up {}: {e}", file.display()))?;
    }
    Ok(())
}

fn opencode(home: &Path, exe: &Path) -> Result<Vec<String>, String> {
    let dir = opencode_dir(home);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let entry = format!(
        r#""deskvnc": {{ "type": "local", "command": [{}, "mcp", "--stdio"], "enabled": true }}"#,
        serde_json::to_string(&exe.display().to_string()).unwrap_or_default()
    );
    let existing = ["opencode.jsonc", "opencode.json"]
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.exists());
    let mut lines = Vec::new();
    match existing {
        None => {
            let file = dir.join("opencode.json");
            let body = format!(
                "{{\n  \"$schema\": \"https://opencode.ai/config.json\",\n  \"mcp\": {{\n    {entry}\n  }}\n}}\n"
            );
            std::fs::write(&file, body).map_err(|e| format!("{}: {e}", file.display()))?;
            lines.push(format!(
                "created {} with the deskvnc MCP server",
                file.display()
            ));
        }
        Some(file) => {
            let text =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            if text.contains("\"deskvnc\"") {
                let path = serde_json::to_string(&exe.display().to_string()).unwrap_or_default();
                match repoint_json_command(&text, &path) {
                    Some(edited) => {
                        backup(&file)?;
                        std::fs::write(&file, edited)
                            .map_err(|e| format!("{}: {e}", file.display()))?;
                        lines.push(format!(
                            "pointed the deskvnc MCP server in {} at this dvv",
                            file.display()
                        ));
                    }
                    None => lines.push(format!("{} already uses this dvv", file.display())),
                }
            } else {
                let edited = insert_mcp_entry(&text, &entry).ok_or_else(|| {
                    format!(
                        "{} does not look like a JSON object, so it was not touched. Add this under \"mcp\": {entry}",
                        file.display()
                    )
                })?;
                backup(&file)?;
                std::fs::write(&file, edited).map_err(|e| format!("{}: {e}", file.display()))?;
                lines.push(format!(
                    "added the deskvnc MCP server to {}",
                    file.display()
                ));
            }
        }
    }
    lines.push(write_skill(&dir.join("skills"))?);
    lines.push("check it with: opencode mcp list".to_string());
    Ok(lines)
}

/// Point an existing `"deskvnc"` entry's command at `path` (a JSON string,
/// quotes included), or `None` when it already points there or is not one
/// this can safely edit.
///
/// An update moves `dvv`, or the person reinstalls somewhere else, and an
/// entry left naming the old one makes every agent call fail with a missing
/// file. Only the first string in the entry's `"command"` array is replaced,
/// and only when it names a `dvv`, so a wrapper somebody wrote on purpose is
/// left alone. Comments and layout survive because nothing else is touched.
pub fn repoint_json_command(text: &str, path: &str) -> Option<String> {
    let key = text.find("\"deskvnc\"")?;
    let command = key + text[key..].find("\"command\"")?;
    // A `}` between the two means the `"command"` found belongs to a later
    // entry, because this one has none.
    if text[key..command].contains('}') {
        return None;
    }
    let open = command + text[command..].find('[')?;
    let start = open + text[open..].find('"')?;
    let bytes = text.as_bytes();
    let mut end = start + 1;
    while end < bytes.len() {
        match bytes[end] {
            b'\\' => end += 2,
            b'"' => break,
            _ => end += 1,
        }
    }
    let old = text.get(start..=end)?;
    if old == path {
        return None;
    }
    let old_path: String = serde_json::from_str(old).ok()?;
    if !names_a_dvv(&old_path) {
        return None;
    }
    Some(format!("{}{path}{}", &text[..start], &text[end + 1..]))
}

/// Is this the path of a `dvv` executable, whichever install it came from?
///
/// Split on both separators rather than through `Path`, which on macOS and
/// Linux does not treat `\` as one, so the answer is the same on every
/// platform for a config written on any of them.
fn names_a_dvv(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();
    lower == "dvv" || lower == "dvv.exe"
}

/// Put an entry inside the top level `"mcp"` object, adding one if there is
/// none, by inserting text so comments and layout survive.
pub fn insert_mcp_entry(text: &str, entry: &str) -> Option<String> {
    if let Some(key) = find_top_level_key(text, "mcp") {
        let open = key + text[key..].find('{')?;
        let mut out = String::with_capacity(text.len() + entry.len() + 8);
        out.push_str(&text[..=open]);
        out.push_str("\n    ");
        out.push_str(entry);
        // A comma only when the object already has something in it.
        let rest = &text[open + 1..];
        if !rest.trim_start().starts_with('}') {
            out.push(',');
        }
        out.push_str(rest);
        return Some(out);
    }
    let open = text.find('{')?;
    let mut out = String::with_capacity(text.len() + entry.len() + 32);
    out.push_str(&text[..=open]);
    out.push_str("\n  \"mcp\": {\n    ");
    out.push_str(entry);
    out.push_str("\n  }");
    if !text[open + 1..].trim_start().starts_with('}') {
        out.push(',');
    }
    out.push_str(&text[open + 1..]);
    Some(out)
}

/// The byte offset of `"name"` as a key of the outermost object, skipping
/// strings and comments so a `"mcp"` inside a value or a comment is not taken
/// for it.
fn find_top_level_key(text: &str, name: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let needle = format!("\"{name}\"");
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                if depth == 1 && text[i..].starts_with(&needle) {
                    let after = text[i + needle.len()..].trim_start();
                    if after.starts_with(':') {
                        return Some(i);
                    }
                }
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    None
}

fn pi(home: &Path, exe: &Path) -> Result<Vec<String>, String> {
    let mut lines = vec![write_skill(&home.join(".pi/agent/skills"))?];
    // Beside `pi` itself when that folder takes a file, because it is on PATH
    // by definition: the person runs `pi` from it. `~/.local/bin` is the
    // fallback, and on Windows it is usually not on PATH, which used to leave
    // the person editing their environment by hand.
    let pi_dir = find_agent("pi").and_then(|pi| pi.parent().map(Path::to_path_buf));
    let placed = pi_dir
        .filter(|dir| writable(dir))
        .map(|dir| place_dvv(&dir, exe))
        .unwrap_or_else(|| link_onto_path(home, exe))?;
    lines.push(placed);
    lines.push(
        "Pi has no MCP client, so it drives dvv through its shell with the skill. Use a model that can see images for desktops."
            .to_string(),
    );
    Ok(lines)
}

/// Make `dvv` runnable by name in `~/.local/bin`, when there is nowhere
/// better.
fn link_onto_path(home: &Path, exe: &Path) -> Result<String, String> {
    if let Some(found) = on_path("dvv") {
        if found.canonicalize().ok().map(plain).as_deref() == Some(exe) {
            return Ok(format!("dvv is already on PATH at {}", found.display()));
        }
    }
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin).map_err(|e| format!("{}: {e}", bin.display()))?;
    place_dvv(&bin, exe)
}

/// Put a `dvv` in `dir` that runs this one: a symlink on unix, a copy on
/// Windows, where a symlink needs developer mode or an elevated prompt.
///
/// A `dvv` already there from an older install is replaced, which is what an
/// update needs. Anything else of that name is left alone and said so.
fn place_dvv(dir: &Path, exe: &Path) -> Result<String, String> {
    let link = dir.join(if cfg!(windows) { "dvv.exe" } else { "dvv" });
    let present = link.symlink_metadata().is_ok();
    #[cfg(unix)]
    {
        if present {
            match std::fs::read_link(&link) {
                Ok(target) if target == exe => {
                    return Ok(format!("dvv is on PATH at {}", link.display()))
                }
                Ok(target) if names_a_dvv(&target.to_string_lossy()) => {
                    std::fs::remove_file(&link).map_err(|e| format!("{}: {e}", link.display()))?;
                }
                _ if is_a_dvv(&link) => {
                    std::fs::remove_file(&link).map_err(|e| format!("{}: {e}", link.display()))?;
                }
                _ => return Ok(not_ours(&link, exe)),
            }
        }
        std::os::unix::fs::symlink(exe, &link).map_err(|e| format!("{}: {e}", link.display()))?;
    }
    #[cfg(not(unix))]
    {
        if present {
            if same_file_contents(&link, exe) {
                return Ok(format!("dvv is on PATH at {}", link.display()));
            }
            if !is_a_dvv(&link) {
                return Ok(not_ours(&link, exe));
            }
        }
        // A copy that is in use, by a holder an agent left running, cannot be
        // replaced. That is reported and not fatal: the next launch replaces
        // it, and the old one still works until then.
        if let Err(e) = std::fs::copy(exe, &link) {
            return Ok(format!(
                "{} is in use and was not updated this time ({e}); it is replaced on a later launch",
                link.display()
            ));
        }
    }
    Ok(format!("dvv is on PATH at {}", link.display()))
}

fn not_ours(link: &Path, exe: &Path) -> String {
    format!(
        "{} already exists and is not a dvv, so it was left alone. The agent can still run {}",
        link.display(),
        exe.display()
    )
}

/// Can this process create a file in `dir`?
fn writable(dir: &Path) -> bool {
    let probe = dir.join(".dvv-write-probe");
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// Do these two files hold the same bytes? Sizes first, which settles it for
/// nearly every update.
#[cfg(not(unix))]
fn same_file_contents(a: &Path, b: &Path) -> bool {
    let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    ma.len() == mb.len() && matches!((std::fs::read(a), std::fs::read(b)), (Ok(x), Ok(y)) if x == y)
}

/// Does the file at `path` answer `version` the way dvv does?
fn is_a_dvv(path: &Path) -> bool {
    std::process::Command::new(path)
        .arg("version")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).starts_with("dvv "))
}

fn codex(home: &Path, exe: &Path) -> Result<Vec<String>, String> {
    let dir = codex_dir(home, std::env::var_os("CODEX_HOME"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let file = dir.join("config.toml");
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    if text.contains("[mcp_servers.deskvnc]") {
        let path = serde_json::to_string(&exe.display().to_string()).unwrap_or_default();
        let line = match repoint_toml_command(&text, &path) {
            Some(edited) => {
                backup(&file)?;
                std::fs::write(&file, edited).map_err(|e| format!("{}: {e}", file.display()))?;
                format!("pointed deskvnc in {} at this dvv", file.display())
            }
            None => format!("{} already uses this dvv", file.display()),
        };
        return Ok(vec![line, write_skill(&dir.join("skills"))?]);
    }
    if file.exists() {
        backup(&file)?;
    }
    let block = format!(
        "\n[mcp_servers.deskvnc]\ncommand = {}\nargs = [\"mcp\", \"--stdio\"]\n",
        serde_json::to_string(&exe.display().to_string()).unwrap_or_default()
    );
    let mut text = text;
    text.push_str(&block);
    std::fs::write(&file, text).map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(vec![
        format!("added the deskvnc MCP server to {}", file.display()),
        write_skill(&dir.join("skills"))?,
    ])
}

/// The TOML twin of [`repoint_json_command`]: the `command = "..."` line in
/// the `[mcp_servers.deskvnc]` table, pointed at `path` (a quoted string).
pub fn repoint_toml_command(text: &str, path: &str) -> Option<String> {
    let table = text.find("[mcp_servers.deskvnc]")?;
    let body = table + text[table..].find('\n')? + 1;
    let end = text[body..]
        .find("\n[")
        .map_or(text.len(), |offset| body + offset);
    let mut offset = body;
    for line in text[body..end].split_inclusive('\n') {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("command") {
            let value = rest.trim_start().strip_prefix('=')?.trim();
            if value == path {
                return None;
            }
            let old: String = serde_json::from_str(value).ok()?;
            if !names_a_dvv(&old) {
                return None;
            }
            let newline = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            return Some(format!(
                "{}command = {path}{newline}{}",
                &text[..offset],
                &text[offset + line.len()..]
            ));
        }
        offset += line.len();
    }
    None
}

fn claude(home: &Path, exe: &Path) -> Result<Vec<String>, String> {
    let claude = find_agent("claude").ok_or("Claude Code is not installed")?;
    let run = |args: &[&std::ffi::OsStr]| {
        std::process::Command::new(&claude)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("could not run claude: {e}"))
    };
    let add = || {
        run(&[
            "mcp".as_ref(),
            "add".as_ref(),
            "--scope".as_ref(),
            "user".as_ref(),
            "deskvnc".as_ref(),
            "--".as_ref(),
            exe.as_os_str(),
            "mcp".as_ref(),
            "--stdio".as_ref(),
        ])
    };
    let mut lines = Vec::new();
    let added = add()?;
    if added.status.success() {
        lines.push("registered deskvnc with claude mcp add".to_string());
    } else {
        let why = String::from_utf8_lossy(&added.stderr).to_string();
        if !why.contains("already exists") {
            return Err(format!("claude mcp add failed: {}", why.trim()));
        }
        // Registered already: by this dvv, or by the one an earlier version
        // installed. `claude mcp get` names the command, and a different one
        // is replaced so the agent is not left calling a file that is gone.
        let got = run(&["mcp".as_ref(), "get".as_ref(), "deskvnc".as_ref()])?;
        let described = String::from_utf8_lossy(&got.stdout).to_string();
        if described.contains(&exe.display().to_string()) {
            lines.push("deskvnc is registered with Claude Code and uses this dvv".to_string());
        } else {
            run(&[
                "mcp".as_ref(),
                "remove".as_ref(),
                "--scope".as_ref(),
                "user".as_ref(),
                "deskvnc".as_ref(),
            ])?;
            let again = add()?;
            if !again.status.success() {
                return Err(format!(
                    "claude mcp add failed: {}",
                    String::from_utf8_lossy(&again.stderr).trim()
                ));
            }
            lines.push("pointed deskvnc in Claude Code at this dvv".to_string());
        }
    }
    lines.push(write_skill(
        &claude_dir(home, std::env::var_os("CLAUDE_CONFIG_DIR")).join("skills"),
    )?);
    Ok(lines)
}

/// `dvv setup --remove`: take out what `dvv setup` added, from one agent or
/// from every one it knows.
///
/// For a person who turned AI agents off in DeskVNCViewer and does not want
/// their agents to keep starting `dvv` (issue #72), and for anyone who wants
/// the wiring gone. Only what this wrote is touched: an MCP entry named
/// deskvnc whose command is a `dvv`, and a skill that is the DeskVNC skill.
/// A wrapper somebody registered under that name is left, and said so. Each
/// edited file keeps its original beside it, as setup does.
pub fn remove(target: Option<&str>) -> i32 {
    #[cfg(unix)]
    adopt_login_path();
    let Some(home) = home() else {
        eprintln!("neither HOME nor USERPROFILE is set, so there is no agent config to find");
        return 1;
    };
    let chosen: Vec<&str> = match target {
        Some(name) if AGENTS.contains(&name) => vec![name],
        Some(other) => {
            eprintln!(
                "{other:?} is not an agent dvv setup knows. It knows {}.",
                AGENTS.join(", ")
            );
            return 2;
        }
        // Every one, installed or not: a config can outlive the agent.
        None => AGENTS.to_vec(),
    };
    let mut failed = false;
    for name in chosen {
        let outcome = match name {
            "opencode" => remove_opencode(&home),
            "pi" => Ok(remove_pi(&home)),
            "codex" => remove_codex(&home),
            _ => remove_claude(&home),
        };
        match outcome {
            Ok(lines) => {
                println!("{name}:");
                for line in lines {
                    println!("  {line}");
                }
            }
            Err(e) => {
                failed = true;
                println!("{name}: not changed: {e}");
            }
        }
    }
    println!();
    println!("Restart an agent that was open so it lets go of DeskVNC. dvv setup puts it back.");
    i32::from(failed)
}

fn remove_opencode(home: &Path) -> Result<Vec<String>, String> {
    let dir = opencode_dir(home);
    let mut lines = Vec::new();
    for file in ["opencode.jsonc", "opencode.json"].map(|name| dir.join(name)) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !text.contains("\"deskvnc\"") {
            continue;
        }
        match remove_json_entry(&text) {
            Some(edited) => {
                backup(&file)?;
                std::fs::write(&file, edited).map_err(|e| format!("{}: {e}", file.display()))?;
                lines.push(format!(
                    "removed the deskvnc MCP server from {}",
                    file.display()
                ));
            }
            None => lines.push(format!(
                "the deskvnc entry in {} does not run a dvv, so it was left alone",
                file.display()
            )),
        }
    }
    if lines.is_empty() {
        lines.push("no deskvnc MCP server in its config".to_string());
    }
    lines.extend(remove_skill(&dir.join("skills")));
    Ok(lines)
}

fn remove_pi(home: &Path) -> Vec<String> {
    let mut lines: Vec<String> = remove_skill(&home.join(".pi/agent/skills"))
        .into_iter()
        .collect();
    if lines.is_empty() {
        lines.push("no DeskVNC skill".to_string());
    }
    lines.push(
        "Pi starts nothing by itself; the dvv on PATH is left, and does nothing until something runs it"
            .to_string(),
    );
    lines
}

fn remove_codex(home: &Path) -> Result<Vec<String>, String> {
    let dir = codex_dir(home, std::env::var_os("CODEX_HOME"));
    let file = dir.join("config.toml");
    let mut lines = Vec::new();
    match std::fs::read_to_string(&file) {
        Ok(text) if text.contains("[mcp_servers.deskvnc]") => match remove_toml_table(&text) {
            Some(edited) => {
                backup(&file)?;
                std::fs::write(&file, edited).map_err(|e| format!("{}: {e}", file.display()))?;
                lines.push(format!(
                    "removed the deskvnc MCP server from {}",
                    file.display()
                ));
            }
            None => lines.push(format!(
                "the deskvnc table in {} does not run a dvv, so it was left alone",
                file.display()
            )),
        },
        _ => lines.push("no deskvnc MCP server in its config".to_string()),
    }
    lines.extend(remove_skill(&dir.join("skills")));
    Ok(lines)
}

fn remove_claude(home: &Path) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    if let Some(claude) = find_agent("claude") {
        let run = |args: &[&str]| {
            std::process::Command::new(&claude)
                .args(args)
                .stdin(std::process::Stdio::null())
                .output()
                .map_err(|e| format!("could not run claude: {e}"))
        };
        let got = run(&["mcp", "get", "deskvnc"])?;
        let described = String::from_utf8_lossy(&got.stdout).to_string();
        if !got.status.success() {
            lines.push("deskvnc is not registered with Claude Code".to_string());
        } else if !described
            .split_whitespace()
            .any(|word| names_a_dvv(word.trim_matches(|c| c == '"' || c == '\'' || c == ',')))
        {
            lines.push(
                "the deskvnc server in Claude Code does not run a dvv, so it was left alone"
                    .to_string(),
            );
        } else {
            let removed = run(&["mcp", "remove", "--scope", "user", "deskvnc"])?;
            if removed.status.success() {
                lines.push("removed deskvnc from Claude Code".to_string());
            } else {
                return Err(format!(
                    "claude mcp remove failed: {}. It may be registered in another scope; claude mcp get deskvnc says which",
                    String::from_utf8_lossy(&removed.stderr).trim()
                ));
            }
        }
    } else {
        lines.push("Claude Code is not installed".to_string());
    }
    lines.extend(remove_skill(
        &claude_dir(home, std::env::var_os("CLAUDE_CONFIG_DIR")).join("skills"),
    ));
    Ok(lines)
}

/// The end of the JSON value that starts at `start`, an object or array,
/// skipping strings and comments: the index just past its closing bracket.
fn value_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Take the `"deskvnc"` entry out of an OpenCode config, with the comma that
/// joined it to its neighbour, by cutting text so comments and layout
/// survive. `None` when there is no such entry, or its command is not a
/// `dvv`.
pub fn remove_json_entry(text: &str) -> Option<String> {
    let key = text.find("\"deskvnc\"")?;
    let colon = key + "\"deskvnc\"".len();
    let open = colon + text[colon..].find('{')?;
    if text[colon..open].trim() != ":" {
        return None;
    }
    let end = value_end(text, open)?;
    let body = &text[open..end];
    let command = body.find("\"command\"")?;
    let first = command + body[command..].find('[')?;
    let quote = first + body[first..].find('"')?;
    let rest = &body[quote + 1..];
    let close = rest.find('"')?;
    if !names_a_dvv(&rest[..close].replace("\\\\", "\\")) {
        return None;
    }
    let after = &text[end..];
    let trimmed = after.trim_start();
    if let Some(stripped) = trimmed.strip_prefix(',') {
        // Followed by another entry: take the comma after it and the space
        // up to that entry.
        let skip = after.len() - stripped.trim_start().len();
        return Some(format!("{}{}", &text[..key], &text[end + skip..]));
    }
    let before = text[..key].trim_end();
    if let Some(stripped) = before.strip_suffix(',') {
        // The last entry: take the comma before it.
        return Some(format!("{}{}", stripped, &text[end..]));
    }
    // The only entry: leave an empty object.
    Some(format!("{}{}", before, &text[end..]))
}

/// Take the `[mcp_servers.deskvnc]` table, and any of its sub tables, out of
/// a Codex config. `None` when its command is not a `dvv`.
pub fn remove_toml_table(text: &str) -> Option<String> {
    let header = "[mcp_servers.deskvnc]";
    let table = text.find(header)?;
    let mut end = table + header.len();
    loop {
        match text[end..].find("\n[") {
            Some(offset) => {
                let next = end + offset + 1;
                if text[next..].starts_with("[mcp_servers.deskvnc.") {
                    end = next + 1;
                    continue;
                }
                end = next;
                break;
            }
            None => {
                end = text.len();
                break;
            }
        }
    }
    let body = &text[table..end];
    let command = body.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("command")?;
        let value = rest.trim_start().strip_prefix('=')?.trim();
        serde_json::from_str::<String>(value).ok()
    })?;
    if !names_a_dvv(&command) {
        return None;
    }
    // At the end of the file, the blank line setup put before the table goes
    // with it. Before another table, the blank line after it went instead.
    let start = if end < text.len() {
        table
    } else {
        text[..table]
            .strip_suffix("\n\n")
            .map_or(table, |kept| kept.len() + 1)
    };
    Some(format!("{}{}", &text[..start], &text[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: &str = r#""deskvnc": {}"#;

    #[test]
    fn a_stale_opencode_entry_is_pointed_at_this_dvv_and_keeps_its_comments() {
        let text = "{\n  // mine\n  \"mcp\": {\n    \"deskvnc\": { \"type\": \"local\", \"command\": [\"/old/App/dvv\", \"mcp\", \"--stdio\"], \"enabled\": true },\n    \"other\": { \"command\": [\"/x/other\"] }\n  }\n}\n";
        let out = repoint_json_command(text, "\"/new/dvv\"").unwrap();
        assert!(out.contains("[\"/new/dvv\", \"mcp\", \"--stdio\"]"));
        assert!(out.contains("// mine"));
        assert!(out.contains("\"/x/other\""));
        assert_eq!(
            repoint_json_command(&out, "\"/new/dvv\""),
            None,
            "already current"
        );
    }

    #[test]
    fn a_windows_path_is_compared_in_its_json_form() {
        let path = serde_json::to_string(r"C:\Program Files\DeskVNCViewer\dvv.exe").unwrap();
        let text =
            format!("{{ \"mcp\": {{ \"deskvnc\": {{ \"command\": [{path}, \"mcp\"] }} }} }}");
        assert_eq!(repoint_json_command(&text, &path), None);
        let old = serde_json::to_string(r"C:\Users\x\target\debug\dvv.exe").unwrap();
        let stale = text.replace(&path, &old);
        assert_eq!(
            repoint_json_command(&stale, &path).as_deref(),
            Some(text.as_str())
        );
    }

    #[test]
    fn a_wrapper_someone_wrote_is_left_alone() {
        let text =
            "{ \"mcp\": { \"deskvnc\": { \"command\": [\"/usr/local/bin/my-wrapper\", \"x\"] } } }";
        assert_eq!(repoint_json_command(text, "\"/new/dvv\""), None);
    }

    #[test]
    fn a_remote_entry_does_not_borrow_the_next_entrys_command() {
        let text = "{ \"mcp\": { \"deskvnc\": { \"type\": \"remote\", \"url\": \"http://x\" }, \"b\": { \"command\": [\"/a/dvv\"] } } }";
        assert_eq!(repoint_json_command(text, "\"/new/dvv\""), None);
    }

    #[test]
    fn a_stale_codex_table_gets_the_new_command_and_nothing_else_moves() {
        let text = "[model]\nname = \"x\"\n\n[mcp_servers.deskvnc]\ncommand = \"/old/dvv\"\nargs = [\"mcp\", \"--stdio\"]\n\n[mcp_servers.other]\ncommand = \"/old/dvv\"\n";
        let out = repoint_toml_command(text, "\"/new/dvv\"").unwrap();
        assert_eq!(
            out,
            "[model]\nname = \"x\"\n\n[mcp_servers.deskvnc]\ncommand = \"/new/dvv\"\nargs = [\"mcp\", \"--stdio\"]\n\n[mcp_servers.other]\ncommand = \"/old/dvv\"\n"
        );
        assert_eq!(repoint_toml_command(&out, "\"/new/dvv\""), None);
    }

    #[test]
    fn an_mcp_object_gets_the_entry_and_keeps_its_comments() {
        let text = "{\n  // mine\n  \"mcp\": {\n    \"other\": {}\n  }\n}\n";
        let out = insert_mcp_entry(text, ENTRY).unwrap();
        assert!(out.contains("// mine"));
        assert!(out.contains("\"deskvnc\": {},\n    \"other\""));
    }

    #[test]
    fn a_config_with_no_mcp_key_gets_one() {
        let text = "{\n  \"model\": \"x\"\n}\n";
        let out = insert_mcp_entry(text, ENTRY).unwrap();
        assert!(out.starts_with("{\n  \"mcp\": {\n    \"deskvnc\": {}\n  },\n  \"model\""));
    }

    #[test]
    fn an_mcp_inside_a_value_or_a_comment_is_not_the_key() {
        let text = "{\n  // \"mcp\": {}\n  \"provider\": { \"mcp\": {} }\n}";
        assert_eq!(find_top_level_key(text, "mcp"), None);
    }

    #[test]
    fn an_empty_mcp_object_gets_no_trailing_comma() {
        let out = insert_mcp_entry("{ \"mcp\": {} }", ENTRY).unwrap();
        assert_eq!(out, "{ \"mcp\": {\n    \"deskvnc\": {}} }");
    }

    #[test]
    fn claude_and_codex_follow_their_own_variables() {
        let home = Path::new("/home/x");
        assert_eq!(claude_dir(home, None), PathBuf::from("/home/x/.claude"));
        assert_eq!(
            claude_dir(home, Some("".into())),
            PathBuf::from("/home/x/.claude"),
            "empty counts as unset"
        );
        assert_eq!(
            claude_dir(home, Some("/cfg/claude".into())),
            PathBuf::from("/cfg/claude")
        );
        assert_eq!(codex_dir(home, None), PathBuf::from("/home/x/.codex"));
        assert_eq!(
            codex_dir(home, Some("/cfg/codex".into())),
            PathBuf::from("/cfg/codex")
        );
    }

    #[test]
    fn an_opencode_entry_comes_out_with_its_comma_and_the_rest_stays() {
        let first = "{\n  // mine\n  \"mcp\": {\n    \"deskvnc\": { \"type\": \"local\", \"command\": [\"/usr/bin/dvv\", \"mcp\", \"--stdio\"], \"enabled\": true },\n    \"other\": { \"command\": [\"/x/other\"] }\n  }\n}\n";
        assert_eq!(
            remove_json_entry(first).unwrap(),
            "{\n  // mine\n  \"mcp\": {\n    \"other\": { \"command\": [\"/x/other\"] }\n  }\n}\n"
        );
        let last =
            "{ \"mcp\": { \"other\": {}, \"deskvnc\": { \"command\": [\"/a/dvv\", \"mcp\"] } } }";
        assert_eq!(
            remove_json_entry(last).unwrap(),
            "{ \"mcp\": { \"other\": {} } }"
        );
        let only =
            "{\n  \"mcp\": {\n    \"deskvnc\": { \"command\": [\"/a/dvv\", \"mcp\"] }\n  }\n}\n";
        let out = remove_json_entry(only).unwrap();
        assert_eq!(out, "{\n  \"mcp\": {\n  }\n}\n");
        assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok());
    }

    #[test]
    fn what_dvv_setup_wrote_is_what_remove_takes_out() {
        let entry = r#""deskvnc": { "type": "local", "command": ["C:\\Program Files\\DeskVNCViewer\\dvv.exe", "mcp", "--stdio"], "enabled": true }"#;
        let original = "{\n  \"model\": \"x\",\n  \"mcp\": {\n    \"other\": {}\n  }\n}\n";
        let wired = insert_mcp_entry(original, entry).unwrap();
        let removed = remove_json_entry(&wired).unwrap();
        assert_eq!(removed, original);
    }

    #[test]
    fn a_wrapper_named_deskvnc_is_not_removed() {
        let text = "{ \"mcp\": { \"deskvnc\": { \"command\": [\"/usr/local/bin/my-wrapper\"] } } }";
        assert_eq!(remove_json_entry(text), None);
        let toml = "[mcp_servers.deskvnc]\ncommand = \"/usr/local/bin/my-wrapper\"\n";
        assert_eq!(remove_toml_table(toml), None);
    }

    #[test]
    fn a_codex_table_comes_out_and_its_neighbours_stay() {
        let text = "[model]\nname = \"x\"\n\n[mcp_servers.deskvnc]\ncommand = \"/usr/bin/dvv\"\nargs = [\"mcp\", \"--stdio\"]\n\n[mcp_servers.deskvnc.env]\nA = \"1\"\n\n[mcp_servers.other]\ncommand = \"/x\"\n";
        assert_eq!(
            remove_toml_table(text).unwrap(),
            "[model]\nname = \"x\"\n\n[mcp_servers.other]\ncommand = \"/x\"\n"
        );
        let appended = "[model]\nname = \"x\"\n";
        let wired = format!("{appended}\n[mcp_servers.deskvnc]\ncommand = \"/usr/bin/dvv\"\nargs = [\"mcp\", \"--stdio\"]\n");
        assert_eq!(remove_toml_table(&wired).unwrap(), appended);
    }
}
