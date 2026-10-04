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
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(exe) => plain(exe),
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
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ];
    // Where npm and scoop put commands on Windows.
    if let Some(appdata) = std::env::var_os("APPDATA") {
        dirs.push(PathBuf::from(appdata).join("npm"));
    }
    dirs.push(home.join("scoop/shims"));
    dirs.into_iter().find_map(|dir| find_in(&dir, name))
}

fn write_skill(dir: &Path) -> Result<String, String> {
    let dir = dir.join("deskvnc");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let file = dir.join("SKILL.md");
    std::fs::write(&file, SKILL).map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(format!("skill written to {}", file.display()))
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
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
        .join("opencode");
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
fn names_a_dvv(path: &str) -> bool {
    Path::new(path)
        .file_stem()
        .is_some_and(|stem| stem.eq_ignore_ascii_case("dvv"))
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
    let dir = home.join(".codex");
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
        return Ok(vec![line, write_skill(&home.join(".codex/skills"))?]);
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
        write_skill(&home.join(".codex/skills"))?,
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
    lines.push(write_skill(&home.join(".claude/skills"))?);
    Ok(lines)
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
}
