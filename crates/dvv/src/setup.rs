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
//! that already names deskvnc is left alone.

use std::path::{Path, PathBuf};

/// The skill every agent gets, compiled in so the binary is all a person
/// needs.
const SKILL: &str = include_str!("../../../skills/deskvnc/SKILL.md");

/// The agents this knows how to wire, in the order they are reported.
const AGENTS: &[&str] = &["opencode", "pi", "codex", "claude"];

/// Set up one agent, or every one that is installed.
pub fn run(target: Option<&str>) -> i32 {
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("this binary cannot find itself, so there is no path to register: {e}");
            return 1;
        }
    };
    let Some(home) = home() else {
        eprintln!("HOME is not set, so there is nowhere to write an agent's config");
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
    println!("DeskVNCViewer has to be running with its agent plane switched on (AI Agents panel).");
    i32::from(failed)
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
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
    [
        home.join(".local/bin"),
        home.join(".bun/bin"),
        home.join(".opencode/bin"),
        home.join(".npm-global/bin"),
        home.join(".claude/local"),
        home.join(".cargo/bin"),
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ]
    .into_iter()
    .map(|dir| dir.join(name))
    .find(|candidate| candidate.is_file())
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
                lines.push(format!(
                    "{} already has a deskvnc entry, left as it is",
                    file.display()
                ));
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
    lines.push(link_onto_path(home, exe)?);
    lines.push(
        "Pi has no MCP client, so it drives dvv through its shell with the skill. Use a model that can see images for desktops."
            .to_string(),
    );
    Ok(lines)
}

/// Make `dvv` runnable by name, which is how a shell driven agent calls it.
fn link_onto_path(home: &Path, exe: &Path) -> Result<String, String> {
    if let Some(found) = on_path("dvv") {
        if found.canonicalize().ok().as_deref() == Some(exe) {
            return Ok(format!("dvv is already on PATH at {}", found.display()));
        }
    }
    let bin = home.join(".local/bin");
    let link = bin.join("dvv");
    if link.exists() || link.symlink_metadata().is_ok() {
        let ours = std::fs::read_link(&link).ok().as_deref() == Some(exe);
        if !ours {
            return Ok(format!(
                "{} already exists and is not this dvv, so it was left alone. Point it at {} yourself if you want this one",
                link.display(),
                exe.display()
            ));
        }
    } else {
        std::fs::create_dir_all(&bin).map_err(|e| format!("{}: {e}", bin.display()))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(exe, &link).map_err(|e| format!("{}: {e}", link.display()))?;
        #[cfg(not(unix))]
        std::fs::copy(exe, &link).map_err(|e| format!("{}: {e}", link.display()))?;
    }
    let on = std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir == bin));
    Ok(if on {
        format!("dvv linked at {}", link.display())
    } else {
        format!(
            "dvv linked at {}, which is not on PATH: add it to your shell profile",
            link.display()
        )
    })
}

fn codex(home: &Path, exe: &Path) -> Result<Vec<String>, String> {
    let dir = home.join(".codex");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let file = dir.join("config.toml");
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    if text.contains("[mcp_servers.deskvnc]") {
        return Ok(vec![format!(
            "{} already has deskvnc, left as it is",
            file.display()
        )]);
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

fn claude(home: &Path, exe: &Path) -> Result<Vec<String>, String> {
    let claude = find_agent("claude").ok_or("Claude Code is not installed")?;
    let status = std::process::Command::new(claude)
        .args(["mcp", "add", "--scope", "user", "deskvnc", "--"])
        .arg(exe)
        .args(["mcp", "--stdio"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("could not run claude: {e}"))?;
    let mut lines = Vec::new();
    if status.status.success() {
        lines.push("registered deskvnc with claude mcp add".to_string());
    } else {
        let why = String::from_utf8_lossy(&status.stderr);
        if why.contains("already exists") {
            lines.push("deskvnc was already registered with Claude Code".to_string());
        } else {
            return Err(format!("claude mcp add failed: {}", why.trim()));
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
