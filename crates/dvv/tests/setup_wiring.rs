//! `dvv setup` writes where each agent reads, leaves a current skill alone,
//! and `dvv setup --remove` takes out what it wrote (issues #72 and #73).
//!
//! Each case runs the real binary with its own home, so nothing here reads
//! or writes the config of whoever runs the tests. Unix only: the fake
//! `claude` is a shell script, and the unchanged skill is proved with a file
//! that cannot be written.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!("dvv-setup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        // A `claude` that answers the three commands setup sends it.
        let claude = root.join("bin/claude");
        std::fs::write(
            &claude,
            "#!/bin/sh\ncase \"$2\" in\n  get) echo \"deskvnc:\"; echo \"  Command: /usr/bin/dvv\";;\nesac\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        Sandbox { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn dvv(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dvv"));
        command
            .args(args)
            .env_clear()
            .env("HOME", self.home())
            .env("SHELL", "/bin/sh")
            .env("PATH", format!("{}:/usr/bin:/bin", self.root.join("bin").display()))
            .env("XDG_CONFIG_HOME", self.home().join(".config"));
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().expect("dvv runs")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn codex_config_and_skill_go_to_codex_home() {
    let sandbox = Sandbox::new("codex-home");
    let codex_home = sandbox.root.join("codex-home");
    let out = sandbox.dvv(&["setup", "codex"], &[("CODEX_HOME", &codex_home)]);
    assert!(out.status.success(), "{}", text(&out));
    let config = std::fs::read_to_string(codex_home.join("config.toml"))
        .unwrap_or_else(|_| panic!("no config.toml in CODEX_HOME: {}", text(&out)));
    assert!(config.contains("[mcp_servers.deskvnc]"), "{config}");
    assert!(codex_home.join("skills/deskvnc/SKILL.md").is_file());
    assert!(
        !sandbox.home().join(".codex").exists(),
        "with CODEX_HOME set, ~/.codex is not where Codex reads"
    );
}

#[test]
fn the_claude_skill_goes_to_claude_config_dir() {
    let sandbox = Sandbox::new("claude-config");
    let claude_dir = sandbox.root.join("claude-config");
    let out = sandbox.dvv(&["setup", "claude"], &[("CLAUDE_CONFIG_DIR", &claude_dir)]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        claude_dir.join("skills/deskvnc/SKILL.md").is_file(),
        "the skill is not where Claude Code reads it: {}",
        text(&out)
    );
    assert!(!sandbox.home().join(".claude/skills").exists());
}

#[test]
fn a_skill_that_is_current_is_not_written_again() {
    let sandbox = Sandbox::new("skill-current");
    let first = sandbox.dvv(&["setup", "opencode"], &[]);
    assert!(first.status.success(), "{}", text(&first));
    let skill = sandbox
        .home()
        .join(".config/opencode/skills/deskvnc/SKILL.md");
    assert!(skill.is_file());
    // A second run must not write it. A file nobody may write proves that
    // better than a modification time, which some filesystems round.
    std::fs::set_permissions(&skill, std::fs::Permissions::from_mode(0o444)).unwrap();
    let second = sandbox.dvv(&["setup", "opencode"], &[]);
    std::fs::set_permissions(&skill, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        second.status.success(),
        "setup wrote a skill that had not changed: {}",
        text(&second)
    );
    assert!(text(&second).contains("is current"), "{}", text(&second));
}

#[test]
fn remove_takes_out_what_setup_wrote_and_nothing_else() {
    let sandbox = Sandbox::new("remove");
    let codex_home = sandbox.root.join("codex-home");
    let claude_dir = sandbox.root.join("claude-config");
    let env: [(&str, &Path); 2] = [("CODEX_HOME", &codex_home), ("CLAUDE_CONFIG_DIR", &claude_dir)];

    let config_dir = sandbox.home().join(".config/opencode");
    std::fs::create_dir_all(&config_dir).unwrap();
    let mine = "{\n  // keep me\n  \"model\": \"x\",\n  \"mcp\": {\n    \"other\": { \"type\": \"local\", \"command\": [\"/x/other\"] }\n  }\n}\n";
    std::fs::write(config_dir.join("opencode.json"), mine).unwrap();
    std::fs::create_dir_all(&codex_home).unwrap();
    std::fs::write(codex_home.join("config.toml"), "[model]\nname = \"x\"\n").unwrap();

    for agent in ["opencode", "codex", "claude"] {
        let out = sandbox.dvv(&["setup", agent], &env);
        assert!(out.status.success(), "{agent}: {}", text(&out));
    }
    let wired = std::fs::read_to_string(config_dir.join("opencode.json")).unwrap();
    assert!(wired.contains("\"deskvnc\""));

    // The agent first and the flag after: a dvv without --remove reads it as
    // `dvv setup opencode`, and this test then fails rather than wiring
    // every agent it can find.
    for agent in ["opencode", "codex", "claude"] {
        let out = sandbox.dvv(&["setup", agent, "--remove"], &env);
        assert!(out.status.success(), "{agent}: {}", text(&out));
    }
    let opencode = std::fs::read_to_string(config_dir.join("opencode.json")).unwrap();
    assert_eq!(opencode, mine, "the OpenCode config is back to what it was");
    let codex = std::fs::read_to_string(codex_home.join("config.toml")).unwrap();
    assert_eq!(codex, "[model]\nname = \"x\"\n");
    assert!(!config_dir.join("skills/deskvnc").exists());
    assert!(!codex_home.join("skills/deskvnc").exists());
    assert!(!claude_dir.join("skills/deskvnc").exists());
}
