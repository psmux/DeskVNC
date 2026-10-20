//! Optional physical-display control uses authenticated SSH, not a virtual
//! Screen Sharing display. Host keys use the application's existing pin store.
use russh::ChannelMsg;
use ssh_transport::{HostKeyVerifier, SshAuth, SshConfig, SshHandle};
use std::sync::Arc;
use std::time::Duration;

pub type Verifier = Arc<dyn HostKeyVerifier + Send + Sync>;

pub async fn connect(
    host: &str,
    user: &str,
    password: &str,
    verifier: Verifier,
) -> Result<SshHandle, String> {
    let mut config = SshConfig::new(host, user);
    config.auth = SshAuth::Password(password.to_owned());
    tokio::time::timeout(
        Duration::from_secs(15),
        ssh_transport::connect_and_authenticate(&config, verifier),
    )
    .await
    .map_err(|_| "Mac display SSH connection timed out".to_owned())?
    .map_err(|e| format!("Mac display SSH connection: {e}"))
}

/// Bounded command output; never log account passwords or authentication data.
pub async fn execute(ssh: &SshHandle, command: &str) -> Result<String, String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut channel = ssh
            .channel_open_session()
            .await
            .map_err(|e| e.to_string())?;
        channel
            .exec(true, command.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut status = None;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
            if stdout.len() + stderr.len() > 1_048_576 {
                return Err("Mac display response exceeded the size limit".into());
            }
        }
        if status != Some(0) {
            return Err(format!(
                "Mac display command failed: {}",
                String::from_utf8_lossy(&stderr)
                    .chars()
                    .take(800)
                    .collect::<String>()
            ));
        }
        String::from_utf8(stdout).map_err(|_| "Mac display response was not UTF-8".into())
    })
    .await
    .map_err(|_| "Mac display command timed out".to_owned())?
}

fn display_command(arguments: &str) -> String {
    format!(
        "/usr/bin/swift - {arguments} <<'DESKVNC_DISPLAY_SWIFT'\n{}\nDESKVNC_DISPLAY_SWIFT",
        include_str!("mac_display.swift")
    )
}

pub struct DisplayController {
    ssh: Arc<SshHandle>,
    original: Option<i32>,
    last_applied: Option<i32>,
}

impl DisplayController {
    pub async fn connect(
        host: &str,
        user: &str,
        password: &str,
        verifier: Verifier,
    ) -> Result<Self, String> {
        Ok(Self {
            ssh: Arc::new(connect(host, user, password, verifier).await?),
            original: None,
            last_applied: None,
        })
    }

    pub async fn restore_on_disconnect(&mut self) {
        if self.original.is_some() && self.last_applied.is_some() {
            if let Err(error) = self.request(remote_core::MacDisplayAction::Restore).await {
                tracing::warn!(%error, "Mac display restoration on disconnect failed");
            }
        }
    }

    pub async fn request(
        &mut self,
        action: remote_core::MacDisplayAction,
    ) -> Result<remote_core::MacDisplayInfo, String> {
        use remote_core::MacDisplayAction;
        let arguments = match action {
            MacDisplayAction::List => "list".into(),
            MacDisplayAction::Set { width, height } => {
                if !(640..=8192).contains(&width) || !(480..=8192).contains(&height) {
                    return Err("Physical display dimensions are outside supported bounds".into());
                }
                format!("set {width} {height}")
            }
            MacDisplayAction::Restore => match (self.original, self.last_applied) {
                (Some(original), Some(applied)) => format!("restore {original} {applied}"),
                _ => return Err("This connection has not changed the physical display".into()),
            },
        };
        if let MacDisplayAction::Set { width, height } = action {
            // Save rollback state BEFORE mutating the Mac, including the mode
            // we expect to apply. A lost reply must not lose restoration state.
            let before = execute(&self.ssh, &display_command("list")).await?;
            let before: remote_core::MacDisplayInfo = serde_json::from_str(&before)
                .map_err(|_| "macOS returned an invalid mode list".to_owned())?;
            let ratio = f64::from(before.pixel_width) / f64::from(before.width.max(1));
            let chosen = before
                .modes
                .iter()
                .filter(|mode| {
                    mode.width == width
                        && mode.height == height
                        && mode.pixel_width <= 4096
                        && mode.pixel_height <= 4096
                })
                .min_by(|a, b| {
                    let distance = |mode: &remote_core::MacDisplayMode| {
                        (f64::from(mode.pixel_width) / f64::from(mode.width.max(1)) - ratio).abs()
                    };
                    distance(a).total_cmp(&distance(b))
                })
                .ok_or_else(|| {
                    "Requested resolution is not an available physical display mode".to_owned()
                })?;
            self.original.get_or_insert(before.current_mode_id);
            self.last_applied = Some(chosen.id);
        }
        let output = execute(&self.ssh, &display_command(&arguments)).await?;
        let mut info: remote_core::MacDisplayInfo = serde_json::from_str(&output)
            .map_err(|_| "macOS returned an invalid physical display response".to_owned())?;
        match action {
            MacDisplayAction::Set { width, height } => {
                if info.width != width || info.height != height {
                    return Err("macOS did not apply the requested physical display mode".into());
                }
                self.original.get_or_insert(info.original_mode_id);
                self.last_applied = Some(info.current_mode_id);
            }
            MacDisplayAction::Restore => {
                self.original = None;
                self.last_applied = None;
            }
            MacDisplayAction::List => {}
        }
        info.can_restore = self.original.is_some();
        Ok(info)
    }
}

impl Drop for DisplayController {
    fn drop(&mut self) {
        if let (Some(original), Some(applied)) = (self.original, self.last_applied) {
            // Best effort on ordinary disconnect/error; the helper refuses to
            // undo a display change made outside this connection.
            let ssh = self.ssh.clone();
            let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                return;
            };
            runtime.spawn(async move {
                if let Err(error) = execute(
                    &ssh,
                    &display_command(&format!("restore {original} {applied}")),
                )
                .await
                {
                    tracing::warn!(%error, "Could not restore Mac display after disconnect");
                }
            });
        }
    }
}
