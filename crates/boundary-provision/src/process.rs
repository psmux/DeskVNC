use anyhow::{Context, Result, ensure};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt};

pub async fn output(path: &Path, args: &[&str], timeout: Duration) -> Result<Vec<u8>> {
    run(path, args, timeout, false).await
}
pub async fn login(path: &Path, args: &[&str], timeout: Duration) -> Result<Vec<u8>> {
    run(path, args, timeout, true).await
}
async fn read(mut reader: impl AsyncRead + Unpin, open_login: bool) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let mut opened = false;
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            return Ok(bytes);
        }
        ensure!(
            bytes.len() + count <= 2 * 1024 * 1024,
            "Provider output exceeded its limit"
        );
        bytes.extend_from_slice(&chunk[..count]);
        if open_login && !opened {
            // Only open complete, newline terminated CLI output tokens.
            let output = String::from_utf8_lossy(&bytes);
            for line in output
                .split_inclusive('\n')
                .filter(|line| line.ends_with('\n'))
            {
                for word in line.split_whitespace() {
                    if valid_login_url(word) {
                        open::that_detached(word)
                            .context("Could not open provider login in your browser")?;
                        opened = true;
                        break;
                    }
                }
                if opened {
                    break;
                }
            }
        }
    }
}
fn valid_login_url(text: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(text) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("login.tailscale.com")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.path().starts_with("/a/")
}
async fn run(path: &Path, args: &[&str], timeout: Duration, open_login: bool) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, async {
        let mut child = tokio::process::Command::new(path)
            .args(args)
            .env("TAILSCALE_BE_CLI", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Could not start the provider command")?;
        let stdout = child.stdout.take().context("Missing provider output")?;
        let stderr = child.stderr.take().context("Missing provider output")?;
        let (bytes, _) = tokio::try_join!(read(stdout, open_login), read(stderr, open_login))?;
        ensure!(
            child.wait().await?.success(),
            "Provider command failed. Check its login or OS permission prompt and resume setup"
        );
        Ok(bytes)
    })
    .await
    .context("Provider command timed out. Setup can be resumed")?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_can_only_open_provider_login() {
        assert!(valid_login_url("https://login.tailscale.com/a/example"));
        for value in [
            "http://login.tailscale.com/a/x",
            "https://login.tailscale.com.evil/a/x",
            "file:///etc/passwd",
            "https://other.com/a/x",
        ] {
            assert!(!valid_login_url(value));
        }
    }
}
