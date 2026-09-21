#![forbid(unsafe_code)]

pub mod cloudflare;
pub mod platform;
mod process;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provider {
    Tailscale,
    Cloudflare,
}
/// Kept in memory only. Provider clients retain their own device credentials.
/// Never serialize or derive Debug for setup requests.
pub struct SetupRequest {
    pub provider: Provider,
    pub auth_key: Zeroizing<String>,
    pub account_id: String,
    pub team: String,
    pub emails: Vec<String>,
    pub configure_account: bool,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Progress {
    pub message: String,
    pub address: Option<IpAddr>,
    pub finished: bool,
    pub failed: bool,
}
pub struct Setup {
    pub progress: watch::Receiver<Progress>,
    cancel: CancellationToken,
}
impl Setup {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}
impl Drop for Setup {
    fn drop(&mut self) {
        self.cancel();
    }
}
pub fn start(request: SetupRequest) -> Setup {
    let (tx, progress) = watch::channel(Progress::default());
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    tokio::spawn(async move {
        // Only one provider setup may change local client state at a time.
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let result = tokio::select! {
            _ = token.cancelled() => Err(anyhow::anyhow!("Setup cancelled. Completed provider changes are retained for resume or cleanup")),
            result = async {
                let _guard = LOCK.try_lock().context("Another provider setup is already running")?;
                let _file_guard = setup_lock()?;
                let provider = request.provider;
                let address = run(request, &tx).await?;
                status(&tx, "Checking the local private network firewall rule");
                platform::allow_private_inbound(provider, address).await?;
                Ok(address)
            } => result,
        };
        match result {
            Ok(address) => {
                tx.send_replace(Progress { message: "Provider connected locally. Save this address, then verify with the other device".into(), address: Some(address), finished: true, failed: false });
            }
            Err(error) => {
                tx.send_replace(Progress {
                    message: error.to_string(),
                    address: None,
                    finished: true,
                    failed: true,
                });
            }
        }
    });
    Setup { progress, cancel }
}
pub fn start_cleanup(account: String, auth_key: Zeroizing<String>) -> Setup {
    let (tx, progress) = watch::channel(Progress::default());
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    tokio::spawn(async move {
        let result: Result<()> = tokio::select! {
            _ = token.cancelled() => Err(anyhow::anyhow!("Cleanup cancelled. Run removal again to finish")),
            result = async {
                let _guard = setup_lock()?;
                status(&tx, "Removing Boundary owned Cloudflare access resources");
                let api = cloudflare::Client::new(&account, &auth_key)?;
                cloudflare::cleanup(&api, &account).await
            } => result,
        };
        let failed = result.is_err();
        let message = match result {
            Ok(()) => "Removed Boundary's enrollment policy and device profile. Shared account settings and provider clients were retained".into(),
            Err(error) => error.to_string(),
        };
        tx.send_replace(Progress {
            message,
            finished: true,
            failed,
            address: None,
        });
    });
    Setup { progress, cancel }
}
fn setup_lock() -> Result<std::fs::File> {
    let directory = platform::data_dir()?;
    std::fs::create_dir_all(&directory)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(directory.join("provider-setup.lock"))?;
    file.try_lock()
        .context("Provider setup is already running in Boundary or DeskVNC")?;
    Ok(file)
}
fn status(tx: &watch::Sender<Progress>, message: &str) {
    tx.send_replace(Progress {
        message: message.into(),
        ..Default::default()
    });
}
async fn run(request: SetupRequest, progress: &watch::Sender<Progress>) -> Result<IpAddr> {
    ensure!(
        request.auth_key.len() <= 4096,
        "The provider credential is too long"
    );
    if request.provider == Provider::Tailscale {
        ensure!(
            request.auth_key.is_empty() || request.auth_key.starts_with("tskey-auth-"),
            "Use a Tailscale device auth key, or leave it empty for browser login"
        );
    }
    if request.provider == Provider::Cloudflare {
        validate_team(&request.team)?;
        if request.configure_account {
            status(progress, "Configuring your private Cloudflare account");
            let api = cloudflare::Client::new(&request.account_id, &request.auth_key)?;
            cloudflare::configure(&api, &request.account_id, &request.team, &request.emails)
                .await?;
        }
    }
    status(progress, "Checking the provider client");
    if platform::client_path(request.provider).is_none() {
        status(
            progress,
            "Installing the official provider client. Complete any operating system installer or permission prompt",
        );
        platform::install(request.provider).await?;
    }
    let path = platform::client_path(request.provider)
        .context("The installer has not completed. Finish its OS prompt, then resume setup")?;
    match request.provider {
        Provider::Tailscale => {
            if let Ok(bytes) =
                process::output(&path, &["status", "--json"], Duration::from_secs(10)).await
            {
                if let Ok(address) = tailscale_address(&bytes) {
                    ensure!(
                        request.auth_key.is_empty(),
                        "This device is already enrolled. Leave the key empty to use its account, or explicitly switch accounts in Tailscale first"
                    );
                    return Ok(address);
                }
                let state: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                ensure!(
                    request.auth_key.is_empty()
                        || state["Self"]["ID"].as_str().is_none_or(str::is_empty),
                    "An existing Tailscale account is disconnected. Reconnect it in the provider app or explicitly switch accounts there before setup"
                );
            }
            status(
                progress,
                "Signing in to Tailscale. Complete provider login and the OS network permission prompt",
            );
            // The auth key is supplied in a private temporary file, never in argv.
            let mut keyfile = None;
            let key_arg;
            let args: Vec<&str> = if request.auth_key.is_empty() {
                vec!["up", "--timeout=120s"]
            } else {
                ensure!(
                    request.auth_key.starts_with("tskey-auth-"),
                    "Use a Tailscale device auth key, or leave it empty for provider login. API tokens are not enrollment keys"
                );
                use std::io::Write;
                let mut file = tempfile::NamedTempFile::new()?;
                file.write_all(request.auth_key.as_bytes())?;
                file.flush()?;
                key_arg = format!("--auth-key=file:{}", file.path().display());
                keyfile = Some(file);
                vec!["up", &key_arg, "--timeout=120s"]
            };
            // CLI owns the browser login flow. Its output may contain an authentication URL.
            // The macOS app is opened as well so its native onboarding is available.
            platform::open_provider(Provider::Tailscale).await?;
            let result = process::login(&path, &args, Duration::from_secs(150)).await;
            drop(keyfile);
            result.context(
                "Tailscale enrollment did not finish. Complete provider login and resume setup",
            )?;
            let bytes =
                process::output(&path, &["status", "--json"], Duration::from_secs(10)).await?;
            tailscale_address(&bytes)
        }
        Provider::Cloudflare => {
            // Refuse to replace an existing registration to a different organization.
            if let Ok(registration) =
                process::output(&path, &["registration", "show"], Duration::from_secs(10)).await
            {
                ensure!(
                    registration_matches(&registration, &request.team),
                    "Cloudflare is already registered to another organization, or its organization could not be verified. Switch it explicitly in the provider app before continuing"
                );
            } else {
                status(
                    progress,
                    "Enrolling this device in your Cloudflare organization. Complete provider sign in",
                );
                platform::open_provider(Provider::Cloudflare).await?;
                process::output(&path, &["registration", "new", &request.team], Duration::from_secs(150)).await
                    .context("Cloudflare enrollment did not finish. Complete provider login and resume setup")?;
            }
            let mut confirmed = false;
            for _ in 0..60 {
                if let Ok(value) =
                    process::output(&path, &["registration", "show"], Duration::from_secs(10)).await
                    && registration_matches(&value, &request.team)
                {
                    confirmed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            ensure!(
                confirmed,
                "Cloudflare enrollment is still pending. Complete sign in and resume setup"
            );
            status(progress, "Connecting the private Cloudflare network");
            process::output(&path, &["connect"], Duration::from_secs(20)).await?;
            for _ in 0..30 {
                let output = process::output(&path, &["status"], Duration::from_secs(10)).await?;
                if String::from_utf8_lossy(&output).lines().any(|line| {
                    line.trim() == "Status update: Connected" || line.trim() == "Connected"
                }) {
                    let mut addresses: Vec<_> = if_addrs::get_if_addrs()?
                        .into_iter()
                        .map(|interface| interface.ip())
                        .filter(is_cloudflare_ip)
                        .collect();
                    addresses.sort();
                    addresses.dedup();
                    if addresses.len() == 1 {
                        return Ok(addresses[0]);
                    }
                    ensure!(
                        addresses.len() <= 1,
                        "Multiple Mesh interfaces were found. Disconnect the conflicting network before continuing"
                    );
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            bail!(
                "Cloudflare has not provided a connected Mesh interface. Check enrollment approval and resume setup"
            )
        }
    }
}
pub fn validate_team(team: &str) -> Result<()> {
    ensure!(
        !team.is_empty()
            && team.len() <= 63
            && team.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !team.starts_with('-')
            && !team.ends_with('-'),
        "Enter the Cloudflare team name, without a URL"
    );
    Ok(())
}
fn registration_matches(bytes: &[u8], team: &str) -> bool {
    // Verify the organization field, never an unrelated token in command output.
    String::from_utf8_lossy(bytes).lines().any(|line| {
        let Some((field, value)) = line.split_once(':') else {
            return false;
        };
        matches!(
            field.trim().to_ascii_lowercase().as_str(),
            "organization" | "organization name" | "team name"
        ) && (value.trim() == team || value.trim() == format!("{team}.cloudflareaccess.com"))
    })
}
fn is_cloudflare_ip(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(ip) if ip.octets()[0] == 100 && (96..=111).contains(&ip.octets()[1]))
}
pub fn tailscale_address(bytes: &[u8]) -> Result<IpAddr> {
    ensure!(
        bytes.len() <= 2 * 1024 * 1024,
        "Tailscale status exceeded the output limit"
    );
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("Could not read Tailscale status")?;
    ensure!(
        value["BackendState"] == "Running" && value["Self"]["Online"] != false,
        "Tailscale has not confirmed a connected device"
    );
    value["TailscaleIPs"].as_array().context("Tailscale has no local addresses")?.iter()
        .filter_map(|ip| ip.as_str()?.parse::<IpAddr>().ok())
        .find(|ip| matches!(ip, IpAddr::V4(ip) if ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1])))
        .context("Tailscale has no connected IPv4 address")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrollment_identity_is_exact() {
        assert!(!registration_matches(b"Organization: other-team", "team"));
        assert!(registration_matches(
            b"Organization: team.cloudflareaccess.com",
            "team"
        ));
        assert!(validate_team("team;command").is_err());
    }
    #[test]
    fn stale_address_is_not_success() {
        assert!(tailscale_address(br#"{"BackendState":"Running","Self":{"Online":false},"TailscaleIPs":["100.64.1.2"]}"#).is_err());
    }
}
