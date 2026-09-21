//! Platform adapters contain installation and process paths only.
//! Account provisioning never depends on a particular operating system.
use crate::{Provider, process};
use anyhow::{Context, Result, bail, ensure};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Windows,
    Linux,
}
impl Platform {
    pub fn current() -> Result<Self> {
        match std::env::consts::OS {
            "macos" => Ok(Self::MacOS),
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            _ => bail!("This operating system has no provider installer"),
        }
    }
}
pub fn data_dir() -> Result<PathBuf> {
    let home = || {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("Cannot locate the user data directory")
    };
    Ok(match Platform::current()? {
        Platform::MacOS => home()?.join("Library/Application Support/com.altrosyn.boundary"),
        Platform::Windows => {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?)
                .join("Boundary")
        }
        Platform::Linux => std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .map_or_else(|| home().map(|path| path.join(".local/share")), Ok)?
            .join("boundary"),
    })
}
pub fn candidates(platform: Platform, provider: Provider) -> Vec<PathBuf> {
    let paths: &[&str] = match (platform, provider) {
        (Platform::MacOS, Provider::Tailscale) => &[
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
            "/opt/homebrew/bin/tailscale",
            "/usr/local/bin/tailscale",
        ],
        (Platform::MacOS, Provider::Cloudflare) => &[
            "/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli",
            "/usr/local/bin/warp-cli",
        ],
        (Platform::Linux, Provider::Tailscale) => {
            &["/usr/bin/tailscale", "/usr/local/bin/tailscale"]
        }
        (Platform::Linux, Provider::Cloudflare) => {
            &["/usr/bin/warp-cli", "/usr/local/bin/warp-cli"]
        }
        (Platform::Windows, _) => &[],
    };
    if platform == Platform::Windows {
        let base = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
        return vec![base.join(match provider {
            Provider::Tailscale => r"Tailscale\tailscale.exe",
            Provider::Cloudflare => r"Cloudflare\Cloudflare WARP\warp-cli.exe",
        })];
    }
    paths.iter().map(PathBuf::from).collect()
}
pub fn client_path(provider: Provider) -> Option<PathBuf> {
    candidates(Platform::current().ok()?, provider)
        .into_iter()
        .find(|path| path.is_file())
}
pub async fn open_provider(provider: Provider) -> Result<()> {
    if Platform::current()? == Platform::MacOS {
        let app = match provider {
            Provider::Tailscale => "Tailscale",
            Provider::Cloudflare => "Cloudflare WARP",
        };
        process::output(
            Path::new("/usr/bin/open"),
            &["-a", app],
            Duration::from_secs(10),
        )
        .await?;
    }
    Ok(())
}
pub async fn install(provider: Provider) -> Result<()> {
    match Platform::current()? {
        Platform::MacOS => install_mac(provider).await,
        Platform::Windows => install_windows(provider).await,
        Platform::Linux => install_linux(provider).await,
    }
}
pub async fn allow_private_inbound(provider: Provider, address: std::net::IpAddr) -> Result<()> {
    if Platform::current()? != Platform::Windows {
        return Ok(());
    }
    use std::hash::{Hash, Hasher};
    let executable = std::env::current_exe()?;
    let executable = executable.to_str().context("Invalid application path")?;
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    executable.hash(&mut hash);
    let rule = format!("Boundary-private-{:016x}", hash.finish());
    let range = match provider {
        Provider::Tailscale => "100.64.0.0/10",
        Provider::Cloudflare => "100.96.0.0/12",
    };
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$name = {}
$program = {}
$existing = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
if ($existing) {{
    $filter = $existing | Get-NetFirewallApplicationFilter
    if ($filter.Program -ne $program -or $existing.Group -ne 'Boundary private access') {{ throw 'Firewall rule ownership changed' }}
    $existing | Remove-NetFirewallRule
}}
New-NetFirewallRule -Name $name -DisplayName 'Boundary private support' -Group 'Boundary private access' -Direction Inbound -Action Allow -Protocol UDP -Program $program -LocalAddress {} -RemoteAddress {} -Profile Any | Out-Null
"#,
        powershell_literal(&rule),
        powershell_literal(executable),
        powershell_literal(&address.to_string()),
        powershell_literal(range)
    );
    let argument = format!(
        "-NoProfile -NonInteractive -EncodedCommand {}",
        encoded_powershell(&script)
    );
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList {} -Verb RunAs -Wait -PassThru
if ($p.ExitCode -ne 0) {{ throw 'Private firewall setup failed' }}
"#,
        powershell_literal(&argument)
    );
    process::output(
        Path::new("powershell.exe"),
        &[
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_powershell(&script),
        ],
        Duration::from_secs(180),
    )
    .await?;
    Ok(())
}
async fn install_windows(provider: Provider) -> Result<()> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(180))
        .build()?;
    let (url, publisher) = match provider {
        Provider::Tailscale => {
            let manifest: serde_json::Value = client
                .get("https://pkgs.tailscale.com/stable/?mode=json")
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let architecture = match std::env::consts::ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                _ => bail!("No Windows installer is available for this architecture"),
            };
            let name = manifest["MSIs"][architecture]
                .as_str()
                .context("Provider did not publish a Windows installer")?;
            ensure!(
                name.starts_with("tailscale-setup-")
                    && name.ends_with(".msi")
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)),
                "Invalid installer filename"
            );
            (
                format!("https://pkgs.tailscale.com/stable/{name}"),
                "Tailscale",
            )
        }
        Provider::Cloudflare => (
            "https://downloads.cloudflareclient.com/v1/download/windows/ga".into(),
            "Cloudflare",
        ),
    };
    let directory = tempfile::tempdir()?;
    let package = directory.path().join("provider.msi");
    download(&client, &url, &package).await?;
    // Authenticode checks precede elevation. The OS owns the UAC prompt.
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$package = {}
$signature = Get-AuthenticodeSignature -LiteralPath $package
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch {}) {{ throw 'Provider installer signature rejected' }}
$process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', ('"' + $package + '"')) -Verb RunAs -Wait -PassThru
if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {{ throw 'Provider installation did not finish' }}
"#,
        powershell_literal(package.to_str().context("Invalid package path")?),
        powershell_literal(&format!("CN={}([ ,.]|$)", publisher))
    );
    process::output(
        Path::new("powershell.exe"),
        &[
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_powershell(&script),
        ],
        Duration::from_secs(900),
    )
    .await?;
    Ok(())
}
fn encoded_powershell(script: &str) -> String {
    use base64::Engine;
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
async fn download(client: &reqwest::Client, url: &str, path: &Path) -> Result<()> {
    let mut response = client
        .get(url)
        .send()
        .await
        .context("Could not download the provider installer")?
        .error_for_status()?;
    ensure!(
        response.content_length().unwrap_or(0) <= 400 * 1024 * 1024,
        "Provider installer exceeds the download limit"
    );
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(path).await?;
    let mut size = 0usize;
    while let Some(chunk) = response.chunk().await? {
        size += chunk.len();
        ensure!(
            size <= 400 * 1024 * 1024,
            "Provider installer exceeds the download limit"
        );
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    Ok(())
}
async fn install_mac(provider: Provider) -> Result<()> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(180))
        .build()?;
    let (url, publisher) = match provider {
        Provider::Tailscale => {
            let manifest: serde_json::Value = client
                .get("https://pkgs.tailscale.com/stable/?mode=json")
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let name = manifest["MacZips"]["universal-package"]
                .as_str()
                .context("Provider did not publish a macOS installer")?;
            ensure!(
                name.starts_with("Tailscale-")
                    && name.ends_with("-macos.pkg")
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)),
                "Invalid installer filename"
            );
            (
                format!("https://pkgs.tailscale.com/stable/{name}"),
                "Tailscale",
            )
        }
        Provider::Cloudflare => (
            "https://downloads.cloudflareclient.com/v1/download/macos/ga".into(),
            "Cloudflare",
        ),
    };
    let directory = tempfile::tempdir()?;
    let package = directory.path().join("provider.pkg");
    let mut response = client
        .get(url)
        .send()
        .await
        .context("Could not download the provider installer")?
        .error_for_status()?;
    ensure!(
        response.content_length().unwrap_or(0) <= 400 * 1024 * 1024,
        "Provider installer exceeds the download limit"
    );
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(&package).await?;
    let mut size = 0usize;
    while let Some(chunk) = response.chunk().await? {
        size += chunk.len();
        ensure!(
            size <= 400 * 1024 * 1024,
            "Provider installer exceeds the download limit"
        );
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    drop(file);
    let name = package.to_str().context("Invalid package path")?;
    let signature = process::output(
        Path::new("/usr/sbin/pkgutil"),
        &["--check-signature", name],
        Duration::from_secs(30),
    )
    .await?;
    let signature = String::from_utf8_lossy(&signature);
    ensure!(
        signature
            .lines()
            .any(|line| line.contains("Developer ID Installer:") && line.contains(publisher)),
        "Installer publisher does not match the selected provider"
    );
    process::output(
        Path::new("/usr/sbin/spctl"),
        &["--assess", "--type", "install", name],
        Duration::from_secs(45),
    )
    .await
    .context("macOS did not approve the provider installer signature")?;
    // The native installer owns administrator authentication and any vendor agreement.
    // Boundary waits for it, then continues enrollment without manual CLI commands.
    process::output(
        Path::new("/usr/bin/open"),
        &["-W", name],
        Duration::from_secs(900),
    )
    .await?;
    Ok(())
}
async fn install_linux(provider: Provider) -> Result<()> {
    // These are fixed scripts, not downloaded executable scripts. Repositories use
    // the vendor signing key and the system package manager's signature verification.
    let script = linux_install_script(provider);
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(script.as_bytes())?;
    file.flush()?;
    process::output(
        Path::new("pkexec"),
        &[
            "/bin/sh",
            file.path().to_str().context("Invalid installer path")?,
        ],
        Duration::from_secs(900),
    )
    .await?;
    Ok(())
}
pub fn linux_install_script(provider: Provider) -> &'static str {
    match provider {
        Provider::Tailscale => {
            r#"set -eu
. /etc/os-release
case "$ID:$VERSION_CODENAME" in
 ubuntu:jammy|ubuntu:noble|ubuntu:resolute|debian:bookworm|debian:trixie) ;;
 *) echo 'This installer currently supports Ubuntu and Debian releases listed by Boundary'; exit 1 ;;
esac
apt-get update
apt-get install -y ca-certificates curl
install -d -m 0755 /usr/share/keyrings
curl --proto '=https' --tlsv1.2 -fsSL "https://pkgs.tailscale.com/stable/$ID/$VERSION_CODENAME.noarmor.gpg" -o /usr/share/keyrings/boundary-tailscale.gpg
printf 'deb [signed-by=/usr/share/keyrings/boundary-tailscale.gpg] https://pkgs.tailscale.com/stable/%s %s main\n' "$ID" "$VERSION_CODENAME" > /etc/apt/sources.list.d/boundary-tailscale.list
apt-get update
apt-get install -y tailscale
systemctl enable --now tailscaled
"#
        }
        Provider::Cloudflare => {
            r#"set -eu
. /etc/os-release
case "$ID:$VERSION_CODENAME" in
 ubuntu:jammy|ubuntu:noble|ubuntu:resolute|debian:bookworm|debian:trixie) ;;
 *) echo 'This installer currently supports Ubuntu and Debian releases listed by Boundary'; exit 1 ;;
esac
apt-get update
apt-get install -y ca-certificates curl gnupg
install -d -m 0755 /usr/share/keyrings
keyfile=$(mktemp)
trap 'rm -f "$keyfile"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL https://pkg.cloudflareclient.com/pubkey.gpg -o "$keyfile"
gpg --batch --yes --dearmor --output /usr/share/keyrings/boundary-cloudflare.gpg "$keyfile"
printf 'deb [signed-by=/usr/share/keyrings/boundary-cloudflare.gpg] https://pkg.cloudflareclient.com/ %s main\n' "$VERSION_CODENAME" > /etc/apt/sources.list.d/boundary-cloudflare.list
apt-get update
apt-get install -y cloudflare-warp
systemctl enable --now warp-svc
"#
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn providers_have_paths_on_every_target() {
        for os in [Platform::MacOS, Platform::Windows, Platform::Linux] {
            for provider in [Provider::Tailscale, Provider::Cloudflare] {
                assert!(!candidates(os, provider).is_empty());
            }
        }
    }
    #[test]
    fn linux_installers_do_not_disable_package_verification() {
        for provider in [Provider::Tailscale, Provider::Cloudflare] {
            let script = linux_install_script(provider);
            assert!(script.contains("signed-by="));
            assert!(!script.contains("trusted=yes"));
            assert!(!script.contains("curl |"));
        }
    }
}
