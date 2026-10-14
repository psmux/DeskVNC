//! How this computer reaches a helper when it shares: the saved connection
//! mode, kept as `network.json` in the shared data folder so DeskVNC and
//! DeskVNC Support on one computer use the same one.

use anyhow::{Context, Result, ensure};
use boundary_session::HostOptions;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", deny_unknown_fields)]
pub enum Profile {
    #[default]
    Automatic,
    Private {
        address: IpAddr,
    },
    Relay {
        url: String,
    },
}
impl Profile {
    pub fn options(&self) -> HostOptions {
        match self {
            Self::Automatic => HostOptions::default(),
            Self::Private { address } => HostOptions {
                relay: false,
                relay_url: None,
                bind_ip: Some(*address),
            },
            Self::Relay { url } => HostOptions {
                relay: true,
                relay_url: Some(url.clone()),
                bind_ip: None,
            },
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Private { address } => ensure!(
                !address.is_unspecified() && !address.is_multicast() && !address.is_loopback(),
                "Choose an address on your private network interface"
            ),
            Self::Relay { url } => boundary_session::validate_relay_url(url)?,
            Self::Automatic => {}
        }
        Ok(())
    }
    /// What can be checked on this computer before saving: the private
    /// address must be one it has.
    pub fn check_local(&self) -> Result<()> {
        self.validate()?;
        if let Self::Private { address } = self {
            let _socket = std::net::UdpSocket::bind((*address, 0)).context(
                "This IP is not available on this device. Connect your private network and check its address",
            )?;
        }
        Ok(())
    }
    pub fn label(&self) -> String {
        match self {
            Self::Automatic => "Automatic connection with relay fallback".into(),
            Self::Private { address } => {
                format!("Private interface {address}. Public relay fallback is off")
            }
            Self::Relay { .. } => "Your compatible relay. No default public relay is added".into(),
        }
    }
}
fn config_path() -> Result<PathBuf> {
    Ok(crate::platform::data_dir()?.join("network.json"))
}
pub fn load() -> Result<Profile> {
    let path = config_path()?;
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Profile::default()),
        Err(error) => return Err(error.into()),
    };
    let profile: Profile = serde_json::from_slice(&bytes)
        .context("Saved network settings are invalid. Choose and save a connection mode again")?;
    profile.validate()?;
    Ok(profile)
}
pub fn save(profile: &Profile) -> Result<()> {
    use std::io::Write;
    profile.validate()?;
    let path = config_path()?;
    let parent = path.parent().context("Invalid settings path")?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec_pretty(profile)?)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|error| anyhow::anyhow!("Could not save network settings: {}", error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_settings_never_enable_relay() {
        let profile = Profile::Private {
            address: "100.100.1.2".parse().unwrap(),
        };
        let restored: Profile =
            serde_json::from_slice(&serde_json::to_vec(&profile).unwrap()).unwrap();
        assert!(!restored.options().relay);
        assert_eq!(
            restored.options().bind_ip,
            Some("100.100.1.2".parse().unwrap())
        );
        assert!(
            serde_json::from_str::<Profile>(r#"{"mode":"Private","address":"0.0.0.0"}"#)
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(serde_json::from_str::<Profile>(r#"{"mode":"unexpected"}"#).is_err());
    }
}
