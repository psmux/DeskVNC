//! SSH tunnelling for the RFB connection (PRD/10 §5).
//!
//! One [`SshTunnel`] owns one SSH connection to the gateway machine and opens
//! a `direct-tcpip` channel per VNC connection attempt, the SSH server dials
//! `target_host:target_port` from *its* side, which is what lets a profile
//! reach a VNC server bound to the remote machine's loopback. No local
//! listening socket is ever opened: the channel itself is handed to the
//! session as its byte stream, so there is no forwarded port on 127.0.0.1 for
//! another local process to race us to.
//!
//! Host-key verification and authentication are the carrier's
//! ([`crate::connect::connect_and_authenticate`]): one TOFU pin store answers
//! for every feature, so trusting a machine once covers its tunnel, its Files
//! panel and its terminal alike.
//!
//! The auto-reconnect supervisor calls [`SshTunnel::open_stream`] again after
//! a drop. A dead SSH carrier is re-dialled then, verified against the pin
//! that was established on first contact; a key that has *changed* since
//! fails the redial with [`Error::HostKeyChanged`], the same hard stop it is
//! everywhere else.

use std::sync::Arc;

use russh::client::Msg;
use russh::ChannelStream;

use crate::config::{host_port, SshConfig};
use crate::connect::{connect_and_authenticate, BoxFuture, ClientHandler};
use crate::error::{Error, Result};
use crate::hostkey::HostKeyVerifier;

/// The stream a tunnelled VNC connection runs over.
pub type TunnelStream = ChannelStream<Msg>;

/// A live SSH connection ready to open `direct-tcpip` channels.
///
/// Cheap to share behind an `Arc`; `open_stream` takes `&self` and serialises
/// redials internally.
pub struct SshTunnel {
    cfg: SshConfig,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    /// `None` after the carrier died; re-dialled on the next `open_stream`.
    /// A tokio mutex because it is held across the redial await, which also
    /// makes concurrent openers queue instead of racing two SSH connects.
    ssh: tokio::sync::Mutex<Option<russh::client::Handle<ClientHandler>>>,
}

impl std::fmt::Debug for SshTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshTunnel")
            .field("gateway", &self.endpoint())
            .finish()
    }
}

impl SshTunnel {
    /// Dial the gateway, verify its host key (TOFU) and authenticate.
    ///
    /// Establishes the carrier *now* rather than lazily, so a wrong
    /// passphrase or an unknown host key surfaces before a session is
    /// spawned, where the shell can still prompt (`Error::HostKeyUnknown`)
    /// or hard-stop (`Error::HostKeyChanged`).
    pub async fn connect(cfg: SshConfig, verifier: impl HostKeyVerifier) -> Result<Self> {
        let verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static> = Arc::new(verifier);
        let ssh = connect_and_authenticate(&cfg, verifier.clone()).await?;
        tracing::info!(gateway = %cfg.endpoint(), auth = cfg.auth.label(), "ssh tunnel established");
        Ok(Self {
            cfg,
            verifier,
            ssh: tokio::sync::Mutex::new(Some(ssh)),
        })
    }

    /// `user@gateway:port`, for logs and the connecting state. Never contains
    /// secrets.
    pub fn endpoint(&self) -> String {
        self.cfg.endpoint()
    }

    /// The tunnelled VNC endpoint as a display string, resolved server-side.
    pub fn describe_target(&self, host: &str, port: u16) -> String {
        format!("{} via ssh {}", host_port(host, port), self.endpoint())
    }

    /// Open one `direct-tcpip` channel to `target_host:target_port`.
    ///
    /// `target_host` is resolved by the SSH *server*, so `localhost` means
    /// the gateway machine's loopback, which is the point of the feature.
    /// A dead carrier is re-dialled (and re-verified against the pin store)
    /// once before giving up.
    pub async fn open_stream(&self, target_host: &str, target_port: u16) -> Result<TunnelStream> {
        let mut guard = self.ssh.lock().await;

        if let Some(ssh) = guard.as_ref() {
            match open_channel(ssh, target_host, target_port, self.cfg.connect_timeout()).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    // The carrier is stale (network change, gateway reboot);
                    // drop it and fall through to a fresh dial. The error is
                    // only logged: what matters is whether the redial works.
                    tracing::info!(
                        gateway = %self.endpoint(),
                        "ssh channel open failed ({e}); re-dialling the tunnel"
                    );
                    *guard = None;
                }
            }
        }

        let ssh = connect_and_authenticate(&self.cfg, self.verifier.clone()).await?;
        tracing::info!(gateway = %self.cfg.endpoint(), "ssh tunnel re-established");
        let stream =
            open_channel(&ssh, target_host, target_port, self.cfg.connect_timeout()).await?;
        *guard = Some(ssh);
        Ok(stream)
    }

    /// Close the SSH connection. Channels already handed out die with it.
    pub async fn close(&self) {
        if let Some(ssh) = self.ssh.lock().await.take() {
            let _ = ssh
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
        }
    }
}

/// Open a `direct-tcpip` channel and turn it into a byte stream, bounded by
/// `timeout`, an unresponsive gateway must not hang the connect attempt.
///
/// Boxed for the region reason documented on [`BoxFuture`]: the channel-open
/// future borrows the handle across an await in a way that defeats the
/// higher-ranked `Send` check when left opaque.
fn open_channel<'a>(
    ssh: &'a russh::client::Handle<ClientHandler>,
    target_host: &'a str,
    target_port: u16,
    timeout: std::time::Duration,
) -> BoxFuture<'a, Result<TunnelStream>> {
    Box::pin(async move {
        let opening = ssh.channel_open_direct_tcpip(
            target_host,
            u32::from(target_port),
            // Originator, advisory metadata for the server's logs. We have
            // no real client socket to report.
            "127.0.0.1",
            0,
        );
        match tokio::time::timeout(timeout, opening).await {
            Err(_) => Err(Error::Timeout),
            Ok(Ok(channel)) => Ok(channel.into_stream()),
            Ok(Err(e)) => Err(Error::Connect {
                host: target_host.to_string(),
                port: target_port,
                reason: format!("the ssh server could not reach the VNC endpoint: {e}"),
            }),
        }
    })
}
