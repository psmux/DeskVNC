//! One live SSH + SFTP sidecar connection.
//!
//! The SFTP channel runs *alongside* the VNC session on its own SSH
//! connection (PRD/08 §2.1), so a VNC reconnect does not disturb an in-flight
//! transfer and vice versa.
//!
//! Host-key verification happens in [`ClientHandler::check_server_key`] and is
//! strictly trust-on-first-use: an unknown key aborts the connect with
//! [`Error::HostKeyUnknown`] so the shell can prompt, and a *changed* key
//! aborts with [`Error::HostKeyChanged`], which is a hard stop with no
//! "continue anyway" path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{HashAlg, PublicKey};
use russh_sftp::client::SftpSession as RawSftp;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::{host_port, resolver_host, FileTransferConfig, SshAuth};
use crate::error::{Error, Result};
use crate::hostkey::{HostKeyDecision, HostKeyVerifier};
use crate::path;
use crate::transfer::{
    ConflictOutcome, ConflictPolicy, Direction, FileJob, ProgressThrottle, TransferEvent,
    TransferPlan, PROGRESS_EVENTS_PER_SEC,
};

/// Bytes moved per read/write turn. Big enough to keep the SFTP pipeline fed,
/// small enough that a cancel lands within a few milliseconds.
const CHUNK: usize = 128 * 1024;

/// A `Send` future with a concrete region.
///
/// Several russh/russh-sftp futures hold a shared reference across an await
/// over a type whose `Send`ness is not provable *higher-ranked*
/// (`&Channel<Msg>`, `&mpsc::Sender<Msg>`). Left as opaque `async fn` return
/// types those propagate outwards and make `SftpSession::connect`'s future
/// non-`Send`, which a `#[tauri::command]` rejects. Boxing at the boundary
/// pins the region and the bound becomes provable. Do not "simplify" these
/// back into plain `async fn`s.
type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// One remote directory entry, as shown in the right-hand pane.
///
/// **Every string here is server-supplied and untrusted**, render as text,
/// and put any path through [`crate::path`] before using it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// Unix mtime, seconds.
    pub modified: Option<i64>,
    /// Permission bits (`0o7777` masked; the file-type bits are stripped).
    pub mode: u32,
    pub is_symlink: bool,
}

// ---------------------------------------------------------------------------
// SSH handler
// ---------------------------------------------------------------------------

struct ClientHandler {
    host: String,
    port: u16,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    decision: Arc<Mutex<Option<HostKeyDecision>>>,
}

// russh 0.62 declares `Handler` with return-position `impl Future` rather than
// `#[async_trait]`, so a plain `async fn` in the impl is what matches now.
impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let fingerprint = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        let key_type = server_public_key.algorithm().as_str().to_string();
        let decision = self
            .verifier
            .verify(&self.host, self.port, &key_type, &fingerprint);
        let accept = matches!(decision, HostKeyDecision::Trusted);
        if !accept {
            tracing::warn!(
                host = %self.host, port = self.port, %key_type,
                "ssh host key not accepted: {decision:?}"
            );
        }
        *self.decision.lock() = Some(decision);
        Ok(accept)
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A connected SSH + SFTP sidecar. Cheap to clone-share behind an `Arc`; all
/// methods take `&self` so several transfers can use one connection.
pub struct SftpSession {
    sftp: RawSftp,
    /// Keeping the SSH handle alive keeps the transport open, dropping it
    /// tears the connection down under the SFTP channel.
    ssh: russh::client::Handle<ClientHandler>,
    host: String,
    port: u16,
    username: String,
    conflict: ConflictPolicy,
}

impl std::fmt::Debug for SftpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpSession")
            .field(
                "endpoint",
                &format!("{}@{}", self.username, host_port(&self.host, self.port)),
            )
            .finish()
    }
}

impl SftpSession {
    /// Connect, verify the host key (TOFU) and authenticate, then open the
    /// `sftp` subsystem.
    pub async fn connect(
        cfg: FileTransferConfig,
        host_key_check: impl HostKeyVerifier,
    ) -> Result<Self> {
        // Boxed on purpose, see `open_sftp_subsystem` for why the handshake
        // future has to have a concrete region rather than an opaque one.
        let future: BoxFuture<'static, Result<Self>> =
            Box::pin(Self::connect_inner(cfg, Arc::new(host_key_check)));
        future.await
    }

    async fn connect_inner(
        cfg: FileTransferConfig,
        verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    ) -> Result<Self> {
        let decision = Arc::new(Mutex::new(None));
        let handler = ClientHandler {
            host: cfg.host.clone(),
            port: cfg.port,
            verifier,
            decision: decision.clone(),
        };

        let ssh_config = Arc::new(russh::client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(30)),
            ..Default::default()
        });

        let connecting =
            russh::client::connect(ssh_config, (resolver_host(&cfg.host), cfg.port), handler);
        let mut ssh = match tokio::time::timeout(cfg.connect_timeout(), connecting).await {
            Err(_) => return Err(Error::Timeout),
            Ok(Ok(handle)) => handle,
            Ok(Err(e)) => {
                // A failed connect is usually a network problem, but if the
                // handler rejected the key we have a much better answer.
                return Err(match decision.lock().take() {
                    Some(HostKeyDecision::Unknown {
                        key_type,
                        fingerprint,
                    }) => Error::HostKeyUnknown {
                        host: cfg.host.clone(),
                        port: cfg.port,
                        key_type,
                        fingerprint,
                    },
                    Some(HostKeyDecision::Changed {
                        expected, actual, ..
                    }) => Error::HostKeyChanged {
                        host: cfg.host.clone(),
                        port: cfg.port,
                        expected,
                        actual,
                    },
                    _ => Error::Connect {
                        host: cfg.host.clone(),
                        port: cfg.port,
                        reason: e.to_string(),
                    },
                });
            }
        };

        authenticate(&mut ssh, &cfg).await?;

        let sftp = open_sftp_subsystem(&mut ssh).await?;

        tracing::info!(endpoint = %cfg.endpoint(), auth = cfg.auth.label(), "sftp sidecar connected");
        Ok(Self {
            sftp,
            ssh,
            host: cfg.host,
            port: cfg.port,
            username: cfg.username,
            conflict: cfg.conflict,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn conflict_policy(&self) -> ConflictPolicy {
        self.conflict
    }

    /// The remote user's home directory (SFTP resolves `.` relative to it).
    pub async fn home_dir(&self) -> Result<String> {
        let home = self.sftp.canonicalize(".").await.map_err(Error::sftp)?;
        path::normalize_remote(&home)
    }

    /// Resolve a possibly `~`-prefixed, possibly relative remote path.
    pub async fn resolve(&self, path_str: &str) -> Result<String> {
        let expanded = if path_str == "~" {
            return self.home_dir().await;
        } else if let Some(rest) = path_str.strip_prefix("~/") {
            let home = self.home_dir().await?;
            path::normalize_remote(&format!("{home}/{rest}"))?
        } else {
            path::normalize_remote(path_str)?
        };
        if expanded.starts_with('/') {
            return Ok(expanded);
        }
        let resolved = self
            .sftp
            .canonicalize(expanded)
            .await
            .map_err(Error::sftp)?;
        path::normalize_remote(&resolved)
    }

    /// List a remote directory. Entries whose names fail
    /// [`crate::path::component`] are dropped rather than surfaced, a server
    /// that sends `..` or `a/b` as a file name is not one whose listing we
    /// want to hand to the UI.
    pub async fn list_dir(&self, dir: &str) -> Result<Vec<RemoteEntry>> {
        let dir = self.resolve(dir).await?;
        let read = self.sftp.read_dir(dir.clone()).await.map_err(Error::sftp)?;

        let mut entries = Vec::new();
        for entry in read {
            let name = entry.file_name();
            if path::component(&name).is_err() {
                tracing::warn!(%dir, "dropping unsafe entry name from remote listing");
                continue;
            }
            let Ok(full) = path::join_remote(&dir, &name) else {
                continue;
            };
            let meta = entry.metadata();
            let file_type = meta.file_type();
            let is_symlink = file_type.is_symlink();

            // For a symlink, the listing carries the *link's* attributes;
            // resolve the target so directories are navigable.
            let (is_dir, size) = if is_symlink {
                match self.sftp.metadata(full.clone()).await {
                    Ok(target) => (target.file_type().is_dir(), target.len()),
                    Err(_) => (false, meta.len()), // dangling link
                }
            } else {
                (file_type.is_dir(), meta.len())
            };

            entries.push(RemoteEntry {
                name,
                path: full,
                is_dir,
                size,
                modified: meta.mtime.map(i64::from),
                mode: meta.permissions.unwrap_or(0) & 0o7777,
                is_symlink,
            });
        }
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(entries)
    }

    pub async fn stat(&self, remote: &str) -> Result<RemoteEntry> {
        let full = self.resolve(remote).await?;
        let meta = self
            .sftp
            .metadata(full.clone())
            .await
            .map_err(Error::sftp)?;
        let link = self.sftp.symlink_metadata(full.clone()).await.ok();
        let name = path::remote_file_name(&full).unwrap_or_else(|_| full.clone());
        Ok(RemoteEntry {
            name,
            path: full,
            is_dir: meta.file_type().is_dir(),
            size: meta.len(),
            modified: meta.mtime.map(i64::from),
            mode: meta.permissions.unwrap_or(0) & 0o7777,
            is_symlink: link.map(|m| m.file_type().is_symlink()).unwrap_or(false),
        })
    }

    pub async fn mkdir(&self, remote: &str) -> Result<()> {
        let full = self.resolve(remote).await?;
        self.sftp.create_dir(full).await.map_err(Error::sftp)
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from = self.resolve(from).await?;
        let to = self.resolve(to).await?;
        self.sftp.rename(from, to).await.map_err(Error::sftp)
    }

    /// Delete a file, or a directory (empty unless `recursive`).
    pub async fn remove(&self, remote: &str, recursive: bool) -> Result<()> {
        let full = self.resolve(remote).await?;
        let meta = self
            .sftp
            .metadata(full.clone())
            .await
            .map_err(Error::sftp)?;
        if !meta.file_type().is_dir() {
            return self.sftp.remove_file(full).await.map_err(Error::sftp);
        }
        if !recursive {
            return self.sftp.remove_dir(full).await.map_err(Error::sftp);
        }

        // Post-order delete driven by an explicit stack, no async recursion,
        // no unbounded call depth from a hostile directory tree.
        let (dirs, files) = self.walk_remote(&full).await?;
        for file in files {
            self.sftp
                .remove_file(file.remote)
                .await
                .map_err(Error::sftp)?;
        }
        for dir in dirs.into_iter().rev() {
            self.sftp.remove_dir(dir).await.map_err(Error::sftp)?;
        }
        self.sftp.remove_dir(full).await.map_err(Error::sftp)
    }

    /// Close the SFTP channel and the SSH connection.
    pub async fn close(self) -> Result<()> {
        let _ = self.sftp.close().await;
        let _ = self
            .ssh
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(())
    }

    // ------------------------------------------------------------- upload

    /// Upload a local file or directory tree into `remote_dir`.
    pub async fn upload(
        &self,
        local: &Path,
        remote_dir: &str,
        id: String,
        tx: mpsc::Sender<TransferEvent>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut reporter = Reporter::new(id, tx, Direction::Upload);
        match self
            .upload_inner(local, remote_dir, &mut reporter, &cancel)
            .await
        {
            Ok(()) => reporter.completed().await,
            Err(Error::Cancelled) => reporter.cancelled().await,
            Err(e) if cancel.is_cancelled() => {
                tracing::debug!("upload ended during cancellation: {e}");
                reporter.cancelled().await;
            }
            Err(e) => {
                reporter.failed(&e).await;
                return Err(e);
            }
        }
        Ok(())
    }

    async fn upload_inner(
        &self,
        local: &Path,
        remote_dir: &str,
        reporter: &mut Reporter,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let remote_dir = self.resolve(remote_dir).await?;
        let name = local
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::UnsafePath(format!("unusable local name: {}", local.display())))?
            .to_string();
        path::component(&name)?;

        let plan = plan_upload(local, &remote_dir, &name).await?;
        reporter.start(name, plan.total_bytes).await;

        for dir in &plan.dirs {
            check_cancel(cancel)?;
            // A directory that already exists is fine; anything else is not,
            // but we let the file writes surface the real error.
            if self.sftp.create_dir(dir.clone()).await.is_err() {
                tracing::debug!(dir, "remote mkdir failed (may already exist)");
            }
        }
        for job in &plan.files {
            check_cancel(cancel)?;
            self.upload_one(job, reporter, cancel).await?;
        }
        Ok(())
    }

    async fn upload_one(
        &self,
        job: &FileJob,
        reporter: &mut Reporter,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let existing = self
            .sftp
            .metadata(job.remote.clone())
            .await
            .ok()
            .filter(|m| !m.file_type().is_dir())
            .map(|m| m.len());

        let dir = path::remote_parent(&job.remote)?;
        let name = path::remote_file_name(&job.remote)?;
        let siblings = if matches!(self.conflict, ConflictPolicy::Rename) && existing.is_some() {
            self.sibling_names(&dir).await
        } else {
            Vec::new()
        };

        let outcome =
            crate::transfer::plan_transfer(self.conflict, &name, existing, job.size, |candidate| {
                siblings.iter().any(|s| s == candidate)
            });

        let (target, offset) = match outcome {
            ConflictOutcome::Skip => {
                reporter.advance(job.size).await;
                return Ok(());
            }
            ConflictOutcome::Fresh => (job.remote.clone(), 0),
            ConflictOutcome::Resume { offset } => {
                reporter.advance(offset).await;
                (job.remote.clone(), offset)
            }
            ConflictOutcome::RenameTo(new_name) => (path::join_remote(&dir, &new_name)?, 0),
        };

        let mut source = tokio::fs::File::open(&job.local).await?;
        if offset > 0 {
            source.seek(std::io::SeekFrom::Start(offset)).await?;
        }

        let flags = if offset > 0 {
            OpenFlags::CREATE | OpenFlags::WRITE
        } else {
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE
        };
        let mut sink = self
            .sftp
            .open_with_flags(target.clone(), flags)
            .await
            .map_err(Error::sftp)?;
        if offset > 0 {
            sink.seek(std::io::SeekFrom::Start(offset)).await?;
        }

        let mut buf = vec![0u8; CHUNK];
        loop {
            check_cancel(cancel)?;
            let read = source.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            sink.write_all(&buf[..read]).await?;
            reporter.advance(read as u64).await;
        }
        sink.flush().await?;
        sink.shutdown().await?;

        // Preserve the executable bit and the modification time where the
        // remote filesystem allows it; failure here is cosmetic, never fatal.
        let secs = job
            .mtime
            .map(|mtime| u32::try_from(mtime.max(0)).unwrap_or(u32::MAX));
        let attrs = FileAttributes {
            permissions: Some(job.mode & 0o7777),
            mtime: secs,
            atime: secs,
            ..Default::default()
        };
        if let Err(e) = self.sftp.set_metadata(target, attrs).await {
            tracing::debug!("could not preserve remote metadata: {e}");
        }
        Ok(())
    }

    // ----------------------------------------------------------- download

    /// Download remote files/directories into `local_dir`.
    ///
    /// Every destination path is built with
    /// [`crate::path::local_destination`], so nothing a server puts in a
    /// listing can place a byte outside `local_dir`.
    pub async fn download(
        &self,
        remote: &str,
        local_dir: &Path,
        id: String,
        tx: mpsc::Sender<TransferEvent>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut reporter = Reporter::new(id, tx, Direction::Download);
        match self
            .download_inner(remote, local_dir, &mut reporter, &cancel)
            .await
        {
            Ok(()) => reporter.completed().await,
            Err(Error::Cancelled) => reporter.cancelled().await,
            Err(e) if cancel.is_cancelled() => {
                tracing::debug!("download ended during cancellation: {e}");
                reporter.cancelled().await;
            }
            Err(e) => {
                reporter.failed(&e).await;
                return Err(e);
            }
        }
        Ok(())
    }

    async fn download_inner(
        &self,
        remote: &str,
        local_dir: &Path,
        reporter: &mut Reporter,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let remote = self.resolve(remote).await?;
        let name = path::remote_file_name(&remote)?;
        let meta = self
            .sftp
            .metadata(remote.clone())
            .await
            .map_err(Error::sftp)?;

        if !meta.file_type().is_dir() {
            let job = FileJob {
                local: path::safe_local_join(local_dir, &name)?,
                remote: remote.clone(),
                size: meta.len(),
                mode: meta.permissions.unwrap_or(0o644) & 0o7777,
                mtime: meta.mtime.map(i64::from),
            };
            reporter.start(name, job.size).await;
            return self.download_one(&job, reporter, cancel).await;
        }

        let (dirs, files) = self.walk_remote(&remote).await?;
        let total: u64 = files.iter().map(|f| f.size).sum();
        reporter.start(name, total).await;

        let root = path::safe_local_join(local_dir, &path::remote_file_name(&remote)?)?;
        tokio::fs::create_dir_all(&root).await?;
        for dir in &dirs {
            check_cancel(cancel)?;
            let local = path::local_destination(local_dir, &path::remote_parent(&remote)?, dir)?;
            tokio::fs::create_dir_all(&local).await?;
        }
        for job in files {
            check_cancel(cancel)?;
            let local =
                path::local_destination(local_dir, &path::remote_parent(&remote)?, &job.remote)?;
            let job = FileJob { local, ..job };
            self.download_one(&job, reporter, cancel).await?;
        }
        Ok(())
    }

    async fn download_one(
        &self,
        job: &FileJob,
        reporter: &mut Reporter,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if let Some(parent) = job.local.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let existing = tokio::fs::metadata(&job.local)
            .await
            .ok()
            .filter(|m| m.is_file())
            .map(|m| m.len());

        let name = job
            .local
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let dir = job.local.parent().map(PathBuf::from).unwrap_or_default();

        let outcome =
            crate::transfer::plan_transfer(self.conflict, &name, existing, job.size, |candidate| {
                dir.join(candidate).exists()
            });

        let (target, offset) = match outcome {
            ConflictOutcome::Skip => {
                reporter.advance(job.size).await;
                return Ok(());
            }
            ConflictOutcome::Fresh => (job.local.clone(), 0),
            ConflictOutcome::Resume { offset } => {
                reporter.advance(offset).await;
                (job.local.clone(), offset)
            }
            ConflictOutcome::RenameTo(new_name) => (path::safe_local_join(&dir, &new_name)?, 0),
        };

        let mut source = self
            .sftp
            .open(job.remote.clone())
            .await
            .map_err(Error::sftp)?;
        if offset > 0 {
            source.seek(std::io::SeekFrom::Start(offset)).await?;
        }

        let mut sink = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(offset == 0)
            .open(&target)
            .await?;
        if offset > 0 {
            sink.seek(std::io::SeekFrom::Start(offset)).await?;
        }

        let mut buf = vec![0u8; CHUNK];
        loop {
            check_cancel(cancel)?;
            let read = source.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            sink.write_all(&buf[..read]).await?;
            reporter.advance(read as u64).await;
        }
        sink.flush().await?;
        drop(sink);

        preserve_local_metadata(&target, job.mode, job.mtime);
        Ok(())
    }

    // ------------------------------------------------------------- helpers

    /// Breadth-first walk of a remote directory. Returns `(dirs, files)` with
    /// directories in parents-first order. Symlinks are recorded but never
    /// followed, a symlink loop would otherwise hang the walk, and a link to
    /// `/` would drag the whole filesystem down the wire.
    async fn walk_remote(&self, root: &str) -> Result<(Vec<String>, Vec<FileJob>)> {
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        let mut queue = std::collections::VecDeque::from([root.to_string()]);
        // Hard cap: a hostile or pathological tree must not exhaust memory.
        const MAX_ENTRIES: usize = 200_000;

        while let Some(dir) = queue.pop_front() {
            let listing = self.sftp.read_dir(dir.clone()).await.map_err(Error::sftp)?;
            for entry in listing {
                if dirs.len() + files.len() >= MAX_ENTRIES {
                    return Err(Error::Other(
                        "the remote directory tree is too large to transfer".into(),
                    ));
                }
                let name = entry.file_name();
                if path::component(&name).is_err() {
                    tracing::warn!("skipping unsafe entry name in remote listing");
                    continue;
                }
                let full = path::join_remote(&dir, &name)?;
                let meta = entry.metadata();
                if meta.file_type().is_symlink() {
                    tracing::debug!(path = %full, "skipping remote symlink");
                    continue;
                }
                if meta.file_type().is_dir() {
                    dirs.push(full.clone());
                    queue.push_back(full);
                } else if meta.file_type().is_file() {
                    files.push(FileJob {
                        local: PathBuf::new(), // filled in by the caller
                        remote: full,
                        size: meta.len(),
                        mode: meta.permissions.unwrap_or(0o644) & 0o7777,
                        mtime: meta.mtime.map(i64::from),
                    });
                }
            }
        }
        Ok((dirs, files))
    }

    /// Names already present in a remote directory, for `Rename` conflicts.
    async fn sibling_names(&self, dir: &str) -> Vec<String> {
        match self.sftp.read_dir(dir.to_string()).await {
            Ok(listing) => listing.map(|e| e.file_name()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Open an SSH channel and start the `sftp` subsystem on it.
///
/// The body is deliberately a **boxed** future with an explicit `+ Send`
/// bound. `russh::Channel` is borrowed across an await here, and without the
/// explicit annotation the auto-trait leak check on `connect`'s opaque future
/// asks for `for<'a> &'a Channel<Msg>: Send`, a higher-ranked bound russh's
/// `Channel` does not satisfy, which surfaces as "implementation of `Send` is
/// not general enough". Boxing pins the region to a concrete one and the
/// bound is provable again. Do not inline this back into `connect`.
fn open_sftp_subsystem<'a>(
    ssh: &'a mut russh::client::Handle<ClientHandler>,
) -> BoxFuture<'a, Result<RawSftp>> {
    Box::pin(async move {
        let channel = ssh.channel_open_session().await.map_err(Error::ssh)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| Error::Sftp(format!("the server refused the sftp subsystem: {e}")))?;
        RawSftp::new(channel.into_stream())
            .await
            .map_err(Error::sftp)
    })
}

/// Boxed for the same reason as [`open_sftp_subsystem`]: russh's
/// `authenticate_*` futures hold `&mpsc::Sender<client::Msg>` across an await,
/// which is not higher-ranked `Send`. Pinning the region here keeps
/// `SftpSession::connect`'s future `Send`, which Tauri commands require.
fn authenticate<'a>(
    ssh: &'a mut russh::client::Handle<ClientHandler>,
    cfg: &'a FileTransferConfig,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(authenticate_inner(ssh, cfg))
}

async fn authenticate_inner(
    ssh: &mut russh::client::Handle<ClientHandler>,
    cfg: &FileTransferConfig,
) -> Result<()> {
    let ok = match &cfg.auth {
        // russh 0.62 returns `AuthResult` (which can also report "accepted but
        // more factors required") instead of a bare bool. Only outright
        // success counts here.
        SshAuth::Password(password) => ssh
            .authenticate_password(cfg.username.clone(), password.clone())
            .await
            .map_err(Error::ssh)?
            .success(),
        SshAuth::KeyFile { path, passphrase } => {
            let path = path.clone();
            let passphrase = passphrase.clone();
            let display = path.display().to_string();
            // Reading and decrypting a key is blocking, CPU-bound work.
            let key = tokio::task::spawn_blocking(move || {
                russh::keys::load_secret_key(&path, passphrase.as_deref())
            })
            .await
            .map_err(|e| Error::Other(e.to_string()))?
            .map_err(|e| Error::Key {
                path: display,
                reason: e.to_string(),
            })?;
            authenticate_with_key(ssh, &cfg.username, Arc::new(key)).await?
        }
        SshAuth::Agent => authenticate_with_agent(ssh, &cfg.username).await?,
    };
    if !ok {
        return Err(Error::Auth {
            user: cfg.username.clone(),
        });
    }
    Ok(())
}

/// RSA keys need an explicit signature hash: `ssh-rsa` (SHA-1) is refused by
/// every current OpenSSH, so try SHA-512 then SHA-256 before giving up.
fn authenticate_with_key<'a>(
    ssh: &'a mut russh::client::Handle<ClientHandler>,
    username: &'a str,
    key: Arc<russh::keys::PrivateKey>,
) -> BoxFuture<'a, Result<bool>> {
    Box::pin(authenticate_with_key_inner(ssh, username, key))
}

async fn authenticate_with_key_inner(
    ssh: &mut russh::client::Handle<ClientHandler>,
    username: &str,
    key: Arc<russh::keys::PrivateKey>,
) -> Result<bool> {
    let hashes: &[Option<HashAlg>] = if key.algorithm().is_rsa() {
        &[Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]
    } else {
        &[None]
    };
    for hash in hashes {
        // `PrivateKeyWithHashAlg::new` is infallible as of russh 0.62; it used
        // to return a Result.
        let with_hash = PrivateKeyWithHashAlg::new(key.clone(), *hash);
        match ssh
            .authenticate_publickey(username.to_string(), with_hash)
            .await
        {
            Ok(result) if result.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => return Err(Error::ssh(e)),
        }
    }
    Ok(false)
}

fn authenticate_with_agent<'a>(
    ssh: &'a mut russh::client::Handle<ClientHandler>,
    username: &'a str,
) -> BoxFuture<'a, Result<bool>> {
    Box::pin(authenticate_with_agent_inner(ssh, username))
}

async fn authenticate_with_agent_inner(
    ssh: &mut russh::client::Handle<ClientHandler>,
    username: &str,
) -> Result<bool> {
    let mut agent = connect_agent().await?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| Error::Agent(e.to_string()))?;
    if identities.is_empty() {
        return Err(Error::Agent("the ssh agent holds no identities".into()));
    }
    for identity in identities {
        // russh 0.62 hands back `AgentIdentity`, which may wrap a certificate
        // rather than a bare key, and `authenticate_publickey_with` now takes
        // the public key plus an explicit signature hash. `None` lets the
        // agent pick, which is what we want for every algorithm it holds.
        let key = identity.public_key().into_owned();
        // Boxed for the region reason documented on `BoxFuture`.
        let attempt: BoxFuture<
            '_,
            std::result::Result<russh::client::AuthResult, russh::AgentAuthError>,
        > = Box::pin(ssh.authenticate_publickey_with(username.to_string(), key, None, &mut agent));
        match attempt.await {
            Ok(result) if result.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!("agent identity rejected: {e}");
                continue;
            }
        }
    }
    Ok(false)
}

#[cfg(unix)]
async fn connect_agent() -> Result<
    russh::keys::agent::client::AgentClient<
        Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin + 'static>,
    >,
> {
    russh::keys::agent::client::AgentClient::connect_env()
        .await
        .map(|c| c.dynamic())
        .map_err(|e| Error::Agent(format!("SSH_AUTH_SOCK: {e}")))
}

/// Windows has two agents in the wild: the OpenSSH service on a named pipe and
/// Pageant. Try the pipe first, then fall back.
#[cfg(windows)]
async fn connect_agent() -> Result<
    russh::keys::agent::client::AgentClient<
        Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin + 'static>,
    >,
> {
    use russh::keys::agent::client::AgentClient;
    const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
    match AgentClient::connect_named_pipe(OPENSSH_PIPE).await {
        Ok(client) => Ok(client.dynamic()),
        Err(e) => {
            tracing::debug!("openssh agent pipe unavailable: {e}");
            // russh 0.62 made `connect_pageant` fallible; it used to return the
            // client directly. Pageant is the fallback, so a failure here means
            // neither agent is reachable.
            let pageant = AgentClient::connect_pageant()
                .await
                .map_err(|e| Error::Agent(format!("no SSH agent available: {e}")))?;
            Ok(pageant.dynamic())
        }
    }
}

// ---------------------------------------------------------------------------
// Planning + progress
// ---------------------------------------------------------------------------

/// Enumerate a local file or directory tree into a [`TransferPlan`].
async fn plan_upload(local: &Path, remote_dir: &str, name: &str) -> Result<TransferPlan> {
    let mut plan = TransferPlan::default();
    let meta = tokio::fs::symlink_metadata(local).await?;
    let root_remote = path::join_remote(remote_dir, name)?;

    if meta.is_file() {
        plan.total_bytes = meta.len();
        plan.files.push(FileJob {
            local: local.to_path_buf(),
            remote: root_remote,
            size: meta.len(),
            mode: unix_mode(&meta, 0o644),
            mtime: system_time_secs(meta.modified().ok()),
        });
        return Ok(plan);
    }
    if !meta.is_dir() {
        return Err(Error::Other(format!(
            "{} is neither a file nor a directory",
            local.display()
        )));
    }

    plan.dirs.push(root_remote.clone());
    let mut queue = std::collections::VecDeque::from([(local.to_path_buf(), root_remote)]);
    while let Some((dir, remote)) = queue.pop_front() {
        let mut read = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = read.next_entry().await? {
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                tracing::warn!("skipping non-UTF-8 local file name");
                continue;
            };
            if path::component(file_name).is_err() {
                continue;
            }
            let child_remote = path::join_remote(&remote, file_name)?;
            let meta = entry.metadata().await?;
            let file_type = entry.file_type().await?;
            if file_type.is_symlink() {
                tracing::debug!(path = ?entry.path(), "skipping local symlink");
                continue;
            }
            if file_type.is_dir() {
                plan.dirs.push(child_remote.clone());
                queue.push_back((entry.path(), child_remote));
            } else if file_type.is_file() {
                plan.total_bytes += meta.len();
                plan.files.push(FileJob {
                    local: entry.path(),
                    remote: child_remote,
                    size: meta.len(),
                    mode: unix_mode(&meta, 0o644),
                    mtime: system_time_secs(meta.modified().ok()),
                });
            }
        }
    }
    // Parents before children, then a stable file order (PRD/08 §3.3:
    // "sequential within a folder tree so ordering is predictable").
    plan.dirs.sort();
    plan.files.sort_by(|a, b| a.remote.cmp(&b.remote));
    Ok(plan)
}

fn unix_mode(meta: &std::fs::Metadata, fallback: u32) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fallback;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        // Windows has no mode bits; hand the remote a sane default and let it
        // apply its own umask.
        let _ = meta;
        fallback
    }
}

fn system_time_secs(time: Option<SystemTime>) -> Option<i64> {
    time.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

/// Apply the downloaded file's mode and mtime locally, where the filesystem
/// allows it. Best effort, a FAT volume simply will not keep the exec bit.
fn preserve_local_metadata(path: &Path, mode: u32, mtime: Option<i64>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Only the executable bits are worth carrying over; the rest of the
        // remote mode is meaningless locally and could widen access.
        if mode & 0o111 != 0 {
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(perms.mode() | 0o100);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = mode;

    if let Some(secs) = mtime {
        if let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) {
            let when = UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64);
            let _ = file.set_modified(when);
        }
    }
}

fn check_cancel(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    Ok(())
}

/// Owns one queue item's event emission: throttles progress, guarantees
/// exactly one terminal event.
struct Reporter {
    id: String,
    direction: Direction,
    tx: mpsc::Sender<TransferEvent>,
    throttle: ProgressThrottle,
    transferred: u64,
    total: u64,
    started: bool,
}

impl Reporter {
    fn new(id: String, tx: mpsc::Sender<TransferEvent>, direction: Direction) -> Self {
        Self {
            id,
            direction,
            tx,
            throttle: ProgressThrottle::new(PROGRESS_EVENTS_PER_SEC),
            transferred: 0,
            total: 0,
            started: false,
        }
    }

    async fn emit(&self, event: TransferEvent) {
        // A closed receiver means the window went away; the cancellation
        // token will stop the transfer shortly, so just drop the event.
        let _ = self.tx.send(event).await;
    }

    async fn start(&mut self, name: String, total: u64) {
        self.total = total;
        self.started = true;
        self.emit(TransferEvent::Started {
            id: self.id.clone(),
            name,
            total,
            direction: self.direction,
        })
        .await;
    }

    async fn advance(&mut self, delta: u64) {
        self.transferred = self.transferred.saturating_add(delta);
        if let Some(rate) = self.throttle.tick(Instant::now(), self.transferred, false) {
            self.emit(TransferEvent::Progress {
                id: self.id.clone(),
                transferred: self.transferred,
                total: self.total,
                bytes_per_sec: rate,
            })
            .await;
        }
    }

    /// Final 100% frame, so the bar never freezes at 97%.
    async fn flush(&mut self) {
        let rate = self
            .throttle
            .tick(Instant::now(), self.transferred, true)
            .unwrap_or(0.0);
        self.emit(TransferEvent::Progress {
            id: self.id.clone(),
            transferred: self.transferred.max(self.total),
            total: self.total,
            bytes_per_sec: rate,
        })
        .await;
    }

    async fn completed(&mut self) {
        self.flush().await;
        self.emit(TransferEvent::Completed {
            id: self.id.clone(),
        })
        .await;
    }

    async fn failed(&mut self, error: &Error) {
        self.emit(TransferEvent::Failed {
            id: self.id.clone(),
            error: error.to_string(),
        })
        .await;
    }

    async fn cancelled(&mut self) {
        self.emit(TransferEvent::Cancelled {
            id: self.id.clone(),
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plan_upload_of_a_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("notes.md");
        tokio::fs::write(&file, b"hello").await.unwrap();

        let plan = plan_upload(&file, "/home/user", "notes.md").await.unwrap();
        assert_eq!(plan.total_bytes, 5);
        assert!(plan.dirs.is_empty());
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].remote, "/home/user/notes.md");
        assert_eq!(plan.files[0].size, 5);
    }

    #[tokio::test]
    async fn plan_upload_walks_a_tree_parents_first() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        tokio::fs::create_dir_all(project.join("src/deep"))
            .await
            .unwrap();
        tokio::fs::write(project.join("README.md"), b"abc")
            .await
            .unwrap();
        tokio::fs::write(project.join("src/main.rs"), b"fn main(){}")
            .await
            .unwrap();
        tokio::fs::write(project.join("src/deep/x.txt"), b"xy")
            .await
            .unwrap();

        let plan = plan_upload(&project, "/remote", "project").await.unwrap();
        assert_eq!(plan.total_bytes, 3 + 11 + 2);
        assert_eq!(plan.files.len(), 3);
        assert_eq!(
            plan.dirs,
            vec![
                "/remote/project".to_string(),
                "/remote/project/src".to_string(),
                "/remote/project/src/deep".to_string(),
            ],
            "directories must be creatable in order"
        );
        // Every remote path stays under the destination directory.
        for job in &plan.files {
            assert!(job.remote.starts_with("/remote/project/"), "{}", job.remote);
        }
        assert!(!plan.is_empty());
    }

    #[tokio::test]
    async fn plan_upload_rejects_a_missing_source() {
        let dir = tempfile::tempdir().unwrap();
        assert!(plan_upload(&dir.path().join("nope"), "/r", "nope")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn reporter_emits_started_progress_and_exactly_one_terminal_event() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut reporter = Reporter::new("t1".into(), tx, Direction::Upload);
        reporter.start("a.bin".into(), 100).await;
        reporter.advance(50).await;
        reporter.completed().await;
        drop(reporter);

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }
        assert!(matches!(
            events.first(),
            Some(TransferEvent::Started { total: 100, .. })
        ));
        assert!(matches!(
            events.last(),
            Some(TransferEvent::Completed { .. })
        ));
        assert_eq!(
            events.iter().filter(|e| e.is_terminal()).count(),
            1,
            "exactly one terminal event: {events:?}"
        );
        // The last progress frame must read 100%.
        let last_progress = events
            .iter()
            .rev()
            .find_map(|e| match e {
                TransferEvent::Progress { transferred, .. } => Some(*transferred),
                _ => None,
            })
            .unwrap();
        assert_eq!(last_progress, 100);
    }

    #[tokio::test]
    async fn reporter_failure_carries_the_error_text() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut reporter = Reporter::new("t2".into(), tx, Direction::Download);
        reporter.start("x".into(), 10).await;
        reporter.failed(&Error::Cancelled).await;
        drop(reporter);
        let mut last = None;
        while let Some(e) = rx.recv().await {
            last = Some(e);
        }
        match last {
            Some(TransferEvent::Failed { id, error }) => {
                assert_eq!(id, "t2");
                assert!(error.contains("cancelled"), "{error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn a_cancelled_token_short_circuits() {
        let token = CancellationToken::new();
        assert!(check_cancel(&token).is_ok());
        token.cancel();
        assert!(matches!(check_cancel(&token), Err(Error::Cancelled)));
    }

    #[test]
    fn local_metadata_preservation_keeps_the_exec_bit() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("run.sh");
        std::fs::write(&file, b"#!/bin/sh\n").unwrap();
        preserve_local_metadata(&file, 0o755, Some(1_700_000_000));

        let meta = std::fs::metadata(&file).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(meta.permissions().mode() & 0o100 != 0, "exec bit lost");
        }
        let modified = meta.modified().unwrap();
        let secs = modified.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_700_000_000);
    }

    #[test]
    fn non_executable_downloads_stay_non_executable() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("notes.txt");
        std::fs::write(&file, b"hi").unwrap();
        preserve_local_metadata(&file, 0o644, None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0, "unexpected exec bit");
        }
    }
}
