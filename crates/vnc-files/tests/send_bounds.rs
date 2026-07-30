//! Regression guard: every future the Tauri layer awaits must be `Send`.
//!
//! `#[tauri::command]` spawns command futures on a multi-thread runtime, so a
//! non-`Send` future is a hard compile error at the *call site*, with a
//! famously unhelpful "implementation of `Send` is not general enough"
//! message pointing at `generate_handler!`.
//!
//! Several russh / russh-sftp futures hold a shared reference across an await
//! over a type whose `Send`ness is not provable higher-ranked
//! (`&Channel<Msg>`, `&mpsc::Sender<Msg>`). `session.rs` boxes those at well
//! marked boundaries to pin the region. This file fails to compile if anyone
//! "simplifies" one of them back into a plain `async fn`, so the breakage is
//! caught here instead of three crates away in `src-tauri`.

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vnc_files::{FileTransferConfig, HostKeyStore, SftpSession, TransferEvent};

#[allow(dead_code)]
fn assert_send<F: Send>(_: F) {}

#[test]
fn every_public_future_is_send() {
    // Type-checking is the test; nothing here is executed.
    #[allow(unreachable_code, clippy::diverging_sub_expression)]
    fn _compile_only() {
        assert_send(async {
            let cfg = FileTransferConfig::new("host", "user");
            let pins = Arc::new(Mutex::new(HostKeyStore::new()));
            let session = SftpSession::connect(cfg, pins).await.unwrap();

            let _ = session.home_dir().await;
            let _ = session.resolve("~/Desktop").await;
            let _ = session.list_dir("/home/user").await;
            let _ = session.stat("/home/user/notes.md").await;
            let _ = session.mkdir("/home/user/new").await;
            let _ = session.rename("/a", "/b").await;
            let _ = session.remove("/home/user/old", true).await;

            let (tx, _rx) = mpsc::channel::<TransferEvent>(8);
            let cancel = CancellationToken::new();
            let _ = session
                .upload(
                    Path::new("/tmp/x"),
                    "/home/user",
                    "id".into(),
                    tx.clone(),
                    cancel.clone(),
                )
                .await;
            let _ = session
                .download("/home/user/x", Path::new("/tmp"), "id".into(), tx, cancel)
                .await;
            let _ = session.close().await;
        });

        assert_send(vnc_files::probe_ssh(
            "host",
            22,
            std::time::Duration::from_secs(1),
        ));
    }
}
