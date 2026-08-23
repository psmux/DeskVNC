//! Tauri commands, one module per area. Every command returns
//! `Result<_, String>` with errors mapped to display strings, no `unwrap()`.

pub mod about;
pub mod capture;
pub mod credentials;
pub mod discovery;
pub mod files;
pub mod hosts;
pub mod menu;
pub mod session;

/// Run a blocking storage/keychain closure off the async runtime and flatten
/// both the join error and the inner error into a display `String`.
pub(crate) async fn blocking<T, E, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}
