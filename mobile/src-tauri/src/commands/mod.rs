//! The commands of `mobile/CONTRACT.md`, one module per area. Every command
//! returns `Result<_, String>`, its error a sentence the UI can show.

pub mod hosts;
pub mod scan;
pub mod session;

/// Run blocking storage or vault work off the async runtime, flattening both
/// the join error and the inner error into a display string.
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
