/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by `vnc-store`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("keychain error: {0}")]
    Keyring(#[from] keyring::Error),

    #[error("credential store is locked; unlock it with the master password first")]
    Locked,

    #[error("wrong master password (or the credential file is corrupted)")]
    InvalidMasterPassword,

    #[error(
        "serialized credentials are {size} bytes, exceeding the {limit}-byte \
         platform credential limit (Windows Credential Manager blob cap)"
    )]
    CredentialTooLarge { size: usize, limit: usize },

    #[error("credential file is malformed: {0}")]
    MalformedCredentialFile(String),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("image processing error: {0}")]
    Image(String),

    #[error("invalid data: {0}")]
    InvalidData(String),

    #[error(
        "this profile's RDP settings are version {found}, and this build \
         understands up to version {max}: the profile was written by a newer \
         version of the app"
    )]
    RdpSettingsTooNew { found: u32, max: u32 },

    #[error("this .rdp file cannot be imported: {0}")]
    RdpFileRefused(String),

    #[error("could not determine the application data directory")]
    NoDataDir,
}
