//! The local transport on Windows: a named pipe only its creator can open.
//!
//! On macOS and Linux the agent plane and the `dvv` holder each listen on a
//! unix socket created mode 0600 in a directory the user owns, and the file
//! permission is the whole of the authentication. Windows has no such socket
//! in the places this has to run, so `04 §2.1` names a pipe instead, with an
//! ACL that grants the creating user and nobody else. That ACL is the part
//! worth writing once, and it is why this crate exists.
//!
//! The default security descriptor on a named pipe gives Everyone read
//! access, which on a machine with two people logged in is one of them being
//! able to open the other's plane. So every instance is created with a DACL
//! naming this process's user SID, and remote clients are rejected, which is
//! the pipe's equivalent of binding loopback.
//!
//! Nothing here on unix. Both callers keep their own `UnixListener`.

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{connect, create, exists, keep_std_handles_private};
