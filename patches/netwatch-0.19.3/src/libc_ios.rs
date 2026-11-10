//! DeskVNC patch. libc 0.2.190 and later declare the routing socket
//! constants (<net/route.h>) for macOS only. iOS runs the same XNU kernel
//! with the same values, so this module re-exports libc and adds them back,
//! which lets this crate build for iOS against the current libc. The values
//! are copied from libc 0.2.191's macOS definitions.

pub use libc::*;

pub const RTF_IFSCOPE: c_int = 0x1000000;
pub const RTM_ADD: c_int = 0x1;
pub const RTM_DELETE: c_int = 0x2;
pub const RTM_CHANGE: c_int = 0x3;
pub const RTM_GET: c_int = 0x4;
pub const RTM_LOSING: c_int = 0x5;
pub const RTM_REDIRECT: c_int = 0x6;
pub const RTM_MISS: c_int = 0x7;
pub const RTM_LOCK: c_int = 0x8;
pub const RTM_RESOLVE: c_int = 0xb;
pub const RTM_NEWADDR: c_int = 0xc;
pub const RTM_DELADDR: c_int = 0xd;
pub const RTM_IFINFO: c_int = 0xe;
pub const RTM_NEWMADDR: c_int = 0xf;
pub const RTM_DELMADDR: c_int = 0x10;
pub const RTM_IFINFO2: c_int = 0x12;
pub const RTM_NEWMADDR2: c_int = 0x13;
pub const RTM_GET2: c_int = 0x14;
pub const RTM_VERSION: c_int = 5;
pub const RTA_IFP: c_int = 0x10;
pub const RTAX_DST: c_int = 0;
pub const RTAX_GATEWAY: c_int = 1;
pub const RTAX_NETMASK: c_int = 2;
pub const RTAX_IFP: c_int = 4;
pub const RTAX_BRD: c_int = 7;
pub const RTAX_MAX: c_int = 8;
pub const RTF_GATEWAY: c_int = 0x2;
