//! Files in a person's own data folder, opened so that a process with more
//! rights than that person never follows a link they put there.
//!
//! On macOS the copy of DeskVNC Support at the sign in screen runs as root,
//! with the data folder of the person who switched it on. That person owns
//! the folder and everything in it, so any name in it, or any folder on the
//! way to it, could be a link to a system file, a second name for one, or a
//! pipe. Run as root, the folder is reached from the home folder one step at
//! a time without following a link, each step belonging to the home folder's
//! owner. A file in it is opened without following a link and used only when
//! it is a plain file with no other name, belonging to that person or to
//! root. One root made, here or by an older version, is handed to the person,
//! so their own app can still open it after they sign in.
//!
//! On Windows the copy at the sign in screen runs as SYSTEM, started by the
//! service, with the person's local app data folder. Run as SYSTEM, the
//! folder is reached from the root of its drive one folder at a time, each
//! opened relative to the one before and never through a symbolic link, a
//! junction or a mount point. A file in it is opened the same way and used
//! only when it is a plain file with one name, belonging to the person (the
//! owner of the folder or of the folder it is in), to SYSTEM or to the
//! Administrators group. A file SYSTEM makes there keeps the folder's
//! inherited permissions, which give the person full control of it.
//!
//! Run as anyone else, the folder is opened as it is and a file still never
//! through a link: a person gains nothing by fooling their own programs.

use std::io::{self, Read, Seek, Write};
use std::path::{Component, Path};

pub use imp::Folder;

/// The largest file [`read`] takes unless told otherwise.
pub const READ_LIMIT: u64 = 1024 * 1024;

/// Read `path`, refusing anything past `limit` bytes.
pub fn read(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let (dir, name) = split(path)?;
    Folder::open(dir)?.read(name, limit)
}

fn split(path: &Path) -> io::Result<(&Path, &str)> {
    let name = path.file_name().and_then(|n| n.to_str());
    match (path.parent(), name) {
        (Some(dir), Some(name)) => Ok((dir, name)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a file in a folder", path.display()),
        )),
    }
}

/// A single name in the folder, never a path.
fn plain_name(name: &str) -> io::Result<()> {
    let mut parts = Path::new(name).components();
    // On Windows a colon names a stream inside a file, or a drive.
    let colon = cfg!(windows) && name.contains(':');
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(_)), None) if !colon => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not a file name"),
        )),
    }
}

fn too_large(name: &str, limit: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{name} is larger than {limit} bytes"),
    )
}

impl Folder {
    /// Add `line` and a new line to `name`, starting the file again once it
    /// is past `limit` bytes. Makes the file if it is not there.
    pub fn append(&self, name: &str, line: &str, limit: u64) -> io::Result<()> {
        let mut file = self.file(name, Open::Append)?;
        if file.metadata()?.len() > limit {
            file.set_len(0)?;
        }
        // Windows opens it to write anywhere, so it can be emptied.
        file.seek(io::SeekFrom::End(0))?;
        writeln!(file, "{line}")
    }

    /// Everything in `name`, which must be at most `limit` bytes.
    pub fn read(&self, name: &str, limit: u64) -> io::Result<Vec<u8>> {
        let file = self.file(name, Open::Read)?;
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(too_large(name, limit));
        }
        Ok(bytes)
    }

    /// `name` opened to be locked, made if it is not there. Nothing is
    /// written to it, so it is opened for reading only.
    pub fn lock(&self, name: &str) -> io::Result<std::fs::File> {
        self.file(name, Open::Lock)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    Read,
    Append,
    Lock,
}

#[cfg(unix)]
mod imp {
    use super::{Open, plain_name};
    use rustix::fs::{self as fs, CWD, FileType, Mode, OFlags};
    use rustix::process::{Gid, Uid, getegid, geteuid};
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::{Component, Path};

    const DIR: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC);

    fn refused(what: String) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, what)
    }

    /// A folder held open, and whose files it holds.
    pub struct Folder {
        fd: OwnedFd,
        owner: u32,
        group: u32,
        /// Whether a file must also have one name and belong to `owner` or
        /// root: set when this process could do more than `owner` can.
        strict: bool,
    }

    impl Folder {
        /// Open `dir`. Run as root, `dir` must be inside the home folder,
        /// and is reached from it without following a link.
        pub fn open(dir: &Path) -> io::Result<Self> {
            if geteuid().is_root() {
                let home = std::env::var_os("HOME")
                    .map(std::path::PathBuf::from)
                    .ok_or_else(|| refused("There is no home folder".into()))?;
                let inside = dir.strip_prefix(&home).map_err(|_| {
                    refused(format!(
                        "{} is not inside the home folder {}",
                        dir.display(),
                        home.display()
                    ))
                })?;
                Self::within(&home, inside, true)
            } else {
                let fd = fs::openat(CWD, dir, DIR, Mode::empty())?;
                Ok(Self {
                    fd,
                    owner: geteuid().as_raw(),
                    group: getegid().as_raw(),
                    strict: false,
                })
            }
        }

        /// Open `dir`, making it first when this process is not root. Root
        /// makes nothing in somebody else's home folder.
        pub fn create(dir: &Path) -> io::Result<Self> {
            if !geteuid().is_root() {
                std::fs::create_dir_all(dir)?;
            }
            Self::open(dir)
        }

        /// `inside` under `base`, one folder at a time, never through a
        /// link, each folder belonging to whoever owns `base`.
        pub(super) fn within(base: &Path, inside: &Path, strict: bool) -> io::Result<Self> {
            let mut fd = fs::openat(CWD, base, DIR, Mode::empty())?;
            let stat = fs::fstat(&fd)?;
            let (owner, group) = (stat.st_uid, stat.st_gid);
            for part in inside.components() {
                let Component::Normal(name) = part else {
                    return Err(refused(format!("{} is not a plain path", inside.display())));
                };
                fd = match fs::openat(&fd, name, DIR | OFlags::NOFOLLOW, Mode::empty()) {
                    Ok(fd) => fd,
                    Err(fs_error) if fs_error.kind() == io::ErrorKind::NotFound => {
                        return Err(fs_error.into());
                    }
                    Err(_) => {
                        return Err(refused(format!(
                            "{} in {} is not a folder",
                            name.to_string_lossy(),
                            base.display()
                        )));
                    }
                };
                if fs::fstat(&fd)?.st_uid != owner {
                    return Err(refused(format!(
                        "{} in {} belongs to someone else",
                        name.to_string_lossy(),
                        base.display()
                    )));
                }
            }
            Ok(Self {
                fd,
                owner,
                group,
                strict,
            })
        }

        pub(super) fn file(&self, name: &str, open: Open) -> io::Result<std::fs::File> {
            plain_name(name)?;
            // Never through a link, and never waiting on a pipe.
            let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            flags |= match open {
                Open::Read => OFlags::RDONLY,
                Open::Append => OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE,
                Open::Lock => OFlags::RDONLY | OFlags::CREATE,
            };
            let fd =
                fs::openat(&self.fd, name, flags, Mode::from_raw_mode(0o644)).map_err(|error| {
                    match error.kind() {
                        io::ErrorKind::NotFound => error.into(),
                        _ => refused(format!("Cannot open {name}: {error}")),
                    }
                })?;
            let stat = fs::fstat(&fd)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(refused(format!("{name} is not a plain file")));
            }
            if self.strict {
                if stat.st_nlink != 1 {
                    return Err(refused(format!("{name} has another name elsewhere")));
                }
                if stat.st_uid != self.owner && stat.st_uid != 0 {
                    return Err(refused(format!("{name} belongs to someone else")));
                }
                // Made by root, now or by an older version. With one name,
                // in a folder only the person can write, it is theirs.
                if stat.st_uid != self.owner && geteuid().is_root() {
                    fs::fchown(
                        &fd,
                        Some(Uid::from_raw(self.owner)),
                        Some(Gid::from_raw(self.group)),
                    )?;
                }
            }
            let flags = fs::fcntl_getfl(&fd)?;
            fs::fcntl_setfl(&fd, flags - OFlags::NONBLOCK)?;
            Ok(std::fs::File::from(fd))
        }
    }
}

// The one place in this crate that calls the system directly: Windows has
// no safe binding that opens a file relative to a folder handle.
#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use super::{Open, plain_name};
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::ptr::{null, null_mut};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, LocalFree, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_TYPE_DISK,
        FILE_WRITE_DATA, GetFileInformationByHandle, GetFileType, READ_CONTROL, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const DIR: u32 =
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    fn refused(what: String) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, what)
    }

    fn raw(handle: &OwnedHandle) -> HANDLE {
        handle.as_raw_handle() as HANDLE
    }

    /// A folder held open, and whose files it holds.
    pub struct Folder {
        handle: OwnedHandle,
        /// Who a file may belong to besides SYSTEM and the Administrators
        /// group: the owners of the folder and of the folder it is in. The
        /// profile service makes the local app data folder as the person.
        owners: Vec<Vec<u8>>,
        /// Whether a file must also have one name and belong to one of
        /// `owners`, SYSTEM or the Administrators group: set when this
        /// process runs as SYSTEM.
        strict: bool,
    }

    /// Whether this process runs as SYSTEM, as the copy the service starts
    /// at the sign in screen does.
    fn system() -> bool {
        let mut token: HANDLE = null_mut();
        // SAFETY: the pseudo handle needs no closing; the token is owned.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return false;
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
        let mut buffer = [0u64; 64];
        let mut length = 0;
        // SAFETY: the buffer is large and aligned enough for a TOKEN_USER
        // and its SID, and the result is read only when the call succeeds.
        unsafe {
            GetTokenInformation(
                raw(&token),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut length,
            ) != 0
                && IsWellKnownSid(
                    (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid,
                    WinLocalSystemSid,
                ) != 0
        }
    }

    fn info(handle: &OwnedHandle) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
        // SAFETY: a plain struct the call fills in.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(raw(handle), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    /// The SID that owns what `handle` has open, as bytes.
    fn owner(handle: &OwnedHandle) -> io::Result<Vec<u8>> {
        let mut sid: PSID = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `sid` points into `descriptor`, which is freed only after
        // the SID is copied out.
        unsafe {
            let error = GetSecurityInfo(
                raw(handle),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut sid,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            );
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            let bytes = if sid.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(sid.cast::<u8>(), GetLengthSid(sid) as usize).to_vec()
            };
            LocalFree(descriptor.cast());
            Ok(bytes)
        }
    }

    fn well_known(sid: &[u8], kind: WELL_KNOWN_SID_TYPE) -> bool {
        // SAFETY: a SID as GetSecurityInfo gave it, never written to.
        !sid.is_empty() && unsafe { IsWellKnownSid(sid.as_ptr() as PSID, kind) } != 0
    }

    /// `name` in the folder `dir` has open, never through a link: a link
    /// or junction there is opened as itself, which the caller refuses.
    fn open_at(
        dir: &OwnedHandle,
        name: &OsStr,
        access: u32,
        disposition: u32,
        options: u32,
    ) -> io::Result<OwnedHandle> {
        let mut wide: Vec<u16> = name.encode_wide().collect();
        let bytes = u16::try_from(wide.len() * 2)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "The name is too long"))?;
        let name = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: wide.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: raw(dir),
            ObjectName: &name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let mut handle: HANDLE = null_mut();
        // SAFETY: every pointer is to a local that outlives the call.
        let status = unsafe {
            let mut status_block: IO_STATUS_BLOCK = std::mem::zeroed();
            NtCreateFile(
                &mut handle,
                access | SYNCHRONIZE,
                &attributes,
                &mut status_block,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                SHARE,
                disposition,
                options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        if status < 0 {
            let error = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
    }

    /// A folder by its path. Unless `follow`, the path's last part must
    /// not itself be a link.
    fn open_path(dir: &Path, follow: bool) -> io::Result<OwnedHandle> {
        let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
        if !follow {
            flags |= FILE_FLAG_OPEN_REPARSE_POINT;
        }
        let file = std::fs::OpenOptions::new()
            .access_mode(DIR)
            .share_mode(SHARE)
            .custom_flags(flags)
            .open(dir)?;
        let handle = OwnedHandle::from(file);
        let attributes = info(&handle)?.dwFileAttributes;
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a folder", dir.display()),
            ));
        }
        if !follow && attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused(format!("{} is a link", dir.display())));
        }
        Ok(handle)
    }

    /// The root of the drive `dir` is on, and the rest of it. Only a path
    /// on a drive letter is taken: anything else could lead elsewhere.
    fn split_root(dir: &Path) -> io::Result<(PathBuf, &Path)> {
        let mut parts = dir.components();
        match (parts.next(), parts.next()) {
            (Some(Component::Prefix(prefix)), Some(Component::RootDir))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
            {
                Ok((Path::new(prefix.as_os_str()).join("\\"), parts.as_path()))
            }
            _ => Err(refused(format!(
                "{} is not a full path on a drive",
                dir.display()
            ))),
        }
    }

    impl Folder {
        /// Open `dir`. Run as SYSTEM, it is reached from the root of its
        /// drive without following a link.
        pub fn open(dir: &Path) -> io::Result<Self> {
            if system() {
                Self::from_root(dir)
            } else {
                Ok(Self {
                    handle: open_path(dir, true)?,
                    owners: Vec::new(),
                    strict: false,
                })
            }
        }

        /// Open `dir`, making it first when this process is not SYSTEM.
        /// SYSTEM makes nothing in somebody else's folder.
        pub fn create(dir: &Path) -> io::Result<Self> {
            if !system() {
                std::fs::create_dir_all(dir)?;
            }
            Self::open(dir)
        }

        /// `dir` as SYSTEM opens it: from the root of its drive, strictly.
        pub(super) fn from_root(dir: &Path) -> io::Result<Self> {
            let (root, inside) = split_root(dir)?;
            Self::within(&root, inside, true)
        }

        /// `inside` under `base`, one folder at a time, each opened in the
        /// one before and never a link, a junction or a mount point.
        pub(super) fn within(base: &Path, inside: &Path, strict: bool) -> io::Result<Self> {
            let mut handle = open_path(base, false)?;
            let mut parent = None;
            for part in inside.components() {
                let Component::Normal(name) = part else {
                    return Err(refused(format!("{} is not a plain path", inside.display())));
                };
                let next = match open_at(&handle, name, DIR, FILE_OPEN, FILE_DIRECTORY_FILE) {
                    Ok(next) => next,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(error),
                    Err(_) => {
                        return Err(refused(format!(
                            "{} in {} is not a folder",
                            name.to_string_lossy(),
                            base.display()
                        )));
                    }
                };
                if info(&next)?.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(refused(format!(
                        "{} in {} is a link",
                        name.to_string_lossy(),
                        base.display()
                    )));
                }
                parent = Some(std::mem::replace(&mut handle, next));
            }
            let mut owners = Vec::new();
            if strict {
                owners.push(owner(&handle)?);
                if let Some(parent) = &parent {
                    owners.push(owner(parent)?);
                }
                owners.retain(|o| !o.is_empty());
            }
            Ok(Self {
                handle,
                owners,
                strict,
            })
        }

        pub(super) fn file(&self, name: &str, open: Open) -> io::Result<std::fs::File> {
            plain_name(name)?;
            let (access, disposition) = match open {
                Open::Read => (FILE_GENERIC_READ, FILE_OPEN),
                // Written anywhere, so a log past its limit can be emptied.
                Open::Append => (
                    FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_APPEND_DATA,
                    FILE_OPEN_IF,
                ),
                // A lock needs no writing.
                Open::Lock => (FILE_GENERIC_READ, FILE_OPEN_IF),
            };
            let handle = open_at(
                &self.handle,
                OsStr::new(name),
                access,
                disposition,
                FILE_NON_DIRECTORY_FILE,
            )
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => error,
                _ => refused(format!("Cannot open {name}: {error}")),
            })?;
            let info = info(&handle)?;
            let plain = info.dwFileAttributes
                & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                == 0
                && unsafe { GetFileType(raw(&handle)) } == FILE_TYPE_DISK;
            if !plain {
                return Err(refused(format!("{name} is not a plain file")));
            }
            if self.strict {
                if info.nNumberOfLinks != 1 {
                    return Err(refused(format!("{name} has another name elsewhere")));
                }
                let owner = owner(&handle)?;
                let allowed = self.owners.contains(&owner)
                    || well_known(&owner, WinLocalSystemSid)
                    || well_known(&owner, WinBuiltinAdministratorsSid);
                if !allowed {
                    return Err(refused(format!("{name} belongs to someone else")));
                }
            }
            Ok(std::fs::File::from(handle))
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::{Open, plain_name};
    use std::io;
    use std::path::{Path, PathBuf};

    /// A folder, by its path.
    pub struct Folder {
        dir: PathBuf,
    }

    impl Folder {
        pub fn open(dir: &Path) -> io::Result<Self> {
            if !std::fs::metadata(dir)?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("{} is not a folder", dir.display()),
                ));
            }
            Ok(Self {
                dir: dir.to_path_buf(),
            })
        }
        pub fn create(dir: &Path) -> io::Result<Self> {
            std::fs::create_dir_all(dir)?;
            Self::open(dir)
        }
        pub(super) fn file(&self, name: &str, open: Open) -> io::Result<std::fs::File> {
            plain_name(name)?;
            let path = self.dir.join(name);
            let mut options = std::fs::OpenOptions::new();
            match open {
                Open::Read => options.read(true),
                Open::Append => options.append(true).create(true),
                Open::Lock => options.write(true).create(true).truncate(false),
            };
            let opened = options.open(&path);
            match open {
                // Made by another account, a lock still needs no writing.
                Open::Lock => opened.or_else(|_| std::fs::File::open(&path)),
                _ => opened,
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("owned-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("data")).unwrap();
        dir
    }

    #[test]
    fn never_writes_through_a_link() {
        let dir = scratch("link");
        let other = dir.join("other");
        std::fs::write(&other, "left alone\n").unwrap();
        symlink(&other, dir.join("data/log")).unwrap();
        let folder = Folder::open(&dir.join("data")).unwrap();
        assert!(folder.append("log", "x", 64 * 1024).is_err());
        assert!(folder.lock("log").is_err());
        assert!(folder.read("log", READ_LIMIT).is_err());
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "left alone\n");
        // A link to nothing is not made into a file either.
        symlink(dir.join("made"), dir.join("data/lock")).unwrap();
        assert!(folder.lock("lock").is_err());
        assert!(folder.append("lock", "x", 64 * 1024).is_err());
        assert!(!dir.join("made").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn never_waits_on_a_pipe() {
        let dir = scratch("pipe");
        let pipe = dir.join("data/log");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&pipe)
                .status()
                .unwrap()
                .success()
        );
        let folder = Folder::open(&dir.join("data")).unwrap();
        assert!(folder.read("log", READ_LIMIT).is_err());
        assert!(folder.append("log", "x", 64 * 1024).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strict_refuses_a_second_name_and_a_linked_folder() {
        let dir = scratch("strict");
        std::fs::write(dir.join("other"), "left alone\n").unwrap();
        std::fs::hard_link(dir.join("other"), dir.join("data/log")).unwrap();
        let folder = Folder::within(&dir, Path::new("data"), true).unwrap();
        assert!(folder.append("log", "x", 64 * 1024).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("other")).unwrap(),
            "left alone\n"
        );
        // A folder on the way that is a link is not followed.
        std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
        symlink(dir.join("elsewhere"), dir.join("data/linked")).unwrap();
        assert!(Folder::within(&dir, Path::new("data/linked"), true).is_err());
        assert!(Folder::within(&dir, Path::new("data/../other"), true).is_err());
        assert_eq!(
            Folder::within(&dir, Path::new("data/missing"), true)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appends_reads_and_starts_again() {
        let dir = scratch("plain");
        let folder = Folder::within(&dir, Path::new("data"), true).unwrap();
        folder.append("log", "one", 7).unwrap();
        folder.append("log", "two", 7).unwrap();
        assert_eq!(folder.read("log", 100).unwrap(), b"one\ntwo\n");
        // Past the limit it starts again.
        folder.append("log", "three", 7).unwrap();
        assert_eq!(folder.read("log", 100).unwrap(), b"three\n");
        assert!(folder.read("log", 3).is_err());
        assert_eq!(
            folder.read("missing", 100).err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        assert!(folder.lock("lock").unwrap().try_lock().is_ok());
        assert!(folder.read("../other", 100).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("owned-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("data")).unwrap();
        dir
    }

    /// A symbolic link to a file. Making one needs a right an administrator
    /// or developer mode has; without it the caller skips that part.
    fn file_link(target: &Path, link: &Path) -> bool {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("skipped, cannot make a symbolic link here: {error}");
                false
            }
        }
    }

    #[test]
    fn never_writes_through_a_link() {
        let dir = scratch("link");
        let other = dir.join("other");
        std::fs::write(&other, "left alone\n").unwrap();
        if !file_link(&other, &dir.join("data").join("log")) {
            return;
        }
        let folder = Folder::open(&dir.join("data")).unwrap();
        assert!(folder.append("log", "x", 64 * 1024).is_err());
        assert!(folder.lock("log").is_err());
        assert!(folder.read("log", READ_LIMIT).is_err());
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "left alone\n");
        // A log past its limit starts again, and that never empties the
        // file a link points to.
        std::fs::write(&other, [b'a'; 100]).unwrap();
        let _ = folder.append("log", "x", 10);
        assert_eq!(std::fs::read(&other).unwrap(), [b'a'; 100]);
        // A link to nothing is not made into a file either.
        let made = dir.join("made");
        assert!(file_link(&made, &dir.join("data").join("lock")));
        assert!(folder.lock("lock").is_err());
        assert!(folder.append("lock", "x", 64 * 1024).is_err());
        assert!(!made.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A junction, which any account may make in a folder it can write.
    fn junction(target: &Path, link: &Path) {
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
    }

    #[test]
    fn strict_refuses_a_second_name_and_a_junction() {
        let dir = scratch("strict");
        let other = dir.join("other");
        std::fs::write(&other, "left alone\n").unwrap();
        std::fs::hard_link(&other, dir.join("data").join("log")).unwrap();
        let folder = Folder::within(&dir, Path::new("data"), true).unwrap();
        assert!(folder.append("log", "x", 64 * 1024).is_err());
        assert!(folder.read("log", READ_LIMIT).is_err());
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "left alone\n");
        // A folder on the way that is a junction is not followed, nor is
        // anything made where it points.
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        junction(&elsewhere, &dir.join("data").join("linked"));
        assert!(Folder::within(&dir, Path::new("data\\linked"), true).is_err());
        assert!(Folder::from_root(&dir.join("data").join("linked")).is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        // A junction in place of a file is no file either.
        junction(&elsewhere, &dir.join("data").join("lock"));
        assert!(folder.lock("lock").is_err());
        assert!(Folder::within(&dir, Path::new("data\\..\\other"), true).is_err());
        assert_eq!(
            Folder::within(&dir, Path::new("data\\missing"), true)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strict_from_the_drive_root_reads_and_writes_plain_files() {
        let dir = scratch("root");
        let folder = Folder::from_root(&dir.join("data")).unwrap();
        folder.append("log", "one", 64 * 1024).unwrap();
        assert_eq!(folder.read("log", 100).unwrap(), b"one\n");
        assert!(folder.lock("lock").unwrap().try_lock().is_ok());
        assert!(Folder::from_root(Path::new("data")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_is_never_a_stream_or_a_path() {
        let dir = scratch("stream");
        let folder = Folder::open(&dir.join("data")).unwrap();
        assert!(folder.append("log:hidden", "x", 64 * 1024).is_err());
        assert!(folder.read("..\\other", 100).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appends_reads_and_starts_again() {
        let dir = scratch("plain");
        let folder = Folder::open(&dir.join("data")).unwrap();
        folder.append("log", "one", 7).unwrap();
        folder.append("log", "two", 7).unwrap();
        assert_eq!(folder.read("log", 100).unwrap(), b"one\ntwo\n");
        folder.append("log", "three", 7).unwrap();
        assert_eq!(folder.read("log", 100).unwrap(), b"three\n");
        assert!(folder.read("log", 3).is_err());
        assert_eq!(
            folder.read("missing", 100).err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        let lock = folder.lock("lock").unwrap();
        assert!(lock.try_lock().is_ok());
        // A second holder is turned away while the first holds it.
        assert!(matches!(
            folder.lock("lock").unwrap().try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
