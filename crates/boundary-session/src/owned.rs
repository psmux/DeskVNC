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
//! Run as anyone else, the folder is opened as it is and a file still never
//! through a link: a person gains nothing by fooling their own programs.

use std::io::{self, Read, Write};
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
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
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

#[cfg(not(unix))]
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
