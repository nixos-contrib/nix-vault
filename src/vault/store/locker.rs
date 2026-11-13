//! Per-profile advisory lock that serializes refresh and persistence of credentials.
//!
//! The lock file lives in the user state directory, holds no secrets, and is created with
//! owner-only permissions.

use std::{
    fs::{DirBuilder, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

use fd_lock::RwLock;

use crate::vault::{Error, Result};

/// Runs `action` while holding the exclusive lock of `profile`, blocking until it is available.
pub fn with_profile_lock<T>(
    state_dir: &Path,
    profile: &str,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let dir = state_dir.join("locks");
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| Error::io("cannot create the lock directory", e))?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join(format!("{profile}.lock")))
        .map_err(|e| Error::io("cannot open the profile lock", e))?;
    let mut lock = RwLock::new(file);
    let _guard = lock
        .write()
        .map_err(|e| Error::io("cannot lock the profile", e))?;
    action()
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };

    use super::*;

    #[test]
    fn second_acquire_blocks_until_the_first_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));

        let (p, e, r) = (path.clone(), entered.clone(), release.clone());
        let first = std::thread::spawn(move || {
            with_profile_lock(&p, "cache", || {
                e.store(true, Ordering::SeqCst);
                while !r.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(())
            })
        });
        while !entered.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let second_ran = Arc::new(AtomicBool::new(false));
        let (p2, s2) = (path.clone(), second_ran.clone());
        let second = std::thread::spawn(move || {
            with_profile_lock(&p2, "cache", || {
                s2.store(true, Ordering::SeqCst);
                Ok(())
            })
        });
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !second_ran.load(Ordering::SeqCst),
            "second lock was not blocked"
        );
        release.store(true, Ordering::SeqCst);
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        assert!(second_ran.load(Ordering::SeqCst));
    }
}
