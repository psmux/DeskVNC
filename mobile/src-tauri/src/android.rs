//! Android only: the Wi-Fi multicast lock.
//!
//! Android filters incoming multicast on Wi-Fi to save power, which silently
//! starves an mDNS browse, unless an app holds a `WifiManager.MulticastLock`.
//! It is taken while a scan runs and let go when the scan ends. Needs
//! `CHANGE_WIFI_MULTICAST_STATE` in the manifest.

use std::sync::Mutex;

use jni::objects::{Global, JObject};
use jni::{jni_sig, jni_str, JValue, JavaVM};

static LOCK: Mutex<Option<Global<JObject<'static>>>> = Mutex::new(None);

/// Hold (`true`) or release (`false`) the lock. Failures are logged and
/// otherwise ignored: without the lock the TCP sweep still works, only the
/// mDNS half goes quiet.
pub fn multicast_lock(hold: bool) {
    if let Err(error) = set(hold) {
        tracing::warn!(%error, hold, "multicast lock");
    }
}

/// Why taking or letting go of the lock failed, as text for the log.
struct Failure(String);

impl From<jni::errors::Error> for Failure {
    fn from(error: jni::errors::Error) -> Self {
        Failure(error.to_string())
    }
}

fn set(hold: bool) -> Result<(), String> {
    let mut slot = LOCK.lock().map_err(|_| "lock poisoned")?;
    let ctx = ndk_context::android_context();
    // SAFETY: `ndk-context` hands out the process's JavaVM pointer, which
    // Tauri set at start and which lives as long as the process.
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) };
    vm.attach_current_thread(|env| -> Result<(), Failure> {
        if !hold {
            if let Some(lock) = slot.take() {
                env.call_method(lock.as_obj(), jni_str!("release"), jni_sig!("()V"), &[])?;
            }
            return Ok(());
        }
        if slot.is_some() {
            return Ok(());
        }
        // SAFETY: the context pointer is the activity Tauri registered, a
        // live global reference for the life of the process. `JObject` has no
        // drop of its own, so wrapping it never deletes that reference.
        let context = unsafe { JObject::from_raw(env, ctx.context().cast()) };
        let name = env.new_string("wifi")?;
        let wifi = env
            .call_method(
                &context,
                jni_str!("getSystemService"),
                jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                &[JValue::Object(&name)],
            )?
            .l()?;
        if wifi.is_null() {
            return Err(Failure("no Wi-Fi service".into()));
        }
        let tag = env.new_string("DeskVNC discovery")?;
        let lock = env
            .call_method(
                &wifi,
                jni_str!("createMulticastLock"),
                jni_sig!("(Ljava/lang/String;)Landroid/net/wifi/WifiManager$MulticastLock;"),
                &[JValue::Object(&tag)],
            )?
            .l()?;
        env.call_method(
            &lock,
            jni_str!("setReferenceCounted"),
            jni_sig!("(Z)V"),
            &[JValue::Bool(false)],
        )?;
        env.call_method(&lock, jni_str!("acquire"), jni_sig!("()V"), &[])?;
        *slot = Some(env.new_global_ref(lock)?);
        Ok(())
    })
    .map_err(|Failure(error)| error)
}
