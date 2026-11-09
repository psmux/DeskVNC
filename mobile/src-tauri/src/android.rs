//! Android only: the Wi-Fi multicast lock.
//!
//! Android filters incoming multicast on Wi-Fi to save power, which silently
//! starves an mDNS browse, unless an app holds a `WifiManager.MulticastLock`.
//! It is taken while a scan runs and let go when the scan ends. Needs
//! `CHANGE_WIFI_MULTICAST_STATE` in the manifest.

use std::sync::Mutex;

use jni::objects::{GlobalRef, JObject, JValue};
use jni::JavaVM;

static LOCK: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// Hold (`true`) or release (`false`) the lock. Failures are logged and
/// otherwise ignored: without the lock the TCP sweep still works, only the
/// mDNS half goes quiet.
pub fn multicast_lock(hold: bool) {
    if let Err(error) = set(hold) {
        tracing::warn!(%error, hold, "multicast lock");
    }
}

fn set(hold: bool) -> Result<(), String> {
    let mut slot = LOCK.lock().map_err(|_| "lock poisoned")?;
    let ctx = ndk_context::android_context();
    // SAFETY: `ndk-context` hands out the process's JavaVM pointer, which
    // Tauri set at start and which lives as long as the process.
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| e.to_string())?;
    let mut env = vm.attach_current_thread().map_err(|e| e.to_string())?;
    if !hold {
        if let Some(lock) = slot.take() {
            env.call_method(lock.as_obj(), "release", "()V", &[])
                .map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    if slot.is_some() {
        return Ok(());
    }
    // SAFETY: the context pointer is the activity Tauri registered, a live
    // global reference for the life of the process.
    let context = unsafe { JObject::from_raw(ctx.context().cast()) };
    let name = env.new_string("wifi").map_err(|e| e.to_string())?;
    let wifi = env
        .call_method(
            &context,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;",
            &[JValue::Object(&name)],
        )
        .and_then(|v| v.l())
        .map_err(|e| e.to_string())?;
    if wifi.is_null() {
        return Err("no Wi-Fi service".into());
    }
    let tag = env
        .new_string("DeskVNC discovery")
        .map_err(|e| e.to_string())?;
    let lock = env
        .call_method(
            &wifi,
            "createMulticastLock",
            "(Ljava/lang/String;)Landroid/net/wifi/WifiManager$MulticastLock;",
            &[JValue::Object(&tag)],
        )
        .and_then(|v| v.l())
        .map_err(|e| e.to_string())?;
    env.call_method(&lock, "setReferenceCounted", "(Z)V", &[JValue::Bool(0)])
        .map_err(|e| e.to_string())?;
    env.call_method(&lock, "acquire", "()V", &[])
        .map_err(|e| e.to_string())?;
    *slot = Some(env.new_global_ref(lock).map_err(|e| e.to_string())?);
    // `context` is borrowed from ndk-context, not ours to delete.
    std::mem::forget(context);
    Ok(())
}
