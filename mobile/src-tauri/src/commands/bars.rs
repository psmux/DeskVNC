//! The colour of the status bar icons on iOS.
//!
//! tao's view controller does not override `preferredStatusBarStyle`, so iOS
//! uses the default style, which follows the phone's dark mode: dark icons on
//! a phone in light mode, over the session's black stage as well. The page
//! knows what it draws under the bar and says which icons it wants
//! (`ui/src/lib/systemBars.ts`); this gives the view controller an override
//! that answers with that, and asks iOS to look again.
//!
//! Android does the same through MainActivity's `DeskVNCSystemBars` bridge,
//! so the command does nothing there or in a desktop check build.

use tauri::AppHandle;

/// `icons` is `"light"` (for a dark backdrop) or `"dark"` (for a light one).
#[tauri::command]
pub async fn system_bars(app: AppHandle, icons: String) -> Result<(), String> {
    let light = match icons.as_str() {
        "light" => true,
        "dark" => false,
        other => return Err(format!("No such icon colour: {other}")),
    };
    apply(&app, light)
}

#[cfg(target_os = "ios")]
fn apply(app: &AppHandle, light: bool) -> Result<(), String> {
    use tauri::Manager;
    let window = app.get_webview_window("main").ok_or("The window is gone")?;
    // UIKit work belongs on the main thread, where with_webview runs this.
    window
        .with_webview(move |webview| unsafe { ios::apply(webview.view_controller().cast(), light) })
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "ios"))]
fn apply(_app: &AppHandle, _light: bool) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "ios")]
mod ios {
    use std::sync::atomic::{AtomicIsize, Ordering};

    use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
    use objc2::{msg_send, sel};

    // UIStatusBarStyle: 0 follows dark mode, 1 is light content, 3 dark content.
    const LIGHT_CONTENT: isize = 1;
    const DARK_CONTENT: isize = 3;
    static STYLE: AtomicIsize = AtomicIsize::new(0);

    extern "C-unwind" fn preferred_status_bar_style(_this: *mut AnyObject, _cmd: Sel) -> isize {
        STYLE.load(Ordering::Relaxed)
    }

    /// # Safety
    /// `view_controller` is the window's UIViewController, or null, and this
    /// runs on the main thread.
    pub unsafe fn apply(view_controller: *mut AnyObject, light: bool) {
        STYLE.store(
            if light { LIGHT_CONTENT } else { DARK_CONTENT },
            Ordering::Relaxed,
        );
        let Some(vc) = (unsafe { view_controller.as_ref() }) else {
            return;
        };
        let class: *const AnyClass = vc.class();
        let imp: Imp = unsafe {
            std::mem::transmute::<extern "C-unwind" fn(*mut AnyObject, Sel) -> isize, Imp>(
                preferred_status_bar_style,
            )
        };
        // The first call adds the override to tao's view controller class;
        // later ones find it there, get false back, and change nothing.
        unsafe {
            objc2::ffi::class_addMethod(
                class as *mut AnyClass,
                sel!(preferredStatusBarStyle),
                imp,
                c"q@:".as_ptr(),
            );
            let _: () = msg_send![vc, setNeedsStatusBarAppearanceUpdate];
        }
    }
}
