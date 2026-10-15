//! The icon in the menu bar (macOS) or the notification area (Windows).
//!
//! Started at sign in for unattended access, the app has no business on
//! anybody's screen. It lives here instead: the icon says whether a helper is
//! connected, and its menu brings the window back or quits. Linux has no tray
//! that works without GTK, so there the window stays minimized as before.

/// What the person picked from the icon's menu. Never built where there is
/// no tray.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
pub enum Action {
    Show,
    Quit,
}

#[cfg(any(target_os = "macos", windows))]
mod imp {
    use super::Action;
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

    pub struct Tray {
        icon: TrayIcon,
        status: MenuItem,
        show: MenuItem,
        quit: MenuItem,
        said: String,
    }

    impl Tray {
        /// `None` when the system would not take an icon; the window is then
        /// the only way in, as it was before there was a tray.
        pub fn new() -> Option<Self> {
            let status = MenuItem::new("DeskVNC Support", false, None);
            let show = MenuItem::new("Show DeskVNC Support", true, None);
            let quit = MenuItem::new("Quit DeskVNC Support", true, None);
            let menu = Menu::new();
            menu.append_items(&[&status, &PredefinedMenuItem::separator(), &show, &quit])
                .ok()?;
            let icon = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("DeskVNC Support")
                .with_icon(picture()?)
                // macOS draws a template icon in the menu bar's own colour.
                .with_icon_as_template(cfg!(target_os = "macos"))
                .build()
                .ok()?;
            Some(Self {
                icon,
                status,
                show,
                quit,
                said: String::new(),
            })
        }

        /// The first line of the menu and the tooltip.
        pub fn say(&mut self, text: &str) {
            if self.said == text {
                return;
            }
            self.said = text.to_owned();
            self.status.set_text(text);
            let _ = self
                .icon
                .set_tooltip(Some(format!("DeskVNC Support: {text}")));
        }

        pub fn poll(&self) -> Option<Action> {
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == *self.show.id() {
                    return Some(Action::Show);
                }
                if event.id == *self.quit.id() {
                    return Some(Action::Quit);
                }
            }
            None
        }
    }

    /// A small monitor on its stand. Black for the macOS template, blue on
    /// Windows, where the taskbar is usually dark.
    fn picture() -> Option<Icon> {
        const SIZE: u32 = 32;
        let colour: [u8; 3] = if cfg!(target_os = "macos") {
            [0, 0, 0]
        } else {
            [0x3b, 0x82, 0xf6]
        };
        let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
        let mut fill = |x0: u32, y0: u32, x1: u32, y1: u32| {
            for y in y0..y1 {
                for x in x0..x1 {
                    let i = ((y * SIZE + x) * 4) as usize;
                    rgba[i..i + 3].copy_from_slice(&colour);
                    rgba[i + 3] = 255;
                }
            }
        };
        // The screen's frame.
        fill(3, 5, 29, 8);
        fill(3, 20, 29, 23);
        fill(3, 5, 6, 23);
        fill(26, 5, 29, 23);
        // The stand and its foot.
        fill(14, 23, 18, 26);
        fill(9, 26, 23, 28);
        Icon::from_rgba(rgba, SIZE, SIZE).ok()
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use super::Action;

    pub struct Tray;

    impl Tray {
        pub fn new() -> Option<Self> {
            None
        }
        pub fn say(&mut self, _: &str) {}
        pub fn poll(&self) -> Option<Action> {
            None
        }
    }
}

pub use imp::Tray;
