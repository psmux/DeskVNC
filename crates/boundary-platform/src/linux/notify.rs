//! Desktop notifications over D-Bus, through org.freedesktop.Notifications.
//!
//! notify-send can show a notification but not take it down again, and
//! GNOME keeps a critical one on screen until somebody closes it by hand, so
//! a question answered in the window stayed asked in the corner. Here the
//! notification lives on its own thread, which closes it by the ID the
//! server gave it once the [`Notification`] is dropped.
use ashpd::zbus;
use ashpd::zvariant::Value;
use std::collections::HashMap;
use std::sync::mpsc;

const SERVICE: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

/// A notification on screen. Dropping it takes it down.
pub struct Notification {
    _shown: mpsc::Sender<()>,
}

/// Show a notification that stays until dropped. `app` names the .desktop
/// file, so the desktop shows the app's own name and icon beside it. With no
/// session bus or notification server nothing shows, and `None` only when
/// the thread could not start.
pub fn notify(app: &str, name: &str, summary: &str, body: &str) -> Option<Notification> {
    let (shown, dropped) = mpsc::channel::<()>();
    let (app, name, summary, body) = (
        app.to_owned(),
        name.to_owned(),
        summary.to_owned(),
        body.to_owned(),
    );
    std::thread::Builder::new()
        .name("notification".into())
        .spawn(move || {
            let _ = async_io::block_on(async {
                let bus = zbus::Connection::session().await?;
                let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
                // Critical: the person has a minute to answer, so it must
                // not slide away on its own.
                hints.insert("urgency", Value::U8(2));
                hints.insert("desktop-entry", Value::from(app.as_str()));
                let reply = bus
                    .call_method(
                        Some(SERVICE),
                        PATH,
                        Some(SERVICE),
                        "Notify",
                        &(
                            name.as_str(),
                            0u32,
                            app.as_str(),
                            summary.as_str(),
                            body.as_str(),
                            Vec::<&str>::new(),
                            hints,
                            -1i32,
                        ),
                    )
                    .await?;
                let id: u32 = reply.body().deserialize()?;
                // Waits for the Notification to be dropped; this thread is
                // its own, so blocking here holds up nothing else.
                let _ = dropped.recv();
                bus.call_method(Some(SERVICE), PATH, Some(SERVICE), "CloseNotification", &id)
                    .await?;
                Ok::<_, zbus::Error>(())
            });
        })
        .ok()?;
    Some(Notification { _shown: shown })
}
