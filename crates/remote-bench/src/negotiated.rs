//! What each protocol actually ran in, so a row can never claim a mode it
//! did not use. RDP's graphics codec comes from rdp-core's traces; VNC's
//! encoding from the driver's stats; every protocol's rectangle kinds from
//! the framebuffer.
use std::collections::BTreeMap;
use std::sync::Mutex;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, filter::Targets};

static SEEN: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

#[derive(Default)]
struct Fields {
    message: String,
    codec: Option<u64>,
    version: Option<u64>,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "codec" => self.codec = Some(value),
            "version" => self.version = Some(value),
            _ => {}
        }
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_u64(field, value as u64);
    }
}

struct Recorder;

impl<S: tracing::Subscriber> Layer<S> for Recorder {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut f = Fields::default();
        event.record(&mut f);
        let key = match (f.message.as_str(), f.codec, f.version) {
            ("wire to surface", Some(codec), _) => format!("egfx codec {}", egfx_codec(codec)),
            ("the graphics capabilities were confirmed", _, Some(v)) => {
                format!("egfx capability set 0x{v:05x} confirmed")
            }
            _ => return,
        };
        *SEEN.lock().unwrap().entry(key).or_default() += 1;
    }
}

/// Listen to the graphics channel's traces and nothing else, so the hot
/// paths of every other crate stay as cheap as in the viewer.
pub fn install() {
    let targets = Targets::new().with_target("rdp_core::channels::egfx", tracing::Level::TRACE);
    // RUST_LOG, when set, also prints the drivers' own logs, to see why a
    // connection did not come up.
    let log = std::env::var("RUST_LOG").ok().map(|_| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(tracing_subscriber::EnvFilter::from_default_env())
    });
    let _ = tracing_subscriber::registry()
        .with(Recorder.with_filter(targets))
        .with(log)
        .try_init();
}

fn egfx_codec(id: u64) -> String {
    let name = match id {
        0x0000 => "uncompressed",
        0x0003 => "RemoteFX",
        0x0008 => "ClearCodec",
        0x0009 => "RemoteFX Progressive",
        0x000a => "Planar",
        0x000b => "AVC420 (H.264)",
        0x000c => "Alpha",
        0x000e => "AVC444 (H.264)",
        0x000f => "AVC444v2 (H.264)",
        _ => "unknown",
    };
    format!("0x{id:04x} {name}")
}

fn vnc_encoding(id: i32) -> String {
    let name = match id {
        0 => "Raw",
        1 => "CopyRect",
        2 => "RRE",
        5 => "Hextile",
        6 => "zlib",
        7 => "Tight",
        16 => "ZRLE",
        50 => "Open H.264",
        _ => "other",
    };
    format!("{id} {name}")
}

/// One line per thing seen, with how often.
pub fn describe(
    protocol: &str,
    local: bool,
    encodings: &BTreeMap<i32, u64>,
    kinds: &BTreeMap<String, u64>,
) -> Vec<String> {
    let mut out = Vec::new();
    if local {
        // Another client did the talking, so this process saw no protocol at
        // all; what the server chose belongs in the run's note.
        out.push("another client's display, read whole; see the note for the codec".into());
        return out;
    }
    match protocol {
        "rdp" => {
            let seen = std::mem::take(&mut *SEEN.lock().unwrap());
            if seen.keys().all(|k| !k.contains("confirmed")) {
                out.push("no graphics pipeline: legacy bitmap updates".into());
            }
            out.extend(seen.into_iter().map(|(k, n)| format!("{k} x{n}")));
        }
        "vnc" => out.extend(
            encodings
                .iter()
                .map(|(e, n)| format!("encoding {} in {n} stats ticks", vnc_encoding(*e))),
        ),
        "boundary" => {
            out.push("the Boundary driver hands over decoded pixels; h264 rects mean video".into())
        }
        _ => {}
    }
    out.extend(kinds.iter().map(|(k, n)| format!("{k} rects x{n}")));
    out
}
