//! What the Mac's media path is doing, as reported by its answer.

/// The state of the media path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MediaState {
    /// Canvas advertised in the media answer, not measured decoder output.
    pub canvas_width: u32,
    pub canvas_height: u32,
    /// The size of the Mac's desktop, in points.
    pub desktop_width: u32,
    pub desktop_height: u32,
    /// Pixel geometry from the latest display layout.
    pub layout_width: u32,
    pub layout_height: u32,
    /// Latest requested pixel geometry; not confirmation of application.
    pub requested_width: u32,
    pub requested_height: u32,
    /// How many tile streams the video is split into.
    pub tiles: u32,
    /// Access units assembled by the backend, not decoded/presented frames.
    pub pictures: u64,
    /// The number of packets that went missing on the way.
    pub lost: u64,
    /// The number of pictures dropped because the client could not keep up.
    pub dropped: u64,
    /// The number of times a fresh picture was asked for.
    pub recoveries: u64,
    /// The number of feedback packets sent to the Mac.
    pub requests: u64,
    /// Video datagrams read from the Mac.
    pub packets: u64,
    /// Bytes of those datagrams: the stream's bandwidth, not the link's.
    pub bytes: u64,
    /// Times the stream went quiet for longer than the stall timeout. A
    /// stalled stream is what a person calls "frozen", whatever the cause.
    pub stalls: u64,
    /// Variation in the spacing between pictures, in milliseconds.
    pub jitter_ms: u32,
    /// Smoothed time from the user's input to the picture that answers it.
    /// Zero until the person has used the session.
    pub input_latency_ms: u32,
    /// The slowest of those answers, so one freeze stays visible.
    pub input_worst_ms: u32,
}

impl MediaState {
    /// Whether the Mac is sending a picture that can be shown.
    pub fn is_streaming(&self) -> bool {
        self.canvas_width > 0 && self.canvas_height > 0 && self.pictures > 0
    }
}
