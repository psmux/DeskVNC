//! Audio output (MS-RDPEA, PRDRDP/05 §5.6, PRDRDP/12 §3.10).
//!
//! Behind the `audio` cargo feature, which is off by default.
//!
//! # Where this runs, and where playback does not
//!
//! MS-RDPEA 1.3.1 lets the protocol run over the static channel `rdpsnd` or
//! over the dynamic channel [`AUDIO_CHANNEL_NAME`]. This is the dynamic form:
//! the PDUs are identical, and it costs no entry in `TS_UD_CS_NET`, so it
//! sits beside the graphics and display control channels in
//! [`crate::channels::dvc`] instead of being a third static channel with its
//! own reassembler.
//!
//! **Nothing here plays anything.** Decoded PCM leaves as
//! `remote_core::SessionEvent::Audio`, and where it is played is the shell's
//! decision, which PRDRDP/00 R24 records as the owner's to take: `cpal` in
//! `src-tauri` or WebAudio in the webview. Either answer is a shell change
//! and not a protocol change, which is the whole reason this module ends at
//! an event.
//!
//! # PCM only, deliberately
//!
//! The client answers the format negotiation with `WAVE_FORMAT_PCM` (0x0001)
//! at sixteen bits per sample and nothing else. Everything else a server
//! offers is dropped from the reply:
//!
//! * ADPCM, A-law, mu-law and GSM 6.10 are small decoders we could write and
//!   all are worse than PCM in quality for a bandwidth saving that no longer
//!   matters.
//! * MP3 and AAC are what a modern Windows server would rather use, and under
//!   AGENT_BRIEF D3 accepting either means writing a transform and Huffman
//!   decoder here and fuzzing it as hard as everything else in this
//!   workspace. Not in phase 2.
//! * Opus is not a Microsoft assignment at all. It is a FreeRDP extension,
//!   and offering it to a Windows server is exactly the case the interop note
//!   below warns about.
//!
//! Stereo 48 kHz sixteen bit PCM is 1.536 Mbit/s, which is a real cost on a
//! slow link. The settings copy has to say so.
//!
//! **[observed]** Windows servers misbehave when the client's format reply
//! contains formats the server did not offer, or formats it does not
//! recognise; FreeRDP and IronRDP both carry a note to that effect and the
//! second names Opus as the case that breaks it. The rule that follows is
//! strict and is what [`Rdpsnd::formats`] implements: reply with a subset of
//! what was offered, in the order it was offered, with `wFormatNo` indices
//! that address our own reply list.
//!
//! # Allocation per packet
//!
//! One, and it is the `Vec<i16>` inside the `AudioPacket` the event owns. It
//! is sized exactly once with `with_capacity` and moved out, never copied.
//! Everything else the channel needs is allocated once per session and reused
//! for the life of it: [`Rdpsnd::wave`] holds the audio bytes of a WaveInfo
//! and Wave pair, [`Rdpsnd::formats_accepted`] is the negotiated list, and
//! every reply is encoded into a buffer [`ReplyBuf`] lends out and takes back
//! (`crate::channels::dvc::ReplyBuf`). At fifty packets a second, which is
//! what a 20 ms block at 48 kHz comes to, a per packet buffer allocation
//! anywhere else in this path would be three thousand allocations a minute
//! for nothing.

use rdp_pdu::io::{Reader, Writer};
use remote_core::{AudioPacket, SessionEvent};

use crate::channels::dvc::ReplyBuf;
use crate::error::{RdpError, Result};

/// The dynamic channel's name (MS-RDPEA 1.3.1).
pub const AUDIO_CHANNEL_NAME: &str = "AUDIO_PLAYBACK_DVC";

/// `SNDPROLOG` is four bytes and `BodySize` does not count it
/// (MS-RDPEA 2.2.1).
const PROLOG_LEN: usize = 4;

/// Message types (MS-RDPEA 2.2.1).
mod msg {
    /// `SNDC_CLOSE`, server to client.
    pub const CLOSE: u8 = 0x01;
    /// `SNDC_WAVE`, the WaveInfo PDU, server to client.
    pub const WAVE: u8 = 0x02;
    /// `SNDC_WAVECONFIRM`, client to server.
    pub const WAVE_CONFIRM: u8 = 0x05;
    /// `SNDC_TRAINING`, both directions.
    pub const TRAINING: u8 = 0x06;
    /// `SNDC_FORMATS`, both directions.
    pub const FORMATS: u8 = 0x07;
    /// `SNDC_QUALITYMODE`, client to server.
    pub const QUALITY_MODE: u8 = 0x0c;
    /// `SNDC_WAVE2`, server to client.
    pub const WAVE2: u8 = 0x0d;
}

/// `WAVE_FORMAT_PCM`, the only `wFormatTag` this build accepts.
const WAVE_FORMAT_PCM: u16 = 0x0001;

/// The highest `wVersion` we implement (MS-RDPEA 2.2.2.1). Version 6 is what
/// gates Wave2 and the quality mode PDU, both of which this module sends and
/// accepts.
const VERSION: u16 = 6;

/// `QualityMode = HIGH_QUALITY` (MS-RDPEA 2.2.2.3), which asks the server not
/// to degrade the stream on its own initiative.
const HIGH_QUALITY: u16 = 0x0002;

/// The sample rates we accept, in the order we prefer them.
const RATES: [u32; 2] = [48_000, 44_100];

/// Bits per sample. Eight bit PCM is accepted by no modern server and would
/// need its own unsigned to signed conversion, so sixteen is the whole set.
const BITS: u16 = 16;

/// The largest wave block we will assemble, in bytes.
///
/// A block is one buffer of audio, and MS-RDPEA gives it no explicit bound.
/// Two seconds of stereo 48 kHz sixteen bit PCM is 384,000 bytes, so a
/// mebibyte is five times the largest legitimate block and a server claiming
/// more is not sending audio.
const MAX_WAVE_BYTES: usize = 1024 * 1024;

/// One `AUDIO_FORMAT`, which is a `WAVEFORMATEX` (MS-RDPEA 2.2.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormat {
    /// `wFormatTag`.
    pub format_tag: u16,
    /// `nChannels`.
    pub channels: u16,
    /// `nSamplesPerSec`.
    pub sample_rate: u32,
    /// `nAvgBytesPerSec`.
    pub avg_bytes_per_sec: u32,
    /// `nBlockAlign`.
    pub block_align: u16,
    /// `wBitsPerSample`.
    pub bits_per_sample: u16,
}

impl AudioFormat {
    /// Whether this is a format the client will decode.
    ///
    /// Sixteen bit PCM, one or two channels, at one of [`RATES`]. Everything
    /// else is a codec we do not have or a sample width we would have to
    /// convert.
    #[must_use]
    pub fn acceptable(&self) -> bool {
        self.format_tag == WAVE_FORMAT_PCM
            && self.bits_per_sample == BITS
            && (self.channels == 1 || self.channels == 2)
            && RATES.contains(&self.sample_rate)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        const NAME: &str = "AUDIO_FORMAT";
        let format = Self {
            format_tag: r.u16(NAME)?,
            channels: r.u16(NAME)?,
            sample_rate: r.u32(NAME)?,
            avg_bytes_per_sec: r.u32(NAME)?,
            block_align: r.u16(NAME)?,
            bits_per_sample: r.u16(NAME)?,
        };
        // `cbSize` extra bytes, which a `WAVEFORMATEX` may carry and a plain
        // PCM one never does. Skipped by its own length, so an extended
        // format does not desynchronise the list behind it.
        let extra = r.u16(NAME)? as usize;
        r.skip(extra, NAME)?;
        Ok(format)
    }

    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.format_tag);
        w.u16(self.channels);
        w.u32(self.sample_rate);
        w.u32(self.avg_bytes_per_sec);
        w.u16(self.block_align);
        w.u16(self.bits_per_sample);
        // `cbSize` of zero: a plain PCM format carries no extra bytes.
        w.u16(0);
    }
}

/// The audio channel's state.
#[derive(Debug, Default)]
pub struct Rdpsnd {
    /// The formats we told the server we accept, in the order we listed them.
    /// `wFormatNo` in every wave PDU indexes this list.
    formats_accepted: Vec<AudioFormat>,
    /// The audio bytes of a block being assembled from a WaveInfo and Wave
    /// pair. Allocated once and reused for the life of the session.
    wave: Vec<u8>,
    /// The block we are waiting for the body of: its number, its timestamp,
    /// its format index and how many bytes are still to come.
    ///
    /// MS-RDPEA 2.2.3.4 is the one genuinely awkward thing in this protocol:
    /// the Wave PDU has no `SNDPROLOG` of its own, so a parser that is not in
    /// this state would read four bytes of padding as a message header.
    expecting: Option<PendingWave>,
    /// Whether the format exchange has happened. A wave PDU before it is a
    /// server that got the order wrong (MS-RDPEA 1.3.2).
    negotiated: bool,
}

/// The half of a wave block a WaveInfo PDU announced.
#[derive(Debug, Clone, Copy)]
struct PendingWave {
    timestamp: u16,
    format_no: u16,
    block_no: u8,
    /// How many more bytes of audio the Wave PDU carries after its four bytes
    /// of padding.
    remaining: usize,
}

impl Rdpsnd {
    /// A channel with nothing negotiated.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The formats the client told the server it accepts.
    #[must_use]
    pub fn accepted(&self) -> &[AudioFormat] {
        &self.formats_accepted
    }

    /// Forget everything but the buffers.
    ///
    /// A deactivation tears the share down and the server reopens its dynamic
    /// channels on the new one, so the format exchange happens again
    /// (PRDRDP/05 §5.1 rule 6).
    pub fn reset(&mut self) {
        self.formats_accepted.clear();
        self.wave.clear();
        self.expecting = None;
        self.negotiated = false;
    }

    /// One complete message from the server.
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] when the PDU did not parse, and
    /// [`RdpError::Protocol`] for a message that parsed and then said
    /// something the state machine cannot act on, such as a wave body with no
    /// WaveInfo in front of it.
    pub fn message(
        &mut self,
        message: &[u8],
        events: &mut Vec<SessionEvent>,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        // The body of a block announced by a WaveInfo has no header of its
        // own, so it is recognised by state and not by looking
        // (MS-RDPEA 2.2.3.4).
        if let Some(pending) = self.expecting.take() {
            return self.wave_body(pending, message, events, replies);
        }

        const NAME: &str = "SNDPROLOG";
        let mut r = Reader::new(message);
        let msg_type = r.u8(NAME)?;
        // `bPad`.
        r.skip(1, NAME)?;
        let body_size = r.u16(NAME)? as usize;
        let body = r.rest();
        if body.len() < body_size {
            return Err(RdpError::Pdu {
                structure: NAME,
                message: format!(
                    "BodySize is {body_size} for a {} byte body (MS-RDPEA 2.2.1)",
                    body.len()
                ),
            });
        }
        let body = &body[..body_size];

        match msg_type {
            msg::FORMATS => self.formats(body, replies),
            msg::TRAINING => self.training(body, replies),
            msg::WAVE => self.wave_info(body, body_size, events, replies),
            msg::WAVE2 => self.wave2(body, events, replies),
            msg::CLOSE => {
                // The stream is finished. Dropping what is half assembled is
                // the part that matters: a client that keeps it plays a
                // fragment of a session that no longer exists after the
                // window has closed (PRDRDP/05 §5.6).
                tracing::debug!("the server closed the audio stream");
                self.wave.clear();
                self.expecting = None;
                Ok(())
            }
            other => {
                // `SNDC_CRYPTKEY`, `SNDC_WAVEENCRYPT` and the two UDP wave
                // types belong to standard RDP security and the UDP path, and
                // this client negotiates neither. Every message is length
                // prefixed, so skipping one cannot desynchronise the channel.
                tracing::debug!(msg_type = other, "an rdpsnd pdu this build ignores");
                Ok(())
            }
        }
    }

    /// The Server Audio Formats and Version PDU (MS-RDPEA 2.2.2.1), answered
    /// with our own (2.2.2.2) and then the quality mode (2.2.2.3).
    fn formats(&mut self, body: &[u8], replies: &mut ReplyBuf) -> Result<()> {
        const NAME: &str = "Server Audio Formats and Version PDU";
        let mut r = Reader::new(body);
        // `dwFlags`, `dwVolume`, `dwPitch`, `wDGramPort`. None of the four
        // changes what we send: the volume and pitch capabilities gate PDUs
        // this build never sends, and the datagram port is the UDP path.
        r.skip(4 + 4 + 4 + 2, NAME)?;
        let count = r.u16(NAME)?;
        // `cLastBlockConfirmed`, which matters only to a client resuming a
        // stream, and `wVersion`.
        r.skip(1, NAME)?;
        let server_version = r.u16(NAME)?;
        r.skip(1, NAME)?;

        self.formats_accepted.clear();
        for _ in 0..count {
            let format = AudioFormat::read(&mut r)?;
            if format.acceptable() {
                self.formats_accepted.push(format);
            }
        }
        tracing::info!(
            offered = count,
            accepted = self.formats_accepted.len(),
            server_version,
            "the audio format exchange"
        );

        let version = server_version.min(VERSION);
        // A reply with no formats is legal and says "I will take nothing",
        // which is the honest answer to a server that offers only codecs we
        // do not have. The session carries on without audio.
        replies.emit(|buf| {
            let mut w = Writer::new(buf);
            w.u8(msg::FORMATS);
            w.u8(0);
            let body_size = 20 + self.formats_accepted.len() * 18;
            w.u16(u16::try_from(body_size).map_err(|_| RdpError::Pdu {
                structure: "Client Audio Formats and Version PDU",
                message: "the accepted format list is longer than BodySize can carry".to_owned(),
            })?);
            // `dwFlags`: `TSSNDCAPS_ALIVE`, which is the only bit a client
            // sets (MS-RDPEA 2.2.2.2).
            w.u32(0x0000_0001);
            // `dwVolume`: both channels at full scale. The server scales at
            // the source when it can, which saves bandwidth over scaling
            // locally.
            w.u32(0xffff_ffff);
            // `dwPitch`, which we never change.
            w.u32(0);
            // `wDGramPort`: no UDP.
            w.u16(0);
            w.u16(u16::try_from(self.formats_accepted.len()).unwrap_or(u16::MAX));
            // `cLastBlockConfirmed`.
            w.u8(0);
            w.u16(version);
            // `bPad`.
            w.u8(0);
            for format in &self.formats_accepted {
                format.write(&mut w);
            }
            Ok(())
        })?;

        // MS-RDPEA 2.2.2.3, sent immediately after the formats.
        replies.emit(|buf| {
            let mut w = Writer::new(buf);
            w.u8(msg::QUALITY_MODE);
            w.u8(0);
            w.u16(4);
            w.u16(HIGH_QUALITY);
            w.u16(0);
            Ok(())
        })?;
        self.negotiated = true;
        Ok(())
    }

    /// The Training PDU (MS-RDPEA 2.2.2.4), answered with a Training Confirm
    /// (2.2.2.5).
    ///
    /// Two rules, and both are about the measurement being the point: answer
    /// before any other work, and echo the timestamp unmodified. Substituting
    /// our own clock is the mistake that makes a server think the link is
    /// instantaneous and then underrun.
    fn training(&mut self, body: &[u8], replies: &mut ReplyBuf) -> Result<()> {
        const NAME: &str = "Training PDU";
        let mut r = Reader::new(body);
        let timestamp = r.u16(NAME)?;
        let pack_size = r.u16(NAME)?;
        replies.emit(|buf| {
            let mut w = Writer::new(buf);
            w.u8(msg::TRAINING);
            w.u8(0);
            w.u16(4);
            w.u16(timestamp);
            w.u16(pack_size);
            Ok(())
        })
    }

    /// The WaveInfo PDU (MS-RDPEA 2.2.3.3): the block's header and the first
    /// four bytes of its audio.
    ///
    /// `BodySize` counts the audio data plus the eight byte header, so the
    /// Wave PDU that follows carries `BodySize - 12` more bytes behind its
    /// four bytes of padding. A client that forgets the four bytes in here
    /// drops the first samples of every block, which is the classic
    /// MS-RDPEA bug.
    fn wave_info(
        &mut self,
        body: &[u8],
        body_size: usize,
        events: &mut Vec<SessionEvent>,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        const NAME: &str = "WaveInfo PDU";
        let mut r = Reader::new(body);
        let timestamp = r.u16(NAME)?;
        let format_no = r.u16(NAME)?;
        let block_no = r.u8(NAME)?;
        r.skip(3, NAME)?;
        let first = r.rest();

        // BodySize = audio length + 8, and four of those bytes are here.
        let audio_len = body_size.saturating_sub(8);
        if audio_len > MAX_WAVE_BYTES {
            return Err(RdpError::Protocol(format!(
                "the server announced a {audio_len} byte wave block, past the \
                 {MAX_WAVE_BYTES} byte cap this client will assemble (MS-RDPEA 2.2.3.3)"
            )));
        }
        self.wave.clear();
        self.wave.reserve(audio_len);
        self.wave.extend_from_slice(first);
        let remaining = audio_len.saturating_sub(first.len());
        if remaining == 0 {
            // A block whose audio fits in the four bytes the WaveInfo
            // carries. Legal, and there is no Wave PDU to wait for.
            let pending = PendingWave {
                timestamp,
                format_no,
                block_no,
                remaining: 0,
            };
            return self.finish_block(pending, events, replies);
        }
        self.expecting = Some(PendingWave {
            timestamp,
            format_no,
            block_no,
            remaining,
        });
        Ok(())
    }

    /// The Wave PDU (MS-RDPEA 2.2.3.4): four bytes of padding and the rest of
    /// the block, with no `SNDPROLOG` of its own.
    fn wave_body(
        &mut self,
        pending: PendingWave,
        message: &[u8],
        events: &mut Vec<SessionEvent>,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        let Some(rest) = message.get(PROLOG_LEN..) else {
            return Err(RdpError::Protocol(
                "a wave body shorter than its four bytes of padding \
                 (MS-RDPEA 2.2.3.4)"
                    .to_owned(),
            ));
        };
        if rest.len() < pending.remaining {
            return Err(RdpError::Protocol(format!(
                "the wave body carried {} bytes of the {} the WaveInfo announced \
                 (MS-RDPEA 2.2.3.4)",
                rest.len(),
                pending.remaining
            )));
        }
        self.wave.extend_from_slice(&rest[..pending.remaining]);
        self.finish_block(pending, events, replies)
    }

    /// The Wave2 PDU (MS-RDPEA 2.2.3.10): the header and all of the audio in
    /// one message, which is what every current server sends.
    ///
    /// Both forms are accepted unconditionally rather than chosen by the
    /// version fields, because being right about which server build changed
    /// is more expensive than accepting both.
    fn wave2(
        &mut self,
        body: &[u8],
        events: &mut Vec<SessionEvent>,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        const NAME: &str = "Wave2 PDU";
        let mut r = Reader::new(body);
        let timestamp = r.u16(NAME)?;
        let format_no = r.u16(NAME)?;
        let block_no = r.u8(NAME)?;
        r.skip(3, NAME)?;
        let audio_timestamp = r.u32(NAME)?;
        let audio = r.rest();
        if audio.len() > MAX_WAVE_BYTES {
            return Err(RdpError::Protocol(format!(
                "a {} byte wave2 block, past the {MAX_WAVE_BYTES} byte cap \
                 (MS-RDPEA 2.2.3.10)",
                audio.len()
            )));
        }
        self.wave.clear();
        self.wave.extend_from_slice(audio);
        self.emit_block(
            PendingWave {
                timestamp,
                format_no,
                block_no,
                remaining: 0,
            },
            audio_timestamp,
            events,
        )?;
        self.confirm(timestamp, block_no, replies)
    }

    /// A block is complete: hand it over and confirm it.
    fn finish_block(
        &mut self,
        pending: PendingWave,
        events: &mut Vec<SessionEvent>,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        // The old form carries no server clock of its own, so the block's own
        // timestamp stands in. It is protocol relative either way
        // (`remote_core::AudioPacket::timestamp_ms`).
        self.emit_block(pending, u32::from(pending.timestamp), events)?;
        self.confirm(pending.timestamp, pending.block_no, replies)
    }

    /// Turn the assembled bytes into PCM and emit them.
    fn emit_block(
        &mut self,
        pending: PendingWave,
        audio_timestamp: u32,
        events: &mut Vec<SessionEvent>,
    ) -> Result<()> {
        let Some(format) = self
            .formats_accepted
            .get(pending.format_no as usize)
            .copied()
        else {
            // A `wFormatNo` outside the list we sent. The server is indexing
            // something we never offered, so we cannot know what the bytes
            // are and playing them as PCM would be noise.
            return Err(RdpError::Protocol(format!(
                "the server sent wave block {} with wFormatNo {}, and this client \
                 offered {} formats (MS-RDPEA 2.2.3.3)",
                pending.block_no,
                pending.format_no,
                self.formats_accepted.len()
            )));
        };

        // The one allocation per packet, sized exactly. `AudioPacket` owns
        // its samples, so this buffer is moved into the event rather than
        // copied out of a pool (this module's header says why there is no
        // pool).
        let mut pcm = Vec::with_capacity(self.wave.len() / 2);
        // Bounds checked by construction, and `#![forbid(unsafe_code)]` means
        // this is a copy rather than a reinterpretation. An odd trailing byte
        // is dropped: it is half a sample and there is nothing to pair it
        // with.
        pcm.extend(
            self.wave
                .chunks_exact(2)
                .map(|pair| i16::from_le_bytes([pair[0], pair[1]])),
        );
        tracing::trace!(
            block = pending.block_no,
            samples = pcm.len(),
            rate = format.sample_rate,
            "an audio block"
        );
        events.push(SessionEvent::Audio(AudioPacket {
            pcm,
            sample_rate: format.sample_rate,
            channels: u8::try_from(format.channels).unwrap_or(2),
            timestamp_ms: audio_timestamp,
        }));
        self.wave.clear();
        Ok(())
    }

    /// The Wave Confirm PDU (MS-RDPEA 2.2.3.8).
    ///
    /// Sent when the block has been handed over, not when it has finished
    /// playing: the server measures its own round trip from this echo and
    /// uses it to decide how far ahead to buffer, and confirming on playback
    /// completion tells it the link is one buffer slower than it is.
    fn confirm(&mut self, timestamp: u16, block_no: u8, replies: &mut ReplyBuf) -> Result<()> {
        replies.emit(|buf| {
            let mut w = Writer::new(buf);
            w.u8(msg::WAVE_CONFIRM);
            w.u8(0);
            w.u16(4);
            w.u16(timestamp);
            w.u8(block_no);
            w.u8(0);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prolog(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u8(msg_type);
        w.u8(0);
        w.u16(u16::try_from(body.len()).expect("a short test body"));
        out.extend_from_slice(body);
        out
    }

    /// A Server Audio Formats and Version PDU offering `formats`.
    fn server_formats(formats: &[(u16, u16, u32, u16)]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u32(0x0000_0001); // dwFlags: TSSNDCAPS_ALIVE
        w.u32(0xffff_ffff); // dwVolume
        w.u32(0); // dwPitch
        w.u16(0); // wDGramPort
        w.u16(u16::try_from(formats.len()).unwrap());
        w.u8(0); // cLastBlockConfirmed
        w.u16(8); // wVersion, higher than ours
        w.u8(0); // bPad
        for (tag, channels, rate, bits) in formats {
            w.u16(*tag);
            w.u16(*channels);
            w.u32(*rate);
            w.u32(rate * u32::from(*channels) * u32::from(bits / 8));
            w.u16(*channels * (bits / 8));
            w.u16(*bits);
            w.u16(0); // cbSize
        }
        prolog(msg::FORMATS, &body)
    }

    /// Negotiate one stereo 48 kHz PCM format and clear the replies.
    fn negotiated() -> (Rdpsnd, ReplyBuf) {
        let mut snd = Rdpsnd::new();
        let mut replies = ReplyBuf::default();
        let mut events = Vec::new();
        snd.message(
            &server_formats(&[(WAVE_FORMAT_PCM, 2, 48_000, 16)]),
            &mut events,
            &mut replies,
        )
        .expect("formats");
        replies.take();
        (snd, replies)
    }

    /// The reply carries only formats the server offered, and only ones we
    /// can decode. Offering a server a format it did not name is the
    /// misbehaviour this module's header records.
    #[test]
    fn only_pcm_formats_the_server_offered_are_accepted() {
        let mut snd = Rdpsnd::new();
        let mut replies = ReplyBuf::default();
        let mut events = Vec::new();
        snd.message(
            &server_formats(&[
                (0x0055, 2, 48_000, 16),          // MP3
                (WAVE_FORMAT_PCM, 2, 48_000, 16), // accepted
                (0x0011, 2, 44_100, 4),           // DVI ADPCM
                (WAVE_FORMAT_PCM, 1, 44_100, 16), // accepted
                (WAVE_FORMAT_PCM, 2, 22_050, 16), // a rate we do not take
                (WAVE_FORMAT_PCM, 2, 48_000, 8),  // eight bit
                (0x704f, 2, 48_000, 16),          // Opus, never offered back
            ]),
            &mut events,
            &mut replies,
        )
        .expect("formats");

        assert_eq!(snd.accepted().len(), 2, "{:?}", snd.accepted());
        assert!(snd.accepted().iter().all(AudioFormat::acceptable));
        assert_eq!(snd.accepted()[0].sample_rate, 48_000);
        assert_eq!(snd.accepted()[1].sample_rate, 44_100);

        // The reply, and then the quality mode PDU behind it.
        let queued = replies.queued();
        assert_eq!(queued.len(), 2, "the formats, then the quality mode");
        assert_eq!(queued[0][0], msg::FORMATS);
        let mut r = Reader::new(&queued[0][PROLOG_LEN..]);
        r.skip(14, "reply").unwrap();
        assert_eq!(r.u16("count").unwrap(), 2, "the count matches the list");
        assert_eq!(r.u8("last block").unwrap(), 0);
        assert_eq!(
            r.u16("version").unwrap(),
            VERSION,
            "capped at what we speak"
        );

        assert_eq!(queued[1][0], msg::QUALITY_MODE);
        let mut r = Reader::new(&queued[1][PROLOG_LEN..]);
        assert_eq!(r.u16("quality").unwrap(), HIGH_QUALITY);
    }

    /// MS-RDPEA 2.2.2.5: the confirm echoes the timestamp and the pack size
    /// unmodified. Substituting our own clock makes the server think the link
    /// is instantaneous.
    #[test]
    fn a_training_pdu_is_echoed_immediately() {
        let (mut snd, mut replies) = negotiated();
        let mut events = Vec::new();
        let mut body = vec![0u8; 2 + 2 + 64];
        body[0..2].copy_from_slice(&0xbeef_u16.to_le_bytes());
        body[2..4].copy_from_slice(&64_u16.to_le_bytes());
        snd.message(&prolog(msg::TRAINING, &body), &mut events, &mut replies)
            .expect("training");

        let queued = replies.queued();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0][0], msg::TRAINING);
        let mut r = Reader::new(&queued[0][PROLOG_LEN..]);
        assert_eq!(r.u16("timestamp").unwrap(), 0xbeef, "echoed unmodified");
        assert_eq!(r.u16("pack size").unwrap(), 64);
        assert_eq!(
            queued[0].len(),
            PROLOG_LEN + 4,
            "the confirm carries no padding"
        );
    }

    /// The awkward pair: a WaveInfo carrying the first four bytes and a Wave
    /// PDU with no header carrying the rest. A client that drops the four
    /// bytes loses the first samples of every block.
    #[test]
    fn the_wave_info_and_wave_pair_keeps_the_first_four_bytes() {
        let (mut snd, mut replies) = negotiated();
        let mut events = Vec::new();

        // Eight samples, sixteen bytes, ascending so a lost prefix is visible.
        let audio: Vec<u8> = (0..8_i16).flat_map(i16::to_le_bytes).collect();
        assert_eq!(audio.len(), 16);

        let mut info = Vec::new();
        let mut w = Writer::new(&mut info);
        w.u16(0x1234); // wTimeStamp
        w.u16(0); // wFormatNo
        w.u8(7); // cBlockNo
        w.u8(0);
        w.u8(0);
        w.u8(0);
        info.extend_from_slice(&audio[..4]);
        // BodySize is the audio length plus eight (MS-RDPEA 2.2.3.3), which
        // is 24 here, and the body itself is only twelve bytes long.
        let mut pdu = Vec::new();
        let mut w = Writer::new(&mut pdu);
        w.u8(msg::WAVE);
        w.u8(0);
        w.u16(u16::try_from(audio.len() + 8).unwrap());
        pdu.extend_from_slice(&info);

        snd.message(&pdu, &mut events, &mut replies)
            .expect("wave info");
        assert!(events.is_empty(), "the block is not complete yet");
        assert!(replies.is_empty(), "and nothing is confirmed yet");

        // The body: four bytes of padding, then the remaining twelve.
        let mut body = vec![0u8; 4];
        body.extend_from_slice(&audio[4..]);
        snd.message(&body, &mut events, &mut replies)
            .expect("wave body");

        assert_eq!(events.len(), 1);
        let SessionEvent::Audio(packet) = &events[0] else {
            panic!("an audio packet: {events:?}");
        };
        assert_eq!(
            packet.pcm,
            (0..8_i16).collect::<Vec<_>>(),
            "every sample, first four bytes included"
        );
        assert_eq!(packet.sample_rate, 48_000);
        assert_eq!(packet.channels, 2);

        let queued = replies.queued();
        assert_eq!(queued.len(), 1, "one block, one confirm");
        assert_eq!(queued[0][0], msg::WAVE_CONFIRM);
        let mut r = Reader::new(&queued[0][PROLOG_LEN..]);
        assert_eq!(r.u16("timestamp").unwrap(), 0x1234, "echoed unmodified");
        assert_eq!(r.u8("block").unwrap(), 7);
    }

    /// Wave2 carries the header and all of the audio in one message, plus the
    /// server's own clock for lip sync, which travels through untouched.
    #[test]
    fn a_wave2_block_carries_the_servers_audio_clock() {
        let (mut snd, mut replies) = negotiated();
        let mut events = Vec::new();

        let audio: Vec<u8> = (0..4_i16).flat_map(i16::to_le_bytes).collect();
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u16(0x0042); // wTimeStamp
        w.u16(0); // wFormatNo
        w.u8(3); // cBlockNo
        w.u8(0);
        w.u8(0);
        w.u8(0);
        w.u32(0x0001_0000); // dwAudioTimeStamp
        body.extend_from_slice(&audio);

        snd.message(&prolog(msg::WAVE2, &body), &mut events, &mut replies)
            .expect("wave2");

        let SessionEvent::Audio(packet) = &events[0] else {
            panic!("an audio packet: {events:?}");
        };
        assert_eq!(packet.pcm, vec![0, 1, 2, 3]);
        assert_eq!(
            packet.timestamp_ms, 0x0001_0000,
            "the server's clock, carried through untouched"
        );
        assert_eq!(replies.queued().len(), 1, "and confirmed");
    }

    /// A `wFormatNo` outside the list we offered means the server is indexing
    /// something we never sent. Playing those bytes as PCM would be noise.
    #[test]
    fn a_format_index_we_never_offered_is_refused() {
        let (mut snd, mut replies) = negotiated();
        let mut events = Vec::new();
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u16(0);
        w.u16(9); // wFormatNo, and we offered one format
        w.u8(0);
        w.u8(0);
        w.u8(0);
        w.u8(0);
        w.u32(0);
        body.extend_from_slice(&[0, 0]);
        let err = snd
            .message(&prolog(msg::WAVE2, &body), &mut events, &mut replies)
            .expect_err("refused");
        assert!(matches!(err, RdpError::Protocol(_)), "{err}");
        assert!(events.is_empty());
    }

    /// A close drops the queue rather than draining it: a client that keeps
    /// playing after a logoff plays a fragment of a session that no longer
    /// exists, after the window has gone.
    #[test]
    fn a_close_drops_a_half_assembled_block() {
        let (mut snd, mut replies) = negotiated();
        let mut events = Vec::new();

        let mut pdu = Vec::new();
        let mut w = Writer::new(&mut pdu);
        w.u8(msg::WAVE);
        w.u8(0);
        w.u16(1024 + 8);
        let mut w = Writer::new(&mut pdu);
        w.u16(0);
        w.u16(0);
        w.u8(1);
        w.u8(0);
        w.u8(0);
        w.u8(0);
        pdu.extend_from_slice(&[0; 4]);
        snd.message(&pdu, &mut events, &mut replies)
            .expect("wave info");
        assert!(snd.expecting.is_some(), "a block is in flight");

        snd.message(&prolog(msg::CLOSE, &[]), &mut events, &mut replies)
            .expect("close");
        assert!(snd.expecting.is_none(), "the block was dropped");
        assert!(snd.wave.is_empty());
        assert!(events.is_empty(), "and nothing was played");
    }

    /// A `BodySize` longer than the message is a truncated PDU, and reading
    /// past it would read the next message's header as audio.
    #[test]
    fn a_body_size_longer_than_the_message_is_refused() {
        let (mut snd, mut replies) = negotiated();
        let mut events = Vec::new();
        let bad = vec![msg::WAVE2, 0, 0xff, 0xff, 1, 2, 3];
        let err = snd
            .message(&bad, &mut events, &mut replies)
            .expect_err("refused");
        assert!(matches!(err, RdpError::Pdu { .. }), "{err}");
    }

    /// The channel's own buffers are allocated once and reused: a block does
    /// not grow the assembly buffer every time, which at fifty packets a
    /// second is what a per packet allocation would cost.
    #[test]
    fn the_assembly_buffer_is_reused_across_blocks() {
        let (mut snd, mut replies) = negotiated();
        let mut events = Vec::new();
        let audio: Vec<u8> = (0..64_i16).flat_map(i16::to_le_bytes).collect();

        let block = |n: u8| {
            let mut body = Vec::new();
            let mut w = Writer::new(&mut body);
            w.u16(u16::from(n));
            w.u16(0);
            w.u8(n);
            w.u8(0);
            w.u8(0);
            w.u8(0);
            w.u32(0);
            body.extend_from_slice(&audio);
            prolog(msg::WAVE2, &body)
        };

        snd.message(&block(1), &mut events, &mut replies)
            .expect("first");
        let capacity = snd.wave.capacity();
        for n in 2..20 {
            snd.message(&block(n), &mut events, &mut replies)
                .expect("more");
        }
        assert_eq!(
            snd.wave.capacity(),
            capacity,
            "the assembly buffer never grew after the first block"
        );
        assert_eq!(events.len(), 19, "and every block was handed over");
    }
}
