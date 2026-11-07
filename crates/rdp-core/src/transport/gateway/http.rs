//! The small slice of HTTP/1.1 an RD Gateway needs (MS-TSGU 3.3.5.1).
//!
//! Requests with the gateway's own methods, `RDG_OUT_DATA` and
//! `RDG_IN_DATA`; a response head reader that keeps whatever arrived after
//! the blank line; and a chunked transfer coding encoder and decoder for the
//! two channel form. Nothing here is a general HTTP client and nothing here
//! needs to be: the gateway's side of the conversation is fixed by the
//! specification.

use crate::error::{RdpError, Result};

/// The path every Windows gateway serves the HTTP transport on.
pub const PATH: &str = "/remoteDesktopGateway/";

/// The longest response head accepted. A gateway's are a few hundred bytes;
/// a 401 with every authentication scheme listed is under two kilobytes.
pub const MAX_HEAD: usize = 16 * 1024;

/// How a request carries its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// `Content-Length: 0`, for every request of the sign in exchange.
    Empty,
    /// `Transfer-Encoding: chunked`, for the `RDG_IN_DATA` channel once it is
    /// signed in: the chunks are the client's packets, for as long as the
    /// connection lives.
    Chunked,
}

/// One request's head.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// `RDG_OUT_DATA` or `RDG_IN_DATA`.
    pub method: &'a str,
    /// The gateway's host name, for the `Host` header.
    pub host: &'a str,
    /// `RDG-Connection-Id`, the same on both channels of one connection.
    pub connection_id: &'a str,
    /// `Authorization`, scheme and token, when there is one.
    pub authorization: Option<(&'a str, String)>,
    /// `RDG-Auth-Scheme: PAA` when a cookie replaces the HTTP sign in.
    pub paa: bool,
    /// The `Sec-WebSocket-Key`, when the upgrade is being asked for.
    pub websocket_key: Option<&'a str>,
    /// How the body goes.
    pub body: Body,
}

impl Request<'_> {
    /// The bytes of the head, blank line included.
    ///
    /// The header set is the one mstsc sends, which FreeRDP copied and which
    /// is what a gateway's request filtering has been tested against.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut s = format!("{} {PATH} HTTP/1.1\r\n", self.method);
        s.push_str("Cache-Control: no-cache\r\n");
        s.push_str("Pragma: no-cache\r\n");
        s.push_str("Accept: */*\r\n");
        match self.websocket_key {
            Some(key) => {
                s.push_str("Connection: Upgrade\r\n");
                s.push_str("Upgrade: websocket\r\n");
                s.push_str("Sec-WebSocket-Version: 13\r\n");
                s.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
            }
            None => s.push_str("Connection: Keep-Alive\r\n"),
        }
        match self.body {
            Body::Empty => s.push_str("Content-Length: 0\r\n"),
            Body::Chunked => s.push_str("Transfer-Encoding: chunked\r\n"),
        }
        if let Some((scheme, token)) = &self.authorization {
            s.push_str(&format!("Authorization: {scheme} {token}\r\n"));
        }
        if self.paa {
            s.push_str("RDG-Auth-Scheme: PAA\r\n");
        }
        s.push_str("User-Agent: MS-RDGateway/1.0\r\n");
        s.push_str(&format!("Host: {}\r\n", self.host));
        s.push_str(&format!(
            "RDG-Connection-Id: {{{}}}\r\n",
            self.connection_id
        ));
        s.push_str("\r\n");
        s.into_bytes()
    }
}

/// A response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The reason phrase, for a log line.
    pub reason: String,
    /// Every header, names lowercased, in order. Repeated names stay
    /// repeated: a 401 lists one `WWW-Authenticate` per scheme.
    pub headers: Vec<(String, String)>,
}

impl Response {
    /// The first value of `name`, which is given in lower case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// `Content-Length`, when there is one and it parses.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")?.trim().parse().ok()
    }

    /// Whether the body uses the chunked transfer coding.
    #[must_use]
    pub fn is_chunked(&self) -> bool {
        self.header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    }

    /// The schemes the gateway offers in `WWW-Authenticate`, lowercased,
    /// each with its token when it carries one.
    #[must_use]
    pub fn challenges(&self) -> Vec<(String, Option<String>)> {
        self.headers
            .iter()
            .filter(|(n, _)| n == "www-authenticate")
            .flat_map(|(_, v)| v.split(','))
            .filter_map(|c| {
                let c = c.trim();
                if c.is_empty() {
                    return None;
                }
                let (scheme, token) = match c.split_once(' ') {
                    Some((s, t)) => (s, Some(t.trim().to_owned())),
                    None => (c, None),
                };
                // `Basic realm="x"` splits into a scheme and a parameter that
                // is not a token. Only NTLM and Negotiate carry tokens here.
                let scheme = scheme.to_ascii_lowercase();
                let token = token.filter(|t| !t.contains('='));
                Some((scheme, token))
            })
            .collect()
    }
}

/// Find the end of a response head in `buf`: the index just past the blank
/// line, or `None` when it has not all arrived.
#[must_use]
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse a complete head, blank line included.
///
/// # Errors
///
/// [`RdpError::Protocol`] for anything that is not an HTTP/1.x status line
/// followed by header lines.
pub fn parse_head(head: &[u8]) -> Result<Response> {
    let text = std::str::from_utf8(head).map_err(|_| {
        RdpError::Protocol("the RD Gateway sent a response head that is not text".to_owned())
    })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(RdpError::Protocol(format!(
            "the RD Gateway did not answer in HTTP/1.1: {:.40}",
            status_line
        )));
    }
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| RdpError::Protocol(format!("bad HTTP status line: {status_line:.60}")))?;
    let reason = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(RdpError::Protocol(format!(
                "bad HTTP header line: {line:.60}"
            )));
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(Response {
        status,
        reason,
        headers,
    })
}

/// One chunk of the chunked transfer coding (RFC 9112 7.1).
#[must_use]
pub fn chunk(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:X}\r\n", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out
}

/// Where a chunked body decoder is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// Reading the hexadecimal size line.
    Size,
    /// Inside a chunk, this many bytes left.
    Data(usize),
    /// The CRLF after a chunk's data.
    DataEnd,
    /// The zero size chunk arrived: the body is over.
    Done,
}

/// A chunked transfer coding decoder that is fed whatever the socket gives.
#[derive(Debug, Clone)]
pub struct Dechunker {
    state: ChunkState,
    line: Vec<u8>,
}

impl Default for Dechunker {
    fn default() -> Self {
        Self {
            state: ChunkState::Size,
            line: Vec::new(),
        }
    }
}

impl Dechunker {
    /// Decode `input`, appending the payload to `out`.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] for a size line that is not hexadecimal, one
    /// that is too long, or a chunk not followed by CRLF.
    pub fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        while !input.is_empty() {
            match self.state {
                ChunkState::Size => {
                    let Some(nl) = input.iter().position(|&b| b == b'\n') else {
                        self.line.extend_from_slice(input);
                        if self.line.len() > 64 {
                            return Err(bad_chunk());
                        }
                        return Ok(());
                    };
                    let (head, rest) = input.split_at(nl + 1);
                    self.line.extend_from_slice(head);
                    input = rest;
                    let line = std::str::from_utf8(&self.line).map_err(|_| bad_chunk())?;
                    // Chunk extensions after a `;` are allowed and ignored.
                    let size = line.trim().split(';').next().unwrap_or_default().trim();
                    let size = usize::from_str_radix(size, 16).map_err(|_| bad_chunk())?;
                    self.line.clear();
                    self.state = if size == 0 {
                        ChunkState::Done
                    } else {
                        ChunkState::Data(size)
                    };
                }
                ChunkState::Data(left) => {
                    let take = left.min(input.len());
                    let (data, rest) = input.split_at(take);
                    out.extend_from_slice(data);
                    input = rest;
                    self.state = if take == left {
                        ChunkState::DataEnd
                    } else {
                        ChunkState::Data(left - take)
                    };
                }
                ChunkState::DataEnd => {
                    // CR then LF, possibly split across two reads.
                    let (&b, rest) = input.split_first().unwrap_or((&0, &[]));
                    input = rest;
                    match b {
                        b'\r' => {}
                        b'\n' => self.state = ChunkState::Size,
                        _ => return Err(bad_chunk()),
                    }
                }
                ChunkState::Done => return Ok(()),
            }
        }
        Ok(())
    }

    /// Whether the terminating zero size chunk has arrived.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }
}

fn bad_chunk() -> RdpError {
    RdpError::Protocol("the RD Gateway sent a malformed chunked body".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_websocket_request_carries_the_upgrade_and_the_token() {
        let req = Request {
            method: "RDG_OUT_DATA",
            host: "gw.example",
            connection_id: "00000000-0000-0000-0000-000000000001",
            authorization: Some(("NTLM", "TlRMTVNT".to_owned())),
            paa: false,
            websocket_key: Some("dGhlIHNhbXBsZSBub25jZQ=="),
            body: Body::Empty,
        };
        let text = String::from_utf8(req.encode()).unwrap();
        assert!(text.starts_with("RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(text.contains("Authorization: NTLM TlRMTVNT\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(text.contains("Host: gw.example\r\n"));
        assert!(text.contains("RDG-Connection-Id: {00000000-0000-0000-0000-000000000001}\r\n"));
        assert!(!text.contains("RDG-Auth-Scheme"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn the_in_channel_is_chunked_and_a_paa_request_says_so() {
        let req = Request {
            method: "RDG_IN_DATA",
            host: "gw",
            connection_id: "x",
            authorization: None,
            paa: true,
            websocket_key: None,
            body: Body::Chunked,
        };
        let text = String::from_utf8(req.encode()).unwrap();
        assert!(text.contains("Connection: Keep-Alive\r\n"));
        assert!(text.contains("Transfer-Encoding: chunked\r\n"));
        assert!(!text.contains("Content-Length"));
        assert!(!text.contains("Authorization"));
        assert!(text.contains("RDG-Auth-Scheme: PAA\r\n"));
    }

    /// The head a Windows gateway sends when it wants NTLM, as captured
    /// from one, with the token shortened.
    #[test]
    fn a_401_lists_its_schemes_and_a_200_parses() {
        let head = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nServer: Microsoft-HTTPAPI/2.0\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\nWWW-Authenticate: Basic realm=\"gw\"\r\n\r\n";
        assert_eq!(head_end(head), Some(head.len()));
        let r = parse_head(head).unwrap();
        assert_eq!(r.status, 401);
        assert_eq!(r.content_length(), Some(0));
        assert_eq!(
            r.challenges(),
            vec![
                ("negotiate".to_owned(), None),
                ("ntlm".to_owned(), None),
                ("basic".to_owned(), None),
            ]
        );

        let r = parse_head(
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM TlRMTVNTUAACAAAA\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            r.challenges(),
            vec![("ntlm".to_owned(), Some("TlRMTVNTUAACAAAA".to_owned()))]
        );

        let r = parse_head(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").unwrap();
        assert_eq!(r.status, 101);
        assert_eq!(
            r.header("sec-websocket-accept"),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );
    }

    #[test]
    fn a_head_that_is_not_http_is_refused() {
        assert!(parse_head(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 abc\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nno colon here\r\n\r\n").is_err());
        assert_eq!(head_end(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn chunks_round_trip_across_any_split() {
        let mut wire = chunk(b"hello");
        wire.extend(chunk(&[7u8; 300]));
        wire.extend(b"0\r\n\r\n");
        for split in 1..wire.len() {
            let mut d = Dechunker::default();
            let mut out = Vec::new();
            for piece in wire.chunks(split) {
                d.feed(piece, &mut out).unwrap();
            }
            assert_eq!(&out[..5], b"hello", "split {split}");
            assert_eq!(out.len(), 305, "split {split}");
            assert!(d.is_done(), "split {split}");
        }
        assert_eq!(chunk(b"ab"), b"2\r\nab\r\n");
    }

    #[test]
    fn a_malformed_chunk_is_refused() {
        let mut out = Vec::new();
        assert!(Dechunker::default().feed(b"zz\r\n", &mut out).is_err());
        assert!(Dechunker::default().feed(b"2\r\nabX", &mut out).is_err());
        assert!(Dechunker::default().feed(&[b'1'; 100], &mut out).is_err());
    }
}
