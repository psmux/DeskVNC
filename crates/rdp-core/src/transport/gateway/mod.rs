//! RD Gateway, the HTTP transport of MS-TSGU.
//!
//! [`open`] returns a byte stream to the RDP server that runs through the
//! gateway, and the rest of the connection sequence runs over it exactly as
//! it runs over a TCP socket: X.224, TLS to the server, CredSSP, MCS. The
//! gateway sees only the outer HTTPS; the RDP server's own TLS sits inside
//! the tunnel.
//!
//! The order, MS-TSGU 3.3.5.1 and 3.7.5:
//!
//! 1. TCP and TLS to the gateway, its certificate checked against its own
//!    pin ([`PinScheme::RdgTls`]) before any credential leaves.
//! 2. `RDG_OUT_DATA` with the WebSocket upgrade asked for, signed in with
//!    NTLM in the `Authorization` header, or marked `RDG-Auth-Scheme: PAA`
//!    when a cookie stands in for the sign in. A `101` means one WebSocket
//!    carries both directions. A `200` means the gateway does not upgrade,
//!    and a second connection, `RDG_IN_DATA`, is signed in the same way and
//!    then carries the client's packets as a chunked body.
//! 3. Handshake, tunnel create, tunnel authorize, channel create.
//! 4. A pump task copies RDP bytes in and out of `HTTP_DATA_PACKET`s and
//!    answers keepalives, until either side closes.
//!
//! The RPC over HTTP transport (MS-TSGU 2.2.9 and 3.1 to 3.6), which
//! gateways before Windows Server 2008 R2 SP1 spoke, is not implemented.

pub mod http;
pub mod websocket;

use std::time::Duration;

use base64::Engine as _;
use rdp_auth::gss::{GssMechanism, GssStep};
use rdp_auth::ntlm::{NtlmClient, NtlmConfig};
use rdp_auth::{ChannelBindings, Identity};
use rdp_pdu::tsgu::{self, ExtendedAuth, ServerPacket};
use remote_core::{
    ConnectOptions, Credentials, GatewayOptions, GatewayTransport, PinScheme, SessionEvent,
    SessionState,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vnc_transport::{BoxedStream, TlsUpgrade};

use crate::connection::prompt::Prompt;
use crate::connection::{credentials, trust};
use crate::error::{ConnectStage, RdpError, Result};

use self::http::{Body, Dechunker, Request, Response};

/// How long the whole gateway setup may take, sign in and tunnel included.
pub const GATEWAY_TIMEOUT: Duration = Duration::from_secs(30);

/// The bytes the gateway sends at the start of a two channel `RDG_OUT_DATA`
/// body before the first packet (MS-TSGU 3.3.5.1 step 4). FreeRDP measured
/// ten and discards ten; so does this.
const SEED_LEN: usize = 10;

/// How long the pump waits for the gateway to confirm a close it asked for.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

/// What the client presents to the gateway.
enum Proof {
    /// NTLM in the HTTP `Authorization` header.
    Ntlm(Credentials),
    /// A pluggable authentication cookie, sent in the tunnel create packet.
    Paa(String),
}

/// Open the tunnel and return the stream the RDP connection runs over.
///
/// `creds` are the session's credentials. When the gateway signs in with the
/// same account they are completed here first, by asking the user if they
/// have to be, so the prompt comes once and CredSSP finds them filled in.
///
/// # Errors
///
/// [`RdpError::AuthFailed`] when the gateway refuses the sign in,
/// [`RdpError::Gateway`] when it refuses the tunnel or the channel, the
/// certificate errors of [`trust::approve_as`], and whatever the dial and
/// the TLS handshake report.
pub async fn open(
    options: &ConnectOptions,
    gateway: &GatewayOptions,
    client_name: &str,
    creds: &mut Credentials,
    events: &mpsc::Sender<SessionEvent>,
    mut prompt: Option<Prompt<'_>>,
) -> Result<BoxedStream> {
    let host = gateway.host.trim();
    if host.is_empty() {
        return Err(RdpError::Gateway(
            "has no host name in this profile".to_owned(),
        ));
    }
    let port = gateway.effective_port();
    tracing::info!(gateway = %host, port, server = %options.host, "opening an rd gateway tunnel");

    remote_core::emit_state(events, SessionState::Connecting).await?;
    let first = dial_tls(options, host, port).await?;
    // Nothing that depends on the gateway's identity, a password least of
    // all, leaves before the user has approved that identity.
    trust::approve_as(
        &first.decision,
        PinScheme::RdgTls,
        events,
        prompt.as_mut().map(Prompt::reborrow),
    )
    .await?;

    let proof = match gateway.access_token.as_deref().filter(|t| !t.is_empty()) {
        Some(token) => Proof::Paa(token.to_owned()),
        None if gateway.separate_credentials => Proof::Ntlm(gateway_credentials(gateway)?),
        None => {
            credentials::ensure(creds, events, prompt.as_mut().map(Prompt::reborrow)).await?;
            Proof::Ntlm(creds.clone())
        }
    };

    let setup = async {
        let link = connect_link(options, gateway, host, port, client_name, first, &proof).await?;
        let paa = match &proof {
            Proof::Paa(token) => Some(token.as_str()),
            Proof::Ntlm(_) => None,
        };
        tunnel(link, paa, client_name, &options.host, options.port).await
    };
    let link =
        crate::transport::with_timeout(ConnectStage::Gateway, GATEWAY_TIMEOUT, setup).await?;
    tracing::info!(gateway = %host, server = %options.host, "the rd gateway channel is open");
    Ok(pump(link))
}

/// The gateway's own account, from the profile and the keychain.
fn gateway_credentials(gateway: &GatewayOptions) -> Result<Credentials> {
    let username = gateway
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            RdpError::CredentialsRequired(
                "the RD Gateway account has no user name; set it in the host's gateway settings"
                    .to_owned(),
            )
        })?;
    let password = gateway.password.clone().ok_or_else(|| {
        RdpError::CredentialsRequired(
            "the RD Gateway account has no saved password; set it in the host's gateway settings"
                .to_owned(),
        )
    })?;
    Ok(Credentials {
        username: Some(username.to_owned()),
        password: Some(password),
        domain: None,
    })
}

/// TCP, through the profile's connector when it has one, then TLS.
async fn dial_tls(options: &ConnectOptions, host: &str, port: u16) -> Result<TlsUpgrade> {
    let stream: BoxedStream = match &options.connector {
        Some(connector) => {
            connector
                .0
                .connect(host, port, options.connect_timeout)
                .await?
        }
        None => Box::pin(vnc_transport::tcp::connect(host, port, options.connect_timeout).await?),
    };
    let pin = options.cert_pins.for_scheme(PinScheme::RdgTls);
    crate::transport::with_timeout(
        ConnectStage::Gateway,
        crate::transport::X224_TIMEOUT,
        async {
            Ok(vnc_transport::tls::upgrade_with_identity(
                stream,
                host,
                pin,
                vnc_transport::TlsBackend::Modern,
            )
            .await?)
        },
    )
    .await
}

/// A connection to the gateway with whatever has been read past the last
/// response head.
struct Conn {
    stream: BoxedStream,
    buf: Vec<u8>,
    certificate: Vec<u8>,
    signature_algorithm_oid: Vec<u8>,
}

impl Conn {
    fn new(upgrade: TlsUpgrade) -> Self {
        Self {
            stream: upgrade.stream,
            buf: Vec::new(),
            certificate: upgrade.server_certificate,
            signature_algorithm_oid: upgrade.signature_algorithm_oid,
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read one response head, leaving anything after it in `buf`.
    ///
    /// The body of a refusal (a 401 between NTLM legs) is always read past.
    /// The body of a success is read past only when `discard_body` is set:
    /// on `RDG_OUT_DATA` a `200` body is the gateway's half of the tunnel
    /// and arrives for as long as the connection lives.
    async fn response(&mut self, discard_body: bool) -> Result<Response> {
        let end = loop {
            if let Some(end) = http::head_end(&self.buf) {
                break end;
            }
            if self.buf.len() > http::MAX_HEAD {
                return Err(RdpError::Protocol(
                    "the RD Gateway sent a response head that never ends".to_owned(),
                ));
            }
            self.fill().await?;
        };
        let head: Vec<u8> = self.buf.drain(..end).collect();
        let response = http::parse_head(&head)?;
        tracing::debug!(status = response.status, reason = %response.reason, "rd gateway response");
        if discard_body || response.status >= 300 {
            let len = response.content_length().unwrap_or(0);
            while self.buf.len() < len {
                self.fill().await?;
            }
            self.buf.drain(..len);
        }
        Ok(response)
    }

    async fn fill(&mut self) -> Result<()> {
        let mut chunk = [0u8; 4096];
        let n = self.stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(RdpError::ConnectionClosed);
        }
        self.buf
            .extend_from_slice(chunk.get(..n).unwrap_or_default());
        Ok(())
    }
}

/// Sign `conn` in with `method` and return the response that ended the
/// exchange: `101` or `200` on success.
async fn sign_in(
    conn: &mut Conn,
    method: &str,
    host: &str,
    connection_id: &str,
    websocket_key: Option<&str>,
    proof: &Proof,
    client_name: &str,
) -> Result<Response> {
    let request = |authorization: Option<(&'static str, String)>| Request {
        method,
        host,
        connection_id,
        authorization,
        paa: matches!(proof, Proof::Paa(_)),
        websocket_key,
        body: Body::Empty,
    };
    // A request with no proof first: the answer either lets us in, which a
    // PAA gateway does, or lists the schemes it will take.
    conn.send(&request(None).encode()).await?;
    let keep_body = method == "RDG_OUT_DATA";
    let first = conn.response(!keep_body).await?;
    let creds = match proof {
        Proof::Paa(_) => return accepted(first, method),
        Proof::Ntlm(creds) if first.status == 401 => creds,
        Proof::Ntlm(_) => return accepted(first, method),
    };
    let offered = first.challenges();
    // Raw NTLM inside `Negotiate` is accepted by Windows' SSPI, which is what
    // answers on a gateway that lists only that.
    let scheme = if offered.iter().any(|(s, _)| s == "ntlm") {
        "NTLM"
    } else if offered.iter().any(|(s, _)| s == "negotiate") {
        "Negotiate"
    } else {
        let names: Vec<_> = offered.iter().map(|(s, _)| s.as_str()).collect();
        return Err(RdpError::Gateway(format!(
            "accepts only sign in schemes this app does not speak: {}",
            names.join(", ")
        )));
    };

    let mut ntlm = ntlm_client(creds, conn, host, client_name)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let negotiate = match ntlm.step(&[])? {
        GssStep::Token(t) | GssStep::FinalToken(t) => t,
        GssStep::Complete => Vec::new(),
    };
    conn.send(&request(Some((scheme, b64.encode(negotiate)))).encode())
        .await?;
    let challenge = conn.response(!keep_body).await?;
    if challenge.status != 401 {
        return accepted(challenge, method);
    }
    let token = challenge
        .challenges()
        .into_iter()
        .find(|(s, t)| s.eq_ignore_ascii_case(scheme) && t.is_some())
        .and_then(|(_, t)| t)
        .ok_or_else(|| {
            RdpError::AuthFailed("the RD Gateway did not continue the NTLM sign in".to_owned())
        })?;
    let challenge_bytes = b64.decode(token.as_bytes()).map_err(|_| {
        RdpError::Protocol("the RD Gateway's NTLM challenge is not base64".to_owned())
    })?;
    let authenticate = match ntlm.step(&challenge_bytes)? {
        GssStep::Token(t) | GssStep::FinalToken(t) => t,
        GssStep::Complete => Vec::new(),
    };
    conn.send(&request(Some((scheme, b64.encode(authenticate)))).encode())
        .await?;
    // The final answer to `RDG_OUT_DATA` is the start of the data channel,
    // so its body is not read here.
    let last = conn.response(!keep_body).await?;
    accepted(last, method)
}

/// Turn the last response of a sign in into the outcome.
fn accepted(response: Response, method: &str) -> Result<Response> {
    match response.status {
        101 | 200 => Ok(response),
        401 => Err(RdpError::AuthFailed(
            "the RD Gateway refused the user name or password".to_owned(),
        )),
        403 | 404 | 410 => Err(RdpError::Gateway(format!(
            "does not offer the HTTP transport ({} {} to {method}); \
             the older RPC over HTTP transport is not supported",
            response.status, response.reason
        ))),
        status => Err(RdpError::Gateway(format!(
            "answered {method} with {status} {}",
            response.reason
        ))),
    }
}

fn ntlm_client(
    creds: &Credentials,
    conn: &Conn,
    host: &str,
    client_name: &str,
) -> Result<NtlmClient> {
    let username = creds
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            RdpError::CredentialsRequired("no user name for the RD Gateway".to_owned())
        })?;
    let password = creds.password.as_deref().ok_or_else(|| {
        RdpError::CredentialsRequired("no password for the RD Gateway".to_owned())
    })?;
    let (user, qualified) = rdp_auth::split_qualified_username(username);
    let domain = if qualified.is_empty() {
        creds.domain.clone().unwrap_or_default()
    } else {
        qualified
    };
    Ok(NtlmClient::new(NtlmConfig {
        identity: Identity::from_prompt(&user, &domain, password)?,
        spn: format!("HTTP/{host}"),
        workstation: Some(client_name.to_owned()),
        // Extended Protection: the sign in is bound to this TLS connection's
        // certificate, so it cannot be relayed to another endpoint.
        channel_bindings: Some(ChannelBindings::from_certificate(
            &conn.certificate,
            &conn.signature_algorithm_oid,
        )),
    }))
}

/// A fresh GUID string for `RDG-Connection-Id`, version 4 form.
fn connection_id() -> String {
    use rand::Rng as _;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// The two halves of an open channel.
struct Link {
    inbound: Inbound,
    outbound: Outbound,
}

/// Set up the HTTP side: one WebSocket, or the `RDG_OUT_DATA` and
/// `RDG_IN_DATA` pair.
async fn connect_link(
    options: &ConnectOptions,
    gateway: &GatewayOptions,
    host: &str,
    port: u16,
    client_name: &str,
    first: TlsUpgrade,
    proof: &Proof,
) -> Result<Link> {
    let id = connection_id();
    let mut out = Conn::new(first);
    let key = (gateway.transport == GatewayTransport::Auto).then(websocket::new_key);
    let response = sign_in(
        &mut out,
        "RDG_OUT_DATA",
        host,
        &id,
        key.as_deref(),
        proof,
        client_name,
    )
    .await?;

    if response.status == 101 {
        let expected = key.as_deref().map(websocket::accept_for);
        if response.header("sec-websocket-accept") != expected.as_deref() {
            return Err(RdpError::Gateway(
                "answered the WebSocket upgrade with the wrong Sec-WebSocket-Accept".to_owned(),
            ));
        }
        tracing::info!("the rd gateway upgraded to a websocket");
        let (read, write) = tokio::io::split(out.stream);
        return Ok(Link {
            inbound: Inbound::new(Box::new(read), out.buf, InMode::WebSocket, 0),
            outbound: Outbound {
                writer: Box::new(write),
                websocket: true,
            },
        });
    }

    // 200: the two channel form. The out channel's body is the gateway's
    // half of the conversation from here on.
    tracing::info!(
        chunked = response.is_chunked(),
        "the rd gateway uses the two channel http form"
    );
    let in_mode = if response.is_chunked() {
        InMode::Chunked(Dechunker::default())
    } else {
        InMode::Identity
    };

    let second = dial_tls(options, host, port).await?;
    // The second connection must reach the gateway the user approved on the
    // first. Comparing the certificates is the whole check: the trust
    // decision was made on the first, and a different certificate here is a
    // different machine.
    if second.server_certificate != out.certificate {
        return Err(RdpError::CertificateUntrusted(
            "the RD Gateway presented a different certificate on its second connection".to_owned(),
        ));
    }
    let mut inc = Conn::new(second);
    sign_in(&mut inc, "RDG_IN_DATA", host, &id, None, proof, client_name).await?;
    // Signed in: the request that opens the chunked body goes without a
    // token, because NTLM over HTTP authenticates the connection.
    let open = Request {
        method: "RDG_IN_DATA",
        host,
        connection_id: &id,
        authorization: None,
        paa: matches!(proof, Proof::Paa(_)),
        websocket_key: None,
        body: Body::Chunked,
    };
    inc.send(&open.encode()).await?;

    Ok(Link {
        inbound: Inbound::new(Box::new(out.stream), out.buf, in_mode, SEED_LEN),
        outbound: Outbound {
            writer: Box::new(inc.stream),
            websocket: false,
        },
    })
}

type Reader = Box<dyn AsyncRead + Send + Unpin>;
type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// How the gateway's bytes are wrapped on their way in.
enum InMode {
    WebSocket,
    Chunked(Dechunker),
    Identity,
}

/// What [`Inbound::next`] produced.
enum Incoming {
    Packet(Vec<u8>),
    Ping(Vec<u8>),
    Closed,
}

/// The gateway's half: raw bytes in, MS-TSGU packets out.
struct Inbound {
    reader: Reader,
    raw: Vec<u8>,
    decoded: Vec<u8>,
    mode: InMode,
    /// Bytes still to drop from the front of the decoded stream.
    skip: usize,
}

impl Inbound {
    fn new(reader: Reader, raw: Vec<u8>, mode: InMode, skip: usize) -> Self {
        Self {
            reader,
            raw,
            decoded: Vec::new(),
            mode,
            skip,
        }
    }

    /// The next whole packet, a ping to answer, or the end.
    async fn next(&mut self) -> Result<Incoming> {
        loop {
            if let Some(packet) = self.take_packet()? {
                return Ok(Incoming::Packet(packet));
            }
            if !self.raw.is_empty() {
                match &mut self.mode {
                    InMode::WebSocket => match websocket::decode(&mut self.raw)? {
                        Some(websocket::Frame::Data(d)) => self.decoded.extend(d),
                        Some(websocket::Frame::Ping(p)) => return Ok(Incoming::Ping(p)),
                        Some(websocket::Frame::Pong) => {}
                        Some(websocket::Frame::Close) => return Ok(Incoming::Closed),
                        None => self.read().await?,
                    },
                    InMode::Chunked(d) => {
                        let raw = std::mem::take(&mut self.raw);
                        d.feed(&raw, &mut self.decoded)?;
                        if d.is_done() {
                            return Ok(Incoming::Closed);
                        }
                    }
                    InMode::Identity => self.decoded.append(&mut self.raw),
                }
                let drop = self.skip.min(self.decoded.len());
                self.decoded.drain(..drop);
                self.skip -= drop;
                continue;
            }
            if !self.read_or_eof().await? {
                return Ok(Incoming::Closed);
            }
        }
    }

    fn take_packet(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(head) = self.decoded.get(..tsgu::HEADER_LEN) else {
            return Ok(None);
        };
        let header = tsgu::Header::decode(head)?;
        let len = header.length as usize;
        if self.decoded.len() < len {
            return Ok(None);
        }
        Ok(Some(self.decoded.drain(..len).collect()))
    }

    async fn read(&mut self) -> Result<()> {
        if self.read_or_eof().await? {
            Ok(())
        } else {
            Err(RdpError::ConnectionClosed)
        }
    }

    async fn read_or_eof(&mut self) -> Result<bool> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.reader.read(&mut chunk).await?;
        self.raw
            .extend_from_slice(chunk.get(..n).unwrap_or_default());
        Ok(n > 0)
    }
}

/// The client's half: MS-TSGU packets in, WebSocket frames or chunks out.
struct Outbound {
    writer: Writer,
    websocket: bool,
}

impl Outbound {
    async fn send(&mut self, packet: &[u8]) -> Result<()> {
        let bytes = if self.websocket {
            websocket::encode(websocket::opcode::BINARY, packet)
        } else {
            http::chunk(packet)
        };
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn pong(&mut self, payload: &[u8]) -> Result<()> {
        if self.websocket {
            let frame = websocket::encode(websocket::opcode::PONG, payload);
            self.writer.write_all(&frame).await?;
            self.writer.flush().await?;
        }
        Ok(())
    }
}

/// The MS-TSGU conversation up to an open channel (MS-TSGU 3.7.5).
async fn tunnel(
    mut link: Link,
    paa: Option<&str>,
    client_name: &str,
    server: &str,
    server_port: u16,
) -> Result<Link> {
    let ext = if paa.is_some() {
        ExtendedAuth::Paa
    } else {
        ExtendedAuth::None
    };
    link.outbound.send(&tsgu::handshake_request(ext)).await?;
    let handshake = expect(&mut link, "handshake", |p| match p {
        ServerPacket::Handshake(h) => Some(h.error_code),
        _ => None,
    })
    .await?;
    refused("refused the handshake", handshake, false)?;

    link.outbound.send(&tsgu::tunnel_create(paa)?).await?;
    let (status, consent) = expect(&mut link, "tunnel", |p| match p {
        ServerPacket::Tunnel(t) => Some((t.status_code, t.consent_message.clone())),
        _ => None,
    })
    .await?;
    refused("refused to create a tunnel", status, false)?;
    if let Some(message) = consent {
        tracing::info!(%message, "the rd gateway sent a consent message");
    }

    link.outbound.send(&tsgu::tunnel_auth(client_name)?).await?;
    let auth = expect(&mut link, "tunnel authorization", |p| match p {
        ServerPacket::TunnelAuth(a) => Some(a.error_code),
        _ => None,
    })
    .await?;
    // E_PROXY_QUARANTINE_ACCESSDENIED is a health policy warning the gateway
    // still lets through (MS-TSGU 3.7.5.2.7).
    if auth != 0x8007_59ED {
        refused(
            "refused to authorize the tunnel (its connection authorization policy said no)",
            auth,
            true,
        )?;
    }

    link.outbound
        .send(&tsgu::channel_create(server, server_port)?)
        .await?;
    let channel = expect(&mut link, "channel", |p| match p {
        ServerPacket::Channel(c) => Some(c.error_code),
        _ => None,
    })
    .await?;
    refused(
        &format!("could not open a channel to {server}:{server_port}"),
        channel,
        false,
    )?;
    Ok(link)
}

/// Fail with `what` and the code's name when `code` is a failure.
///
/// The handshake, tunnel and channel responses carry HRESULTs and are tested
/// the way FreeRDP and mstsc test them, on the severity bit. The tunnel
/// authorization result is stricter in MS-TSGU 3.7.5.2.7: anything but zero
/// is a refusal, so it is checked with `strict`.
fn refused(what: &str, code: u32, strict: bool) -> Result<()> {
    let failed = if strict {
        code != 0
    } else {
        code & 0x8000_0000 != 0
    };
    if !failed {
        return Ok(());
    }
    let name = tsgu::error_name(code).unwrap_or("an unknown error");
    Err(RdpError::Gateway(format!("{what}: {name} (0x{code:08x})")))
}

/// Wait for the packet `pick` recognises, answering keepalives and logging
/// service messages on the way.
async fn expect<T>(
    link: &mut Link,
    what: &str,
    pick: impl Fn(&ServerPacket<'_>) -> Option<T>,
) -> Result<T> {
    loop {
        let packet = match link.inbound.next().await? {
            Incoming::Packet(p) => p,
            Incoming::Ping(p) => {
                link.outbound.pong(&p).await?;
                continue;
            }
            Incoming::Closed => {
                return Err(RdpError::Gateway(format!(
                    "closed the connection while the client waited for its {what} response"
                )))
            }
        };
        let decoded = ServerPacket::decode(&packet)?;
        if let Some(found) = pick(&decoded) {
            return Ok(found);
        }
        match decoded {
            ServerPacket::Keepalive => link.outbound.send(&tsgu::keepalive()).await?,
            ServerPacket::ServiceMessage(message) => {
                tracing::info!(%message, "the rd gateway sent a service message");
            }
            ServerPacket::CloseChannel(code) => {
                return Err(RdpError::Gateway(format!(
                "closed the channel while the client waited for its {what} response (0x{code:08x})"
            )))
            }
            other => {
                return Err(RdpError::Protocol(format!(
                    "the RD Gateway sent {other:?} while the client waited for its {what} response"
                )))
            }
        }
    }
}

/// What the pump's writer is asked to send.
enum Outgoing {
    Packet(Vec<u8>),
    Pong(Vec<u8>),
}

/// Start the pump and return the RDP side of it.
///
/// Three tasks over one in memory pipe. The upstream task reads what the RDP
/// connection writes and queues it as data packets. The downstream task reads
/// the gateway, writes the RDP bytes into the pipe and queues the answers to
/// keepalives and pings. The writer task owns the gateway's write half and
/// sends what is queued, in order. Dropping the stream this returns closes
/// the pipe, the upstream task sends `PKT_TYPE_CLOSE_CHANNEL`, and the rest
/// wind down behind it.
fn pump(link: Link) -> BoxedStream {
    let (rdp_side, pump_side) = tokio::io::duplex(4 * tsgu::MAX_DATA_LEN);
    let (mut from_rdp, mut to_rdp) = tokio::io::split(pump_side);
    let (tx, mut rx) = mpsc::channel::<Outgoing>(64);
    let stop = CancellationToken::new();
    let Link {
        mut inbound,
        mut outbound,
    } = link;

    tokio::spawn(async move {
        while let Some(out) = rx.recv().await {
            let sent = match out {
                Outgoing::Packet(p) => outbound.send(&p).await,
                Outgoing::Pong(p) => outbound.pong(&p).await,
            };
            if let Err(e) = sent {
                tracing::debug!(error = %e, "writing to the rd gateway failed");
                break;
            }
        }
        let _ = outbound.writer.shutdown().await;
    });

    let up_tx = tx.clone();
    let up_stop = stop.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; tsgu::MAX_DATA_LEN];
        loop {
            let n = tokio::select! {
                () = up_stop.cancelled() => return,
                n = from_rdp.read(&mut buf) => n,
            };
            match n {
                Ok(n) if n > 0 => {
                    let Ok(packet) = tsgu::data(buf.get(..n).unwrap_or_default()) else {
                        break;
                    };
                    if up_tx.send(Outgoing::Packet(packet)).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        // The RDP side closed: tell the gateway, give it a moment to answer,
        // then stop waiting for it.
        let _ = up_tx.send(Outgoing::Packet(tsgu::close_channel(0))).await;
        tokio::select! {
            () = up_stop.cancelled() => {}
            () = tokio::time::sleep(CLOSE_GRACE) => up_stop.cancel(),
        }
    });

    tokio::spawn(async move {
        loop {
            let incoming = tokio::select! {
                () = stop.cancelled() => break,
                incoming = inbound.next() => incoming,
            };
            let packet = match incoming {
                Ok(Incoming::Packet(p)) => p,
                Ok(Incoming::Ping(p)) => {
                    let _ = tx.send(Outgoing::Pong(p)).await;
                    continue;
                }
                Ok(Incoming::Closed) => break,
                Err(e) => {
                    tracing::debug!(error = %e, "reading from the rd gateway failed");
                    break;
                }
            };
            match ServerPacket::decode(&packet) {
                Ok(ServerPacket::Data(data)) => {
                    if to_rdp.write_all(data).await.is_err() {
                        break;
                    }
                }
                Ok(ServerPacket::Keepalive) => {
                    let _ = tx.send(Outgoing::Packet(tsgu::keepalive())).await;
                }
                Ok(ServerPacket::CloseChannel(code)) => {
                    tracing::info!(
                        code = format_args!("{code:#010x}"),
                        "the rd gateway closed the channel"
                    );
                    let _ = tx
                        .send(Outgoing::Packet(tsgu::close_channel_response(0)))
                        .await;
                    break;
                }
                Ok(ServerPacket::CloseChannelResponse(_)) => break,
                Ok(ServerPacket::ServiceMessage(message)) => {
                    tracing::info!(%message, "the rd gateway sent a service message");
                }
                Ok(other) => tracing::debug!(?other, "ignoring an rd gateway packet"),
                Err(e) => {
                    tracing::debug!(error = %e, "an rd gateway packet did not parse");
                    break;
                }
            }
        }
        let _ = to_rdp.shutdown().await;
        stop.cancel();
    });

    Box::pin(rdp_side)
}

#[cfg(test)]
mod tests;
