//! The gateway transport against a scripted gateway on in memory pipes.
//!
//! The PDUs themselves are pinned byte for byte in `rdp_pdu::tsgu`; these
//! tests drive the conversation: the sign in, both HTTP forms, the tunnel
//! sequence, the refusals and the pump.

use rdp_pdu::tsgu::{self, packet_type};
use tokio::io::{duplex, DuplexStream};

use super::*;

/// One server side packet: an unmasked binary WebSocket frame around it.
fn server_frame(packet: &[u8]) -> Vec<u8> {
    let mut out = vec![0x82];
    if packet.len() < 126 {
        out.push(packet.len() as u8);
    } else {
        out.push(126);
        out.extend((packet.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(packet);
    out
}

/// Read one masked client frame and return its opcode and unmasked payload.
async fn client_frame(s: &mut DuplexStream) -> (u8, Vec<u8>) {
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await.unwrap();
    assert_eq!(h[1] & 0x80, 0x80, "client frames are masked");
    let len = match h[1] & 0x7F {
        126 => {
            let mut b = [0u8; 2];
            s.read_exact(&mut b).await.unwrap();
            usize::from(u16::from_be_bytes(b))
        }
        127 => {
            let mut b = [0u8; 8];
            s.read_exact(&mut b).await.unwrap();
            u64::from_be_bytes(b) as usize
        }
        n => usize::from(n),
    };
    let mut mask = [0u8; 4];
    s.read_exact(&mut mask).await.unwrap();
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).await.unwrap();
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    (h[0] & 0x0F, payload)
}

/// One client packet off a WebSocket.
async fn ws_packet(s: &mut DuplexStream) -> Vec<u8> {
    let (op, payload) = client_frame(s).await;
    assert_eq!(op, websocket::opcode::BINARY);
    payload
}

fn ws_link(client: DuplexStream) -> Link {
    let (r, w) = tokio::io::split(client);
    Link {
        inbound: Inbound::new(Box::new(r), Vec::new(), InMode::WebSocket, 0),
        outbound: Outbound {
            writer: Box::new(w),
            websocket: true,
        },
    }
}

fn packet(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = kind.to_le_bytes().to_vec();
    out.extend([0, 0]);
    out.extend(((body.len() + 8) as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn handshake_response(code: u32) -> Vec<u8> {
    let mut b = code.to_le_bytes().to_vec();
    b.extend([1, 0, 0, 0, 0, 0]);
    packet(packet_type::HANDSHAKE_RESPONSE, &b)
}

fn tunnel_response(code: u32) -> Vec<u8> {
    let mut b = vec![0, 0];
    b.extend(code.to_le_bytes());
    b.extend([0, 0, 0, 0]);
    packet(packet_type::TUNNEL_RESPONSE, &b)
}

fn auth_response(code: u32) -> Vec<u8> {
    let mut b = code.to_le_bytes().to_vec();
    b.extend([0, 0, 0, 0]);
    packet(packet_type::TUNNEL_AUTH_RESPONSE, &b)
}

fn channel_response(code: u32) -> Vec<u8> {
    let mut b = code.to_le_bytes().to_vec();
    b.extend([0, 0, 0, 0]);
    packet(packet_type::CHANNEL_RESPONSE, &b)
}

/// Play the gateway's side of the tunnel sequence over a WebSocket,
/// checking what the client sent at each step, with a keepalive and a
/// service message thrown in before the tunnel response.
async fn gateway_side(s: &mut DuplexStream, channel_code: u32) {
    assert_eq!(
        ws_packet(s).await,
        tsgu::handshake_request(ExtendedAuth::None)
    );
    s.write_all(&server_frame(&handshake_response(0)))
        .await
        .unwrap();

    assert_eq!(ws_packet(s).await, tsgu::tunnel_create(None).unwrap());
    s.write_all(&server_frame(&tsgu::keepalive()))
        .await
        .unwrap();
    let mut msg = vec![4, 0];
    msg.extend([b'h', 0, 0, 0]);
    s.write_all(&server_frame(&packet(packet_type::SERVICE_MESSAGE, &msg)))
        .await
        .unwrap();
    // The keepalive is answered before the tunnel response arrives.
    assert_eq!(ws_packet(s).await, tsgu::keepalive());
    s.write_all(&server_frame(&tunnel_response(0)))
        .await
        .unwrap();

    assert_eq!(ws_packet(s).await, tsgu::tunnel_auth("CLIENT").unwrap());
    s.write_all(&server_frame(&auth_response(0))).await.unwrap();

    assert_eq!(
        ws_packet(s).await,
        tsgu::channel_create("rdp.example", 3389).unwrap()
    );
    s.write_all(&server_frame(&channel_response(channel_code)))
        .await
        .unwrap();
}

#[tokio::test]
async fn the_tunnel_sequence_runs_over_a_websocket_and_the_pump_carries_rdp() {
    let (client, mut server) = duplex(1 << 20);
    let gw = tokio::spawn(async move {
        gateway_side(&mut server, 0).await;

        // RDP bytes from the client arrive as data packets.
        assert_eq!(
            ws_packet(&mut server).await,
            tsgu::data(b"\x03\x00\x00\x13").unwrap()
        );
        // RDP bytes to the client, split across two frames on purpose, and
        // a ping that must be answered with a pong carrying its payload.
        let reply = tsgu::data(b"server says hi").unwrap();
        let (a, b) = reply.split_at(5);
        server.write_all(&server_frame(a)).await.unwrap();
        server.write_all(&[0x89, 0x02, b'p', b'q']).await.unwrap();
        server.write_all(&server_frame(b)).await.unwrap();
        let (op, payload) = client_frame(&mut server).await;
        assert_eq!(
            (op, payload.as_slice()),
            (websocket::opcode::PONG, &b"pq"[..])
        );

        // A gateway keepalive in the data phase is answered.
        server
            .write_all(&server_frame(&tsgu::keepalive()))
            .await
            .unwrap();
        assert_eq!(ws_packet(&mut server).await, tsgu::keepalive());

        // The client closing its stream sends CLOSE_CHANNEL.
        assert_eq!(ws_packet(&mut server).await, tsgu::close_channel(0));
        server
            .write_all(&server_frame(&packet(
                packet_type::CLOSE_CHANNEL_RESPONSE,
                &[0, 0, 0, 0],
            )))
            .await
            .unwrap();
    });

    let link = tunnel(ws_link(client), None, "CLIENT", "rdp.example", 3389)
        .await
        .expect("tunnel");
    let mut rdp = pump(link);
    rdp.write_all(b"\x03\x00\x00\x13").await.unwrap();
    let mut got = [0u8; 14];
    rdp.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"server says hi");
    drop(rdp);
    tokio::time::timeout(Duration::from_secs(5), gw)
        .await
        .expect("the gateway side finished")
        .unwrap();
}

#[tokio::test]
async fn a_channel_the_gateway_cannot_open_names_the_error() {
    let (client, mut server) = duplex(1 << 16);
    let gw = tokio::spawn(async move { gateway_side(&mut server, 0x8007_59DD).await });
    let err = tunnel(ws_link(client), None, "CLIENT", "rdp.example", 3389)
        .await
        .err()
        .expect("refused");
    gw.await.unwrap();
    let text = err.to_string();
    assert!(matches!(err, RdpError::Gateway(_)), "{err:?}");
    assert!(text.contains("E_PROXY_TS_CONNECTFAILED"), "{text}");
    assert!(text.contains("rdp.example:3389"), "{text}");
    assert!(!err.is_transient() && !err.needs_user_action());
}

/// A resource or connection policy refusal comes back on the tunnel
/// authorization, and any non zero code there is a refusal.
#[tokio::test]
async fn a_policy_refusal_on_tunnel_authorization_is_reported() {
    let (client, mut server) = duplex(1 << 16);
    let gw = tokio::spawn(async move {
        ws_packet(&mut server).await;
        server
            .write_all(&server_frame(&handshake_response(0)))
            .await
            .unwrap();
        ws_packet(&mut server).await;
        server
            .write_all(&server_frame(&tunnel_response(0)))
            .await
            .unwrap();
        ws_packet(&mut server).await;
        server
            .write_all(&server_frame(&auth_response(0x8007_59DA)))
            .await
            .unwrap();
    });
    let err = tunnel(ws_link(client), None, "CLIENT", "rdp.example", 3389)
        .await
        .err()
        .expect("refused");
    gw.await.unwrap();
    assert!(
        err.to_string().contains("E_PROXY_RAP_ACCESSDENIED"),
        "{err}"
    );
}

/// With a PAA cookie the handshake announces it and the tunnel create
/// carries it.
#[tokio::test]
async fn a_paa_cookie_goes_in_the_handshake_and_the_tunnel_create() {
    let (client, mut server) = duplex(1 << 16);
    let gw = tokio::spawn(async move {
        assert_eq!(
            ws_packet(&mut server).await,
            tsgu::handshake_request(ExtendedAuth::Paa)
        );
        server
            .write_all(&server_frame(&handshake_response(0)))
            .await
            .unwrap();
        assert_eq!(
            ws_packet(&mut server).await,
            tsgu::tunnel_create(Some("cookie")).unwrap()
        );
        server
            .write_all(&server_frame(&tunnel_response(0x8007_59F8)))
            .await
            .unwrap();
    });
    let err = tunnel(ws_link(client), Some("cookie"), "CLIENT", "h", 3389)
        .await
        .err()
        .expect("refused");
    gw.await.unwrap();
    assert!(
        err.to_string()
            .contains("E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED"),
        "{err}"
    );
}

/// The two channel form: packets out as chunks on the in channel, packets
/// back on the chunked out channel body after the ten seed bytes.
#[tokio::test]
async fn the_two_channel_form_chunks_out_and_skips_the_seed_in() {
    let (out_client, mut out_server) = duplex(1 << 16);
    let (in_client, mut in_server) = duplex(1 << 16);
    let link = Link {
        inbound: Inbound::new(
            Box::new(out_client),
            Vec::new(),
            InMode::Chunked(Dechunker::default()),
            SEED_LEN,
        ),
        outbound: Outbound {
            writer: Box::new(in_client),
            websocket: false,
        },
    };
    let gw = tokio::spawn(async move {
        let mut body = vec![0x5A; SEED_LEN];
        body.extend(handshake_response(0));
        // The seed and the first packet in one chunk, split mid packet.
        let (a, b) = body.split_at(14);
        out_server.write_all(&http::chunk(a)).await.unwrap();
        out_server.write_all(&http::chunk(b)).await.unwrap();
        out_server
            .write_all(&http::chunk(&tunnel_response(0)))
            .await
            .unwrap();
        out_server
            .write_all(&http::chunk(&auth_response(0)))
            .await
            .unwrap();
        out_server
            .write_all(&http::chunk(&channel_response(0)))
            .await
            .unwrap();

        let mut sent = vec![0u8; 4096];
        let mut have = Vec::new();
        let expected = [
            http::chunk(&tsgu::handshake_request(ExtendedAuth::None)),
            http::chunk(&tsgu::tunnel_create(None).unwrap()),
            http::chunk(&tsgu::tunnel_auth("CLIENT").unwrap()),
            http::chunk(&tsgu::channel_create("h", 3390).unwrap()),
        ]
        .concat();
        while have.len() < expected.len() {
            let n = in_server.read(&mut sent).await.unwrap();
            assert!(n > 0);
            have.extend_from_slice(&sent[..n]);
        }
        assert_eq!(have, expected);
    });
    tunnel(link, None, "CLIENT", "h", 3390)
        .await
        .expect("tunnel");
    gw.await.unwrap();
}

/// A test conn over a pipe, with a made up certificate for the binding.
fn conn(stream: DuplexStream) -> Conn {
    Conn {
        stream: Box::pin(stream),
        buf: Vec::new(),
        certificate: vec![0x30, 0x03, 0x02, 0x01, 0x00],
        signature_algorithm_oid: Vec::new(),
    }
}

/// Read one request head off the server side of the pipe.
async fn request_head(s: &mut DuplexStream) -> String {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while http::head_end(&buf).is_none() {
        s.read_exact(&mut b).await.unwrap();
        buf.push(b[0]);
    }
    String::from_utf8(buf).unwrap()
}

fn authorization(head: &str) -> Option<(String, Vec<u8>)> {
    let line = head
        .lines()
        .find(|l| l.starts_with("Authorization: "))?
        .trim_start_matches("Authorization: ");
    let (scheme, token) = line.split_once(' ')?;
    Some((
        scheme.to_owned(),
        base64::engine::general_purpose::STANDARD
            .decode(token)
            .unwrap(),
    ))
}

/// A CHALLENGE a Windows server could send: the client's flags echoed,
/// a timestamp in the target info, which NTLMv2 requires.
fn challenge_for(negotiate: &[u8]) -> Vec<u8> {
    let flags = u32::from_le_bytes(negotiate[12..16].try_into().unwrap());
    let mut info = Vec::new();
    // MsvAvNbDomainName "D", MsvAvTimestamp, MsvAvEOL.
    info.extend([2, 0, 2, 0, b'D', 0]);
    info.extend([7, 0, 8, 0]);
    info.extend(0x01D9_0000_0000_0000u64.to_le_bytes());
    info.extend([0, 0, 0, 0]);
    rdp_auth::ntlm::messages::encode_challenge(&rdp_auth::ntlm::messages::ChallengeMessage {
        target_name: vec![b'D', 0],
        flags,
        server_challenge: [1, 2, 3, 4, 5, 6, 7, 8],
        target_info: info,
        version: None,
        raw: Vec::new(),
    })
}

/// The whole NTLM exchange on one connection: an unauthenticated request
/// learns the schemes, NEGOTIATE gets a CHALLENGE, AUTHENTICATE gets the
/// WebSocket upgrade.
#[tokio::test]
async fn ntlm_signs_in_over_http_and_the_upgrade_ends_the_exchange() {
    let (client, mut server) = duplex(1 << 16);
    let gw = tokio::spawn(async move {
        let first = request_head(&mut server).await;
        assert!(first.starts_with("RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n"));
        assert!(authorization(&first).is_none());
        assert!(first.contains("Upgrade: websocket"));
        server
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\nContent-Length: 4\r\n\r\nbody")
            .await
            .unwrap();

        let second = request_head(&mut server).await;
        let (scheme, negotiate) = authorization(&second).expect("negotiate");
        assert_eq!(scheme, "NTLM");
        assert_eq!(&negotiate[..12], b"NTLMSSP\0\x01\0\0\0");
        let challenge = base64::engine::general_purpose::STANDARD.encode(challenge_for(&negotiate));
        server
            .write_all(
                format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {challenge}\r\nContent-Length: 0\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();

        let third = request_head(&mut server).await;
        let (_, authenticate) = authorization(&third).expect("authenticate");
        assert_eq!(&authenticate[..12], b"NTLMSSP\0\x03\0\0\0");
        let key = third
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .to_owned();
        server
            .write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                    websocket::accept_for(&key)
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });

    let mut c = conn(client);
    let key = websocket::new_key();
    let proof = Proof::Ntlm(Credentials::domain_user_pass("D", "user", "pw"));
    let response = sign_in(
        &mut c,
        "RDG_OUT_DATA",
        "gw.example",
        "id",
        Some(&key),
        &proof,
        "CLIENT",
    )
    .await
    .expect("signed in");
    assert_eq!(response.status, 101);
    assert_eq!(
        response.header("sec-websocket-accept"),
        Some(websocket::accept_for(&key).as_str())
    );
    gw.await.unwrap();
}

/// A gateway that answers the AUTHENTICATE with another 401 has refused the
/// password, and that is an authentication failure, never retried on its own.
#[tokio::test]
async fn a_second_401_is_a_refused_password() {
    let (client, mut server) = duplex(1 << 16);
    let gw = tokio::spawn(async move {
        request_head(&mut server).await;
        server
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let second = request_head(&mut server).await;
        let (scheme, negotiate) = authorization(&second).unwrap();
        // Only Negotiate offered: the raw NTLM token goes under that name.
        assert_eq!(scheme, "Negotiate");
        let challenge = base64::engine::general_purpose::STANDARD.encode(challenge_for(&negotiate));
        server
            .write_all(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await
            .unwrap();
        request_head(&mut server).await;
        server
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut c = conn(client);
    let proof = Proof::Ntlm(Credentials::user_pass("user", "wrong"));
    let err = sign_in(&mut c, "RDG_OUT_DATA", "gw", "id", None, &proof, "CLIENT")
        .await
        .expect_err("refused");
    gw.await.unwrap();
    assert!(matches!(err, RdpError::AuthFailed(_)), "{err:?}");
    assert!(err.needs_user_action());
}

/// With a PAA cookie the request says so and carries no Authorization, and a
/// gateway that only speaks Basic is refused by name rather than being sent a
/// password in the clear.
#[tokio::test]
async fn paa_skips_the_http_sign_in_and_basic_only_is_refused() {
    let (client, mut server) = duplex(1 << 16);
    let gw = tokio::spawn(async move {
        let head = request_head(&mut server).await;
        assert!(head.contains("RDG-Auth-Scheme: PAA\r\n"));
        assert!(authorization(&head).is_none());
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut c = conn(client);
    let r = sign_in(
        &mut c,
        "RDG_IN_DATA",
        "gw",
        "id",
        None,
        &Proof::Paa("c".into()),
        "CLIENT",
    )
    .await
    .expect("paa");
    assert_eq!(r.status, 200);
    gw.await.unwrap();

    let (client, mut server) = duplex(1 << 16);
    let gw = tokio::spawn(async move {
        request_head(&mut server).await;
        server
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"gw\"\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut c = conn(client);
    let err = sign_in(
        &mut c,
        "RDG_OUT_DATA",
        "gw",
        "id",
        None,
        &Proof::Ntlm(Credentials::user_pass("u", "p")),
        "CLIENT",
    )
    .await
    .expect_err("basic only");
    gw.await.unwrap();
    assert!(err.to_string().contains("basic"), "{err}");
}

/// A 404 on the HTTP transport is a gateway that only speaks RPC over HTTP.
#[test]
fn a_gateway_without_the_http_transport_says_so() {
    let r = http::parse_head(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap();
    let err = accepted(r, "RDG_OUT_DATA").expect_err("404");
    assert!(err.to_string().contains("RPC over HTTP"), "{err}");
}

#[test]
fn the_connection_id_is_a_version_4_guid() {
    let id = connection_id();
    assert_eq!(id.len(), 36);
    assert_eq!(id.as_bytes()[14], b'4');
    assert_ne!(id, connection_id());
}

/// The separate gateway account needs both halves, and says which is missing.
#[test]
fn a_separate_gateway_account_without_a_password_is_named() {
    let mut g = GatewayOptions::new("gw");
    g.separate_credentials = true;
    g.username = Some("ops".into());
    let err = gateway_credentials(&g).expect_err("no password");
    assert!(err.to_string().contains("password"), "{err}");
    g.password = Some("pw".into());
    assert_eq!(
        gateway_credentials(&g).unwrap().username.as_deref(),
        Some("ops")
    );
}
