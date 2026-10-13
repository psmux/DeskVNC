//! Real loopback TCP peer using the independent server-side SRP equation.
use super::*;
use num_bigint_dig::BigUint;
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "fixture-é";
const PASSWORD: &str = "synthetic test password";

async fn server_auth(stream: &mut TcpStream, bad_proof: bool) -> Result<Vec<u8>> {
    let mut preamble = [0; 14];
    stream.read_exact(&mut preamble).await?;
    ensure!(preamble == auth::PREAMBLE, "Wrong client preamble");
    stream
        .write_all(&[1, 0, 0, 0, 5, 0, 0, 0, 0x27, 0x27, 0, 0, 0, 0])
        .await?;
    let request = read_record(stream).await?;
    let entries = auth::tlvs(&request)?;
    let user: Vec<u8> = USER.encode_utf16().flat_map(u16::to_be_bytes).collect();
    ensure!(
        entries == [(0x10, &[0, 0, 0, 1][..]), (0x20, user.as_slice())],
        "Wrong client identity"
    );
    let group = auth::modulus();
    let n = BigUint::from_bytes_be(&group);
    let g = BigUint::from(5u32);
    let salt: Vec<u8> = (0..32).collect();
    let identity = auth::utf16le(USER);
    let x = BigUint::from_bytes_be(&auth::hash(&[
        &salt,
        &auth::hash(&[&identity, b":", &auth::utf16le(PASSWORD)]),
    ]));
    let verifier = g.modpow(&x, &n);
    let k = BigUint::from_bytes_be(&auth::hash(&[&group, &auth::padded(&[5])]));
    let b = BigUint::parse_bytes(b"badc0ffee123456789abcdef", 16).unwrap();
    let public_b = ((k * &verifier + g.modpow(&b, &n)) % &n).to_bytes_be();
    // Fragment each response byte to exercise partial header/payload reads.
    for byte in auth::packet(2, &[(0x30, &group), (0x40, &[5]), (0x50, &salt)]) {
        stream.write_u8(byte).await?;
    }
    let request = read_record(stream).await?;
    let entries = auth::tlvs(&request)?;
    let public_a = entries
        .iter()
        .find(|(t, _)| *t == 0x60)
        .context("Missing A")?
        .1;
    let u = BigUint::from_bytes_be(&auth::hash(&[
        &auth::padded(public_a),
        &auth::padded(&public_b),
    ]));
    let secret = ((BigUint::from_bytes_be(public_a) * verifier.modpow(&u, &n)) % &n)
        .modpow(&b, &n)
        .to_bytes_be();
    let mut key = auth::hash(&[&secret, &[0, 0, 0, 0]]);
    key.extend(auth::hash(&[&secret, &[0, 0, 0, 1]]));
    let xor: Vec<u8> = auth::hash(&[&group])
        .iter()
        .zip(auth::hash(&[&[5]]))
        .map(|(x, y)| x ^ y)
        .collect();
    let m1 = auth::hash(&[
        &xor,
        &auth::hash(&[&identity]),
        &salt,
        public_a,
        &public_b,
        &key,
    ]);
    let m2 = if bad_proof {
        vec![0; 20]
    } else {
        auth::hash(&[public_a, &m1, &key])
    };
    stream
        .write_all(&auth::packet(4, &[(0x60, &public_b)]))
        .await?;
    let request = read_record(stream).await?;
    ensure!(
        auth::tlvs(&request)?
            .iter()
            .any(|(t, v)| *t == 0x70 && *v == m1),
        "Client proof mismatch"
    );
    stream.write_all(&auth::packet(6, &[(0x70, &m2)])).await?;
    Ok(key)
}

async fn peer(listener: TcpListener, view_only: bool, partial: bool) -> Result<Vec<Vec<u8>>> {
    let (mut socket, _) = listener.accept().await?;
    let key = server_auth(&mut socket, false).await?;
    ensure!(
        read_record(&mut socket).await? == [0x2e],
        "Wrong channel request"
    );
    let mut token = vec![0x2e];
    token.extend(0u8..32);
    write_record(&mut socket, &token).await?;
    let mut tx = CipherState::new(&key[..32], &token[1..17])?;
    let mut rx = CipherState::new(&key[..32], &token[17..33])?;
    let mode = rx.decrypt(read_record(&mut socket).await?)?;
    ensure!(
        mode == [0x1a, 0, 0, 0, if view_only { 6 } else { 1 }],
        "Wrong desktop mode"
    );
    encrypted_send(&mut socket, &mut tx, &[0x1a]).await?;
    ensure!(
        rx.decrypt(read_record(&mut socket).await?)? == [0x32],
        "Wrong desktop negotiation"
    );
    encrypted_send(&mut socket, &mut tx, &[0x32]).await?;
    ensure!(
        rx.decrypt(read_record(&mut socket).await?)? == [0x28],
        "Wrong desktop start"
    );
    encrypted_send(&mut socket, &mut tx, &[0x28]).await?;
    let mut compression = desktop::Deflate::default();
    let setup = compression.decode(&rx.decrypt(read_record(&mut socket).await?)?)?;
    ensure!(
        desktop::fields(&setup, false)?.len() == 3,
        "Wrong image request"
    );
    let mut image = desktop::tlv(
        0x10000000,
        &[24u32, 0xff0000, 0xff00, 0xff]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>(),
    );
    image.extend(desktop::tlv(0x30000000, &[0, 0, 0, 2, 0, 0, 0, 2]));
    image.extend(desktop::tlv(
        0x40000000,
        &[0, 0, 255, 0, 255, 0, 0, 0, 255, 0, 0, 255, 255, 255, 0, 0],
    ));
    encrypted_send(&mut socket, &mut tx, &compression.encode(&image)?).await?;
    if partial {
        socket.write_all(&[0, 0, 0, 32, 1]).await?;
    }
    let mut received = Vec::new();
    while let Ok(data) = read_record(&mut socket).await {
        received.push(compression.decode(&rx.decrypt(data)?)?);
    }
    Ok(received)
}

#[tokio::test]
async fn native_driver_authenticates_renders_controls_and_releases_over_tcp() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(peer(listener, false, false));
        let mut options = ConnectOptions::radmin("127.0.0.1", port);
        options.credentials = Credentials::user_pass(USER, PASSWORD);
        let (events, mut rx) = mpsc::channel(16);
        let handle = RadminDriver
            .spawn("tcp-fixture".into(), options, events)
            .unwrap();
        loop {
            match rx.recv().await.unwrap() {
                SessionEvent::FramebufferUpdate { rects, .. } => {
                    let RectPayload::Rgba(pixels) = &rects[0].payload else {
                        panic!()
                    };
                    assert_eq!(&pixels[..8], &[255, 0, 0, 255, 0, 255, 0, 255]);
                    break;
                }
                SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                    panic!("{reason}")
                }
                _ => {}
            }
        }
        handle.send(ClientCommand::SecureAttention).await.unwrap();
        handle
            .send(ClientCommand::Key {
                keysym: 97,
                keycode: Some(0x1e),
                down: true,
            })
            .await
            .unwrap();
        handle.send(ClientCommand::SetViewOnly(true)).await.unwrap();
        handle.send(ClientCommand::SecureAttention).await.unwrap();
        handle
            .send(ClientCommand::Key {
                keysym: 98,
                keycode: Some(0x30),
                down: true,
            })
            .await
            .unwrap();
        handle.send(ClientCommand::Disconnect).await.unwrap();
        let messages = server.await.unwrap().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(hex::encode(&messages[0]), "700000010e");
        assert_eq!(hex::encode(&messages[1]), "70000006004101001e00");
        assert_eq!(hex::encode(&messages[2]), "70000006024100000000");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn invalid_server_proof_never_reaches_connected() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_auth(&mut stream, true).await.unwrap();
        });
        let mut options = ConnectOptions::radmin("127.0.0.1", port);
        options.credentials = Credentials::user_pass(USER, PASSWORD);
        let (events, mut rx) = mpsc::channel(16);
        let _handle = RadminDriver
            .spawn("bad-proof".into(), options, events)
            .unwrap();
        while let Some(event) = rx.recv().await {
            match event {
                SessionEvent::StateChanged(SessionState::Connected) => {
                    panic!("Unverified server accepted")
                }
                SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                    assert!(reason.contains("proof"));
                    break;
                }
                _ => {}
            }
        }
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_enforced_view_only_cannot_be_escalated_by_commands() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(peer(listener, true, false));
        let mut options = ConnectOptions::radmin("127.0.0.1", port);
        options.credentials = Credentials::user_pass(USER, PASSWORD);
        options.view_only = true;
        let (events, mut rx) = mpsc::channel(16);
        let handle = RadminDriver
            .spawn("view-fixture".into(), options, events)
            .unwrap();
        loop {
            match rx.recv().await.unwrap() {
                SessionEvent::FramebufferUpdate { .. } => break,
                SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                    panic!("{reason}")
                }
                _ => {}
            }
        }
        handle
            .send(ClientCommand::SetViewOnly(false))
            .await
            .unwrap();
        handle.send(ClientCommand::SecureAttention).await.unwrap();
        handle
            .send(ClientCommand::Pointer {
                x: 1,
                y: 1,
                button_mask: 1,
            })
            .await
            .unwrap();
        handle
            .send(ClientCommand::ClipboardText("must not send".into()))
            .await
            .unwrap();
        handle.send(ClientCommand::Disconnect).await.unwrap();
        assert!(server.await.unwrap().unwrap().is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancellation_closes_a_partial_record_without_waiting_for_its_deadline() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(peer(listener, false, true));
        let mut options = ConnectOptions::radmin("127.0.0.1", port);
        options.credentials = Credentials::user_pass(USER, PASSWORD);
        let (events, mut rx) = mpsc::channel(16);
        let handle = RadminDriver
            .spawn("partial-record".into(), options, events)
            .unwrap();
        loop {
            match rx.recv().await.unwrap() {
                SessionEvent::FramebufferUpdate { .. } => break,
                SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                    panic!("{reason}")
                }
                _ => {}
            }
        }
        handle.shutdown();
        assert!(tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .is_empty());
    })
    .await
    .unwrap();
}
