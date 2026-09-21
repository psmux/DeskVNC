//! A bounded, temporary invitation directory. Deploy behind trusted HTTPS.
use crate::{Issued, Lookup, Register, Revoke, normalize_code};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct Entry {
    invitation: String,
    revoke: String,
    deadline: Instant,
}
#[derive(Default)]
struct Store {
    entries: HashMap<String, Entry>,
    rates: HashMap<IpAddr, (Instant, u32)>,
    total: Option<(Instant, u32)>,
}
#[derive(Clone, Default)]
pub struct Service(Arc<Mutex<Store>>);
impl Service {
    pub fn router(self) -> Router {
        let weak = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let Some(store) = weak.upgrade() else {
                    break;
                };
                if let Ok(mut store) = store.lock() {
                    store
                        .entries
                        .retain(|_, entry| entry.deadline > Instant::now());
                }
            }
        });
        Router::new()
            .route("/v1/register", post(register))
            .route("/v1/resolve", post(resolve))
            .route("/v1/revoke", post(revoke))
            .layer(DefaultBodyLimit::max(20000))
            .layer(middleware::from_fn_with_state(self.clone(), limit))
            .with_state(self)
    }
}
async fn limit(
    State(service): State<Service>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    {
        let mut store = service
            .0
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let now = Instant::now();
        store.entries.retain(|_, entry| entry.deadline > now);
        store
            .rates
            .retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
        if store
            .total
            .is_none_or(|(start, _)| now.duration_since(start) >= Duration::from_secs(60))
        {
            store.total = Some((now, 0));
        }
        let total = &mut store.total.as_mut().unwrap().1;
        if *total >= 120 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        *total += 1;
        let (_, count) = store.rates.entry(peer.ip()).or_insert((now, 0));
        if *count >= 20 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        *count += 1;
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(response)
}
fn random() -> Result<[u8; 32], StatusCode> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(bytes)
}
fn digits() -> Result<String, StatusCode> {
    let mut code = String::new();
    while code.len() < 12 {
        for byte in random()? {
            if byte < 250 {
                code.push(char::from(b'0' + byte % 10));
            }
            if code.len() == 12 {
                break;
            }
        }
    }
    Ok(code)
}
async fn register(
    State(service): State<Service>,
    Json(body): Json<Register>,
) -> Result<Json<Issued>, StatusCode> {
    let invitation = boundary_session::Invitation::decode(&body.invitation)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs();
    let duration = Duration::from_secs(invitation.expires.saturating_sub(now).min(600));
    let mut store = service
        .0
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if store.entries.len() >= 1024 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let code = loop {
        let code = digits()?;
        if !store.entries.contains_key(&code) {
            break code;
        }
    };
    let revoke: String = random()?.iter().map(|byte| format!("{byte:02x}")).collect();
    store.entries.insert(
        code.clone(),
        Entry {
            invitation: body.invitation,
            revoke: revoke.clone(),
            deadline: Instant::now() + duration,
        },
    );
    Ok(Json(Issued { code, revoke }))
}
async fn resolve(
    State(service): State<Service>,
    Json(body): Json<Lookup>,
) -> Result<Json<Register>, StatusCode> {
    let code = normalize_code(&body.code).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut store = service
        .0
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let entry = store.entries.remove(&code).ok_or(StatusCode::NOT_FOUND)?;
    if entry.deadline <= Instant::now() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(Register {
        invitation: entry.invitation,
    }))
}
async fn revoke(
    State(service): State<Service>,
    Json(body): Json<Revoke>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if body.token.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut store = service
        .0
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    store.entries.retain(|_, entry| entry.revoke != body.token);
    Ok(Json(serde_json::json!({"ok": true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;
    use boundary_session::{Approval, Desktop, Event, Frame, HostOptions, Input, Session};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fake(Arc<AtomicUsize>);
    impl Desktop for Fake {
        fn capture(&mut self) -> anyhow::Result<Frame> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Frame {
                width: 1,
                height: 1,
                rgba: vec![1, 2, 3, 255],
            })
        }
        fn input(&mut self, _: Input) -> anyhow::Result<()> {
            Ok(())
        }
        fn release(&mut self) {}
    }
    fn options() -> HostOptions {
        HostOptions {
            relay: false,
            relay_url: None,
            bind_ip: None,
        }
    }
    async fn ticket() -> (Session, String, Arc<AtomicUsize>) {
        let captures = Arc::new(AtomicUsize::new(0));
        let probe = captures.clone();
        let mut host = boundary_session::host(options(), move || Ok(Box::new(Fake(probe))));
        loop {
            match event(&mut host).await {
                Event::Invitation(ticket) => return (host, ticket, captures),
                Event::Finished(result) => panic!("Host stopped: {result:?}"),
                _ => {}
            }
        }
    }
    async fn event(session: &mut Session) -> Event {
        tokio::time::timeout(Duration::from_secs(5), session.events.recv())
            .await
            .unwrap()
            .unwrap()
    }
    async fn start() -> (Service, Client, tokio::task::JoinHandle<()>) {
        let service = Service::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = Client::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let router = service.clone().router();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (service, client, task)
    }
    #[tokio::test]
    async fn numeric_lookup_connects_only_after_host_consent_and_is_single_use() {
        let (_, client, task) = start().await;
        let (mut host, ticket, captures) = ticket().await;
        let lease = client.register(ticket).await.unwrap();
        let resolved = client.resolve(&lease.display()).await.unwrap();
        assert!(client.resolve(&lease.code).await.is_err());
        let mut viewer = boundary_session::viewer(resolved, "Code test".into(), options());
        loop {
            if let Event::Approval { answer, .. } = event(&mut host).await {
                assert_eq!(captures.load(Ordering::SeqCst), 0);
                answer.send(Approval::View).ok().unwrap();
                break;
            }
        }
        tokio::time::timeout(Duration::from_secs(5), viewer.frames.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            viewer.frames.borrow().as_ref().unwrap().rgba,
            vec![1, 2, 3, 255]
        );
        host.stop();
        viewer.stop();
        task.abort();
    }
    #[tokio::test]
    async fn revoked_and_expired_codes_cannot_resolve() {
        let (service, client, task) = start().await;
        let (_host, ticket, _) = ticket().await;
        let lease = client.register(ticket.clone()).await.unwrap();
        let code = lease.code.clone();
        drop(lease);
        tokio::time::timeout(Duration::from_secs(2), async {
            while service.0.lock().unwrap().entries.contains_key(&code) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(client.resolve(&code).await.is_err());
        let lease = client.register(ticket).await.unwrap();
        service
            .0
            .lock()
            .unwrap()
            .entries
            .get_mut(&lease.code)
            .unwrap()
            .deadline = Instant::now();
        assert!(client.resolve(&lease.code).await.is_err());
        task.abort();
    }
    #[tokio::test]
    async fn guessing_is_rate_limited_and_secrets_are_not_in_urls() {
        let (_, client, task) = start().await;
        for _ in 0..20 {
            assert!(client.resolve("000000000000").await.is_err());
        }
        let response = client
            .http
            .post(client.base.join("v1/resolve").unwrap())
            .json(&Lookup {
                code: "000000000000".into(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        task.abort();
    }
}
