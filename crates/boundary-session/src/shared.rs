//! One endpoint per lasting helper identity, shared by every session that
//! connects as it.
//!
//! A relay keeps one connection per endpoint ID. When DeskVNC opened a second
//! Boundary tab, that tab bound its own endpoint with the same helper key,
//! the relay told the first one "another endpoint connected with the same
//! endpoint id" and stopped passing it messages, and a first session that
//! still needed the relay froze a second after the new tab opened. Sessions
//! in one process now take the same endpoint and it closes when the last of
//! them lets go.

use crate::{
    HostOptions,
    session::{self, Lookup},
};
use anyhow::Result;
use iroh::{Endpoint, SecretKey};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, Weak},
};

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    id: iroh::EndpointId,
    relay: bool,
    relay_url: Option<String>,
    bind_ip: Option<IpAddr>,
}

static POOL: Mutex<Option<HashMap<Key, Weak<Inner>>>> = Mutex::new(None);
/// Held while an endpoint is being bound, so two tabs opening at once do
/// not each bind one.
static BINDING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Inner(Endpoint);
impl Drop for Inner {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move { endpoint.close().await });
        }
    }
}

/// An endpoint some session is using. It closes when the last one is dropped.
#[derive(Clone)]
pub(crate) struct Shared(Arc<Inner>);
impl std::ops::Deref for Shared {
    type Target = Endpoint;
    fn deref(&self) -> &Endpoint {
        &self.0.0
    }
}

/// The endpoint for this helper key and these network options, bound the
/// first time and shared after that. It can find machines by ID, which an
/// invitation does not need and does not mind.
pub(crate) async fn helper(options: &HostOptions, key: SecretKey) -> Result<Shared> {
    let wanted = Key {
        id: key.public(),
        relay: options.relay,
        relay_url: options.relay_url.clone().filter(|s| !s.trim().is_empty()),
        bind_ip: options.bind_ip,
    };
    let _binding = BINDING.lock().await;
    if let Some(inner) = POOL
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .get(&wanted)
        .and_then(Weak::upgrade)
        .filter(|inner| !inner.0.is_closed())
    {
        return Ok(Shared(inner));
    }
    let inner = Arc::new(Inner(
        session::endpoint_with(options, Some(key), Lookup::Resolve).await?,
    ));
    let mut pool = POOL.lock().unwrap();
    let pool = pool.get_or_insert_with(HashMap::new);
    pool.retain(|_, weak| weak.strong_count() > 0);
    pool.insert(wanted, Arc::downgrade(&inner));
    Ok(Shared(inner))
}
