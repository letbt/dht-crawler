use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use lru::LruCache;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct BlackList {
    cache: Arc<Mutex<LruCache<SocketAddr, Instant>>>,
}

impl BlackList {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).unwrap(),
            ))),
        }
    }

    pub async fn contains(&self, addr: &SocketAddr) -> bool {
        let cache = self.cache.lock().await;
        cache.contains(addr)
    }

    pub async fn insert(&mut self, addr: SocketAddr) {
        let mut cache = self.cache.lock().await;
        cache.put(addr, Instant::now());
    }
}
