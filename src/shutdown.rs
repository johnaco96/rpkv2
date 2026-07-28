use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug, Default)]
pub struct Shutdown {
    requested: Arc<AtomicBool>,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
    }

    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_request_is_shared_across_clones() {
        let shutdown = Shutdown::new();
        let clone = shutdown.clone();

        assert!(!shutdown.is_requested());
        clone.request();
        assert!(shutdown.is_requested());
    }
}
