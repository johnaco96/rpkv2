use crate::{shutdown::Shutdown, tiles::Tile};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TileHealth {
    Running,
    Exited,
    Panicked(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TileHealthSnapshot {
    pub name: String,
    pub critical: bool,
    pub health: TileHealth,
}

#[derive(Clone, Debug, Default)]
pub struct HealthRegistry {
    inner: Arc<Mutex<BTreeMap<String, TileHealthSnapshot>>>,
}

impl HealthRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, name: impl Into<String>, critical: bool) {
        let name = name.into();
        let mut inner = self.inner.lock().expect("health registry lock poisoned");
        inner.insert(
            name.clone(),
            TileHealthSnapshot {
                name,
                critical,
                health: TileHealth::Running,
            },
        );
    }

    pub fn mark_exited(&self, name: &str) {
        self.update(name, TileHealth::Exited);
    }

    pub fn mark_panicked(&self, name: &str, reason: String) {
        self.update(name, TileHealth::Panicked(reason));
    }

    pub fn snapshots(&self) -> Vec<TileHealthSnapshot> {
        self.inner
            .lock()
            .expect("health registry lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub fn is_healthy(&self) -> bool {
        self.snapshots()
            .iter()
            .all(|tile| matches!(tile.health, TileHealth::Running | TileHealth::Exited))
    }

    pub fn metrics_text(&self) -> String {
        let mut out = String::new();
        for tile in self.snapshots() {
            let healthy = match tile.health {
                TileHealth::Running | TileHealth::Exited => 1,
                TileHealth::Panicked(_) => 0,
            };
            out.push_str(&format!(
                "rpkv2_tile_health{{tile=\"{}\",critical=\"{}\"}} {}\n",
                tile.name, tile.critical, healthy
            ));
        }
        out
    }

    fn update(&self, name: &str, health: TileHealth) {
        let mut inner = self.inner.lock().expect("health registry lock poisoned");
        if let Some(tile) = inner.get_mut(name) {
            tile.health = health;
        }
    }
}

#[derive(Debug)]
pub struct TileFailure {
    pub tile: String,
    pub reason: String,
}

impl fmt::Display for TileFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "critical tile '{}' failed: {}", self.tile, self.reason)
    }
}

impl Error for TileFailure {}

struct SupervisedTile {
    name: String,
    critical: bool,
    handle: JoinHandle<()>,
}

pub struct TileSupervisor {
    shutdown: Shutdown,
    health: HealthRegistry,
    workers: Vec<SupervisedTile>,
}

impl TileSupervisor {
    pub fn new(shutdown: Shutdown) -> Self {
        Self {
            shutdown,
            health: HealthRegistry::new(),
            workers: Vec::new(),
        }
    }

    pub fn health(&self) -> HealthRegistry {
        self.health.clone()
    }

    pub fn spawn_critical<T: Tile>(&mut self, name: &'static str, tile: T) {
        self.spawn(name, true, tile);
    }

    pub fn spawn<T: Tile>(&mut self, name: &'static str, critical: bool, tile: T) {
        self.health.register(name, critical);
        let handle = tile.start_with_shutdown(self.shutdown.clone());
        self.workers.push(SupervisedTile {
            name: name.to_string(),
            critical,
            handle,
        });
    }

    pub fn poll(&mut self) -> Result<(), TileFailure> {
        let mut i = 0;
        while i < self.workers.len() {
            if !self.workers[i].handle.is_finished() {
                i += 1;
                continue;
            }

            let worker = self.workers.swap_remove(i);
            match worker.handle.join() {
                Ok(()) => self.health.mark_exited(&worker.name),
                Err(panic) => {
                    let reason = panic_reason(panic);
                    self.health.mark_panicked(&worker.name, reason.clone());
                    if worker.critical {
                        self.shutdown.request();
                        return Err(TileFailure {
                            tile: worker.name,
                            reason,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub fn shutdown_and_join(mut self) -> Result<(), TileFailure> {
        self.shutdown.request();
        let mut failure = None;
        for worker in self.workers.drain(..) {
            match worker.handle.join() {
                Ok(()) => self.health.mark_exited(&worker.name),
                Err(panic) => {
                    let reason = panic_reason(panic);
                    self.health.mark_panicked(&worker.name, reason.clone());
                    if worker.critical && failure.is_none() {
                        failure = Some(TileFailure {
                            tile: worker.name,
                            reason,
                        });
                    }
                }
            }
        }

        if let Some(failure) = failure {
            Err(failure)
        } else {
            Ok(())
        }
    }
}

fn panic_reason(panic: Box<dyn std::any::Any + Send + 'static>) -> String {
    if let Some(reason) = panic.downcast_ref::<&'static str>() {
        (*reason).to_string()
    } else if let Some(reason) = panic.downcast_ref::<String>() {
        reason.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    struct PanicTile;

    impl Tile for PanicTile {
        fn start_with_shutdown(self, _shutdown: Shutdown) -> JoinHandle<()> {
            thread::spawn(|| panic!("injected tile panic"))
        }
    }

    struct WaitTile;

    impl Tile for WaitTile {
        fn start_with_shutdown(self, shutdown: Shutdown) -> JoinHandle<()> {
            thread::spawn(move || {
                while !shutdown.is_requested() {
                    thread::sleep(Duration::from_millis(1));
                }
            })
        }
    }

    #[test]
    fn critical_tile_panic_is_visible_and_requests_shutdown() {
        let shutdown = Shutdown::new();
        let mut supervisor = TileSupervisor::new(shutdown.clone());
        supervisor.spawn_critical("panic", PanicTile);

        let err = loop {
            if let Err(err) = supervisor.poll() {
                break err;
            }
            thread::sleep(Duration::from_millis(1));
        };

        assert_eq!(err.tile, "panic");
        assert!(err.reason.contains("injected tile panic"));
        assert!(shutdown.is_requested());
        assert!(!supervisor.health().is_healthy());
        assert!(supervisor.health().metrics_text().contains("panic"));
        assert!(supervisor.health().metrics_text().contains(" 0\n"));
    }

    #[test]
    fn shutdown_and_join_marks_clean_exit_healthy() {
        let shutdown = Shutdown::new();
        let mut supervisor = TileSupervisor::new(shutdown);
        supervisor.spawn_critical("wait", WaitTile);
        let health = supervisor.health();

        supervisor.shutdown_and_join().unwrap();

        assert!(health.is_healthy());
        assert!(health.metrics_text().contains(" 1\n"));
    }
}
