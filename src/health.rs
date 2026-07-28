use crate::supervision::{HealthRegistry, TileHealth};
use std::{
    fs::{self, OpenOptions},
    io,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthState {
    Starting,
    Ready,
    Degraded,
    Unhealthy,
    ShuttingDown,
}

impl HealthState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::ShuttingDown => "shutting_down",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Ready,
            2 => Self::Degraded,
            3 => Self::Unhealthy,
            4 => Self::ShuttingDown,
            _ => Self::Starting,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Starting => 0,
            Self::Ready => 1,
            Self::Degraded => 2,
            Self::Unhealthy => 3,
            Self::ShuttingDown => 4,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HealthReporter {
    inner: Arc<HealthInner>,
}

#[derive(Debug)]
struct HealthInner {
    validator_id: String,
    state: AtomicU8,
    config_valid: AtomicBool,
    keys_loaded: AtomicBool,
    socket_bound: AtomicBool,
    storage_writable: AtomicBool,
    metrics_active: AtomicBool,
    tiles: Option<HealthRegistry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub validator_id: String,
    pub state: HealthState,
    pub ready: bool,
    pub config_valid: bool,
    pub keys_loaded: bool,
    pub socket_bound: bool,
    pub storage_writable: bool,
    pub metrics_active: bool,
    pub tiles_alive: bool,
}

impl HealthReporter {
    pub fn new(validator_id: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(HealthInner {
                validator_id: validator_id.into(),
                state: AtomicU8::new(HealthState::Starting.as_u8()),
                config_valid: AtomicBool::new(false),
                keys_loaded: AtomicBool::new(false),
                socket_bound: AtomicBool::new(false),
                storage_writable: AtomicBool::new(false),
                metrics_active: AtomicBool::new(false),
                tiles: None,
            }),
        }
    }

    pub fn with_tiles(&self, tiles: HealthRegistry) -> Self {
        Self {
            inner: Arc::new(HealthInner {
                validator_id: self.inner.validator_id.clone(),
                state: AtomicU8::new(self.state().as_u8()),
                config_valid: AtomicBool::new(self.inner.config_valid.load(Ordering::Relaxed)),
                keys_loaded: AtomicBool::new(self.inner.keys_loaded.load(Ordering::Relaxed)),
                socket_bound: AtomicBool::new(self.inner.socket_bound.load(Ordering::Relaxed)),
                storage_writable: AtomicBool::new(
                    self.inner.storage_writable.load(Ordering::Relaxed),
                ),
                metrics_active: AtomicBool::new(self.inner.metrics_active.load(Ordering::Relaxed)),
                tiles: Some(tiles),
            }),
        }
    }

    pub fn mark_config_valid(&self) {
        self.inner.config_valid.store(true, Ordering::Relaxed);
    }

    pub fn mark_keys_loaded(&self) {
        self.inner.keys_loaded.store(true, Ordering::Relaxed);
    }

    pub fn mark_socket_bound(&self) {
        self.inner.socket_bound.store(true, Ordering::Relaxed);
    }

    pub fn mark_storage_writable(&self) {
        self.inner.storage_writable.store(true, Ordering::Relaxed);
    }

    pub fn mark_metrics_active(&self) {
        self.inner.metrics_active.store(true, Ordering::Relaxed);
    }

    pub fn set_ready(&self) {
        self.inner
            .state
            .store(HealthState::Ready.as_u8(), Ordering::Relaxed);
    }

    pub fn set_degraded(&self) {
        self.inner
            .state
            .store(HealthState::Degraded.as_u8(), Ordering::Relaxed);
    }

    pub fn set_unhealthy(&self) {
        self.inner
            .state
            .store(HealthState::Unhealthy.as_u8(), Ordering::Relaxed);
    }

    pub fn set_shutting_down(&self) {
        self.inner
            .state
            .store(HealthState::ShuttingDown.as_u8(), Ordering::Relaxed);
    }

    pub fn state(&self) -> HealthState {
        HealthState::from_u8(self.inner.state.load(Ordering::Relaxed))
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        let tiles_alive = self
            .inner
            .tiles
            .as_ref()
            .is_none_or(HealthRegistry::critical_tiles_alive);
        let mut state = self.state();
        if !tiles_alive {
            state = HealthState::Unhealthy;
        }
        let config_valid = self.inner.config_valid.load(Ordering::Relaxed);
        let keys_loaded = self.inner.keys_loaded.load(Ordering::Relaxed);
        let socket_bound = self.inner.socket_bound.load(Ordering::Relaxed);
        let storage_writable = self.inner.storage_writable.load(Ordering::Relaxed);
        let metrics_active = self.inner.metrics_active.load(Ordering::Relaxed);
        let ready = state == HealthState::Ready
            && config_valid
            && keys_loaded
            && socket_bound
            && storage_writable
            && metrics_active
            && tiles_alive;

        HealthSnapshot {
            validator_id: self.inner.validator_id.clone(),
            state,
            ready,
            config_valid,
            keys_loaded,
            socket_bound,
            storage_writable,
            metrics_active,
            tiles_alive,
        }
    }

    pub fn render_health_json(&self) -> String {
        let snapshot = self.snapshot();
        format!(
            "{{\"validator_id\":\"{}\",\"state\":\"{}\",\"ready\":{},\"checks\":{{\"config_valid\":{},\"keys_loaded\":{},\"socket_bound\":{},\"storage_writable\":{},\"metrics_active\":{},\"tiles_alive\":{}}}}}\n",
            escape_json(&snapshot.validator_id),
            snapshot.state.as_str(),
            snapshot.ready,
            snapshot.config_valid,
            snapshot.keys_loaded,
            snapshot.socket_bound,
            snapshot.storage_writable,
            snapshot.metrics_active,
            snapshot.tiles_alive
        )
    }
}

pub fn ensure_storage_writable(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let probe = dir.join(format!(".rpkv2-health-probe-{}", std::process::id()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)?;
    file.sync_all()?;
    drop(file);
    fs::remove_file(probe)?;
    Ok(())
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

impl HealthRegistry {
    pub fn critical_tiles_alive(&self) -> bool {
        self.snapshots().iter().all(|tile| {
            !tile.critical || matches!(tile.health, TileHealth::Running | TileHealth::Exited)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_storage_writable() {
        let health = HealthReporter::new("validator-a");
        health.mark_config_valid();
        health.mark_keys_loaded();
        health.mark_socket_bound();
        health.mark_metrics_active();
        health.set_ready();

        let snapshot = health.snapshot();

        assert_eq!(snapshot.state, HealthState::Ready);
        assert!(!snapshot.ready);
        assert!(!snapshot.storage_writable);
    }

    #[test]
    fn readiness_passes_when_all_required_checks_pass() {
        let health = HealthReporter::new("validator-a");
        health.mark_config_valid();
        health.mark_keys_loaded();
        health.mark_socket_bound();
        health.mark_storage_writable();
        health.mark_metrics_active();
        health.set_ready();

        assert!(health.snapshot().ready);
        assert!(health.render_health_json().contains("\"state\":\"ready\""));
    }

    #[test]
    fn critical_tile_panic_makes_health_unhealthy() {
        let registry = HealthRegistry::new();
        registry.register("verifier", true);
        registry.mark_panicked("verifier", "injected failure".to_string());
        let health = HealthReporter::new("validator-a").with_tiles(registry);
        health.mark_config_valid();
        health.mark_keys_loaded();
        health.mark_socket_bound();
        health.mark_storage_writable();
        health.mark_metrics_active();
        health.set_ready();

        let snapshot = health.snapshot();

        assert_eq!(snapshot.state, HealthState::Unhealthy);
        assert!(!snapshot.ready);
        assert!(!snapshot.tiles_alive);
    }
}
