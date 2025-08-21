// src/util.rs
use hdrhistogram::Histogram;
use std::{fs::File, time::{Duration, Instant}};
use csv::Writer;

pub struct Timer(Instant);
impl Timer {
    pub fn start() -> Self { Timer(Instant::now()) }
    pub fn elapsed_us(&self) -> u64 { self.0.elapsed().as_micros() as u64 }
}

pub struct Histo(Histogram<u64>);
impl Histo {
    pub fn new(max_us: u64) -> Self {
        Histo(Histogram::new_with_bounds(1, max_us, 3).unwrap())
    }
    pub fn record_us(&mut self, v: u64) { let _ = self.0.record(v); }
    pub fn p(&self, q: f64) -> u64 { self.0.value_at_quantile(q) }
    pub fn mean(&self) -> f64 { self.0.mean() }
    pub fn count(&self) -> u64 { self.0.len() as u64 }
    pub fn write_csv(&self, path: &str) -> anyhow::Result<()> {
        let mut w = Writer::from_writer(File::create(path)?);
        w.write_record(&["quantile","usec"])?;
        for &(q, name) in &[
            (0.50,"p50"), (0.90,"p90"), (0.99,"p99"), (0.999,"p999")
        ] {
            let v = self.p(q);
            w.write_record(&[name, &v.to_string()])?;
        }
        w.flush()?;
        Ok(())
    }
}

pub fn pretty_throughput(bytes: u64, dur: Duration) -> String {
    let bps = (bytes as f64) / dur.as_secs_f64();
    if bps > 1e9 { format!("{:.2} GB/s", bps/1e9) }
    else if bps > 1e6 { format!("{:.2} MB/s", bps/1e6) }
    else if bps > 1e3 { format!("{:.2} KB/s", bps/1e3) }
    else { format!("{:.0} B/s", bps) }
}
