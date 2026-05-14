use anyhow::{Context, Result, anyhow};
use clap::Parser;
use csv::{Reader, StringRecord};
use std::{collections::HashMap, fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "bench_summary")]
struct Args {
    #[arg(long)]
    tx: PathBuf,
    #[arg(long)]
    rx: PathBuf,
    #[arg(long)]
    payload: Option<u64>,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug)]
struct Summary {
    tx_packets: u64,
    rx_packets: u64,
    est_loss_count: u64,
    est_loss_percent: f64,
    duration_secs: Option<f64>,
    effective_tx_pps: Option<f64>,
    effective_rx_pps: Option<f64>,
    throughput_mbps: Option<f64>,
    latency_p50_us: Option<f64>,
    latency_p90_us: Option<f64>,
    latency_p99_us: Option<f64>,
    latency_p999_us: Option<f64>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let tx = load_summary_row(&args.tx, "tx")?;
    let rx = load_summary_row(&args.rx, "rx")?;

    let tx_packets = required_u64(&tx, "packets_sent")?;
    let rx_packets = required_u64(&rx, "received_packets")?;

    let est_loss_count = optional_u64(&rx, "estimated_loss")
        .unwrap_or_else(|| tx_packets.saturating_sub(rx_packets));
    let est_loss_percent = optional_f64(&rx, "loss_pct").unwrap_or_else(|| {
        if tx_packets > 0 {
            (est_loss_count as f64) * 100.0 / tx_packets as f64
        } else {
            0.0
        }
    });

    let duration_secs =
        optional_f64(&tx, "duration_secs").or_else(|| optional_f64(&rx, "run_duration_secs"));

    let effective_tx_pps = optional_f64(&tx, "achieved_pps").or_else(|| {
        duration_secs.and_then(|d| {
            if d > 0.0 {
                Some(tx_packets as f64 / d)
            } else {
                None
            }
        })
    });

    let effective_rx_pps = duration_secs.and_then(|d| {
        if d > 0.0 {
            Some(rx_packets as f64 / d)
        } else {
            None
        }
    });

    let payload_bytes = args.payload.or_else(|| optional_u64(&tx, "payload_bytes"));
    let throughput_mbps = optional_f64(&rx, "throughput_mbps")
        .or_else(|| match (effective_rx_pps, payload_bytes) {
            (Some(pps), Some(payload)) => Some((pps * payload as f64 * 8.0) / 1_000_000.0),
            _ => None,
        })
        .or_else(|| match (effective_tx_pps, payload_bytes) {
            (Some(pps), Some(payload)) => Some((pps * payload as f64 * 8.0) / 1_000_000.0),
            _ => None,
        });

    let summary = Summary {
        tx_packets,
        rx_packets,
        est_loss_count,
        est_loss_percent,
        duration_secs,
        effective_tx_pps,
        effective_rx_pps,
        throughput_mbps,
        latency_p50_us: optional_f64(&rx, "p50_us"),
        latency_p90_us: optional_f64(&rx, "p90_us"),
        latency_p99_us: optional_f64(&rx, "p99_us"),
        latency_p999_us: optional_f64(&rx, "p999_us"),
    };

    print_human(&summary);

    if let Some(out) = args.out {
        fs::write(&out, render_json(&summary))
            .with_context(|| format!("failed to write {}", out.display()))?;
        eprintln!("wrote summary JSON to {}", out.display());
    }

    Ok(())
}

fn load_summary_row(path: &PathBuf, label: &str) -> Result<HashMap<String, String>> {
    let mut rdr = Reader::from_path(path)
        .with_context(|| format!("{label} file not found or unreadable: {}", path.display()))?;

    let headers = rdr
        .headers()
        .with_context(|| format!("{label} csv missing header row: {}", path.display()))?
        .clone();

    let row = first_data_row(&mut rdr)
        .with_context(|| format!("{label} csv has no data rows: {}", path.display()))?;

    Ok(headers
        .iter()
        .zip(row.iter())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

fn first_data_row(rdr: &mut Reader<std::fs::File>) -> Result<StringRecord> {
    let mut iter = rdr.records();
    let rec = iter
        .next()
        .ok_or_else(|| anyhow!("missing first record"))??;
    Ok(rec)
}

fn required_u64(map: &HashMap<String, String>, key: &str) -> Result<u64> {
    optional_u64(map, key).ok_or_else(|| bail_parse(key, "u64"))
}

fn optional_u64(map: &HashMap<String, String>, key: &str) -> Option<u64> {
    map.get(key).and_then(|v| v.parse::<u64>().ok())
}

fn optional_f64(map: &HashMap<String, String>, key: &str) -> Option<f64> {
    map.get(key).and_then(|v| v.parse::<f64>().ok())
}

fn bail_parse(col: &str, typ: &str) -> anyhow::Error {
    anyhow!("required column '{col}' missing or malformed ({typ})")
}

fn print_human(s: &Summary) {
    println!("tx packet count: {}", s.tx_packets);
    println!("rx packet count: {}", s.rx_packets);
    println!("estimated loss count: {}", s.est_loss_count);
    println!("estimated loss percent: {:.3}%", s.est_loss_percent);
    println!(
        "duration seconds: {}",
        s.duration_secs
            .map(|v| format!("{v:.6}"))
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "effective tx pps: {}",
        s.effective_tx_pps
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "effective rx pps: {}",
        s.effective_rx_pps
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "throughput Mbps: {}",
        s.throughput_mbps
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "latency quantiles us: p50={} p90={} p99={} p999={}",
        fmt_opt(s.latency_p50_us),
        fmt_opt(s.latency_p90_us),
        fmt_opt(s.latency_p99_us),
        fmt_opt(s.latency_p999_us),
    );
}

fn fmt_opt(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.3}"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn render_json(s: &Summary) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"tx_packet_count\": {},\n",
            "  \"rx_packet_count\": {},\n",
            "  \"estimated_loss_count\": {},\n",
            "  \"estimated_loss_percent\": {:.6},\n",
            "  \"duration_seconds\": {},\n",
            "  \"effective_tx_pps\": {},\n",
            "  \"effective_rx_pps\": {},\n",
            "  \"throughput_mbps\": {},\n",
            "  \"latency_p50_us\": {},\n",
            "  \"latency_p90_us\": {},\n",
            "  \"latency_p99_us\": {},\n",
            "  \"latency_p999_us\": {}\n",
            "}}\n"
        ),
        s.tx_packets,
        s.rx_packets,
        s.est_loss_count,
        s.est_loss_percent,
        json_opt(s.duration_secs),
        json_opt(s.effective_tx_pps),
        json_opt(s.effective_rx_pps),
        json_opt(s.throughput_mbps),
        json_opt(s.latency_p50_us),
        json_opt(s.latency_p90_us),
        json_opt(s.latency_p99_us),
        json_opt(s.latency_p999_us),
    )
}

fn json_opt(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.6}"),
        None => "null".to_string(),
    }
}
