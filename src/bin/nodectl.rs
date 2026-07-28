use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rpkv2::{node_lifecycle, tiles::storage::StorageRecoveryPolicy};
use std::{path::PathBuf, process::Command};

#[derive(Parser)]
#[command(name = "nodectl", about = "rpkv2 validator node lifecycle commands")]
struct Cli {
    #[command(subcommand)]
    command: NodeCommand,
}

#[derive(Subcommand)]
enum NodeCommand {
    Init {
        #[arg(long)]
        validator_id: String,
        #[arg(long)]
        node_dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    Start {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        exec: bool,
    },
    Stop {
        #[arg(long)]
        pid_file: PathBuf,
        #[arg(long)]
        remove_pid_file: bool,
    },
    Status {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        pid_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    ValidateConfig {
        #[arg(long)]
        config: PathBuf,
    },
    RepairLedger {
        #[arg(long)]
        storage_dir: PathBuf,
        #[arg(value_enum, long, default_value_t = RecoveryPolicyArg::FailStartup)]
        policy: RecoveryPolicyArg,
    },
    Snapshot {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    RestoreSnapshot {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    Version,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RecoveryPolicyArg {
    FailStartup,
    QuarantineCorrupt,
}

impl From<RecoveryPolicyArg> for StorageRecoveryPolicy {
    fn from(value: RecoveryPolicyArg) -> Self {
        match value {
            RecoveryPolicyArg::FailStartup => Self::FailStartup,
            RecoveryPolicyArg::QuarantineCorrupt => Self::QuarantineCorrupt,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        NodeCommand::Init {
            validator_id,
            node_dir,
            overwrite,
        } => {
            let report = node_lifecycle::init_node(&validator_id, node_dir, overwrite)?;
            println!("node_dir={}", report.node_dir.display());
            println!(
                "config_template_path={}",
                report.config_template_path.display()
            );
            println!("storage_dir={}", report.storage_dir.display());
            println!("run_dir={}", report.run_dir.display());
            println!("snapshot_dir={}", report.snapshot_dir.display());
            println!(
                "public_identity_path={}",
                report.identity.public_identity_path.display()
            );
        }
        NodeCommand::Start { config, exec } => {
            let plan = node_lifecycle::start_plan(&config)?;
            println!("config_valid=true");
            println!("validator_id={}", plan.validator_id);
            println!("bind_address={}", plan.bind_address);
            println!("metrics_address={}", plan.metrics_address);
            println!("storage_dir={}", plan.storage_dir.display());
            println!("command={}", plan.command.join(" "));
            if exec {
                let mut command = Command::new(&plan.command[0]);
                command.args(&plan.command[1..]);
                command.status()?;
            } else {
                println!("dry_run=true");
            }
        }
        NodeCommand::Stop {
            pid_file,
            remove_pid_file,
        } => {
            let pid = node_lifecycle::stop_with_pid_file(&pid_file, remove_pid_file)?;
            println!("pid_file={}", pid_file.display());
            println!(
                "pid={}",
                pid.map_or_else(|| "none".to_string(), |pid| pid.to_string())
            );
            println!("remove_pid_file={remove_pid_file}");
        }
        NodeCommand::Status {
            config,
            pid_file,
            json,
        } => {
            let report = node_lifecycle::status_report(&config, pid_file.as_ref());
            if json {
                println!("{}", serde_json_like_status(&report));
            } else {
                println!("config_path={}", report.config_path.display());
                println!("config_valid={}", report.config_valid);
                println!(
                    "validator_id={}",
                    report.validator_id.as_deref().unwrap_or("unknown")
                );
                println!(
                    "storage_dir={}",
                    report
                        .storage_dir
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                );
                println!(
                    "storage_clean={}",
                    report
                        .storage_clean
                        .map_or_else(|| "unknown".to_string(), |value| value.to_string())
                );
                println!(
                    "pid={}",
                    report
                        .pid
                        .map_or_else(|| "none".to_string(), |pid| pid.to_string())
                );
                println!("running={}", report.running);
            }
        }
        NodeCommand::ValidateConfig { config } => {
            let cfg = node_lifecycle::validate_config(&config)?;
            println!("config_valid=true");
            println!("validator_id={}", cfg.local.validator_id);
        }
        NodeCommand::RepairLedger {
            storage_dir,
            policy,
        } => {
            let recovery = node_lifecycle::repair_ledger(&storage_dir, policy.into())?;
            println!("storage_dir={}", storage_dir.display());
            println!("files_scanned={}", recovery.report.files_scanned);
            println!("records_scanned={}", recovery.report.records_scanned);
            println!("issues={}", recovery.report.issues.len());
            println!("quarantined_files={}", recovery.quarantined_files.len());
        }
        NodeCommand::Snapshot {
            input,
            output,
            overwrite,
        }
        | NodeCommand::RestoreSnapshot {
            input,
            output,
            overwrite,
        } => {
            let report = node_lifecycle::copy_validated_snapshot(input, output, overwrite)?;
            println!("source_path={}", report.source_path.display());
            println!("destination_path={}", report.destination_path.display());
            println!("bytes_written={}", report.bytes_written);
            println!("slot={}:{}", report.slot_epoch, report.slot);
            println!("block_hash={}", report.block_hash_hex);
            println!("state_root={}", report.state_root_hex);
        }
        NodeCommand::Version => {
            rpkv2::version::print();
        }
    }
    Ok(())
}

fn serde_json_like_status(report: &node_lifecycle::NodeStatusReport) -> String {
    format!(
        concat!(
            "{{",
            "\"config_path\":\"{}\",",
            "\"config_valid\":{},",
            "\"validator_id\":{},",
            "\"storage_dir\":{},",
            "\"storage_clean\":{},",
            "\"pid\":{},",
            "\"running\":{}",
            "}}"
        ),
        escape_json(&report.config_path.display().to_string()),
        report.config_valid,
        optional_string(report.validator_id.as_deref()),
        optional_string(
            report
                .storage_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .as_deref()
        ),
        optional_bool(report.storage_clean),
        report
            .pid
            .map_or_else(|| "null".to_string(), |pid| pid.to_string()),
        report.running
    )
}

fn optional_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn optional_bool(value: Option<bool>) -> String {
    value.map_or_else(|| "null".to_string(), |value| value.to_string())
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
