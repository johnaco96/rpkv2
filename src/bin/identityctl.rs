use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rpkv2::identity_keys::{
    Ed25519KeyRole, generate_ed25519_key_files, generate_transport_key_files,
    generate_validator_identity, hex, load_public_identity, load_transport_spki_from_private_key,
    public_key_hex_from_private_ed25519, validate_config_consistency,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "identityctl",
    about = "Safe operator tooling for rpkv2 validator identity and keys"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenerateValidatorIdentity {
        #[arg(long)]
        validator_id: String,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    GenerateTransportKey {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    GeneratePacketSigningKey {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    GenerateConsensusVotingKey {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    PrintPublicIdentity {
        #[arg(long)]
        public_identity: PathBuf,
    },
    PrintPublicKey {
        #[arg(value_enum, long)]
        kind: PublicKeyKind,
        #[arg(long)]
        private_key: PathBuf,
    },
    ValidateConfig {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        public_identity: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PublicKeyKind {
    TransportSpki,
    Ed25519,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::GenerateValidatorIdentity {
            validator_id,
            out_dir,
            overwrite,
        } => {
            let generated = generate_validator_identity(&validator_id, &out_dir, overwrite)?;
            println!("validator_id={}", generated.public_identity.validator_id);
            println!(
                "transport_private_key_path={}",
                generated.transport_private_key_path.display()
            );
            println!(
                "transport_public_spki_path={}",
                generated.transport_public_spki_path.display()
            );
            println!(
                "packet_signing_key_path={}",
                generated.packet_signing_key_path.display()
            );
            println!(
                "packet_verify_key_path={}",
                generated.packet_verify_key_path.display()
            );
            println!(
                "consensus_voting_key_path={}",
                generated.consensus_voting_key_path.display()
            );
            println!(
                "consensus_verify_key_path={}",
                generated.consensus_verify_key_path.display()
            );
            println!(
                "public_identity_path={}",
                generated.public_identity_path.display()
            );
        }
        Command::GenerateTransportKey { out_dir, overwrite } => {
            let generated = generate_transport_key_files(out_dir, overwrite)?;
            println!(
                "transport_private_key_path={}",
                generated.private_key_path.display()
            );
            println!(
                "transport_public_spki_path={}",
                generated.public_key_path.display()
            );
        }
        Command::GeneratePacketSigningKey { out_dir, overwrite } => {
            let generated =
                generate_ed25519_key_files(out_dir, Ed25519KeyRole::PacketSigning, overwrite)?;
            println!(
                "packet_signing_key_path={}",
                generated.private_key_path.display()
            );
            println!(
                "packet_verify_key_path={}",
                generated.public_key_path.display()
            );
        }
        Command::GenerateConsensusVotingKey { out_dir, overwrite } => {
            let generated =
                generate_ed25519_key_files(out_dir, Ed25519KeyRole::ConsensusVoting, overwrite)?;
            println!(
                "consensus_voting_key_path={}",
                generated.private_key_path.display()
            );
            println!(
                "consensus_verify_key_path={}",
                generated.public_key_path.display()
            );
        }
        Command::PrintPublicIdentity { public_identity } => {
            let identity = load_public_identity(public_identity)?;
            println!("{}", toml::to_string_pretty(&identity)?);
        }
        Command::PrintPublicKey { kind, private_key } => match kind {
            PublicKeyKind::TransportSpki => {
                println!(
                    "{}",
                    hex(&load_transport_spki_from_private_key(private_key)?)
                );
            }
            PublicKeyKind::Ed25519 => {
                println!("{}", public_key_hex_from_private_ed25519(private_key)?);
            }
        },
        Command::ValidateConfig {
            config,
            public_identity,
        } => {
            let identity = validate_config_consistency(config, public_identity)?;
            println!("config_valid=true");
            println!("validator_id={}", identity.validator_id);
        }
    }
    Ok(())
}
