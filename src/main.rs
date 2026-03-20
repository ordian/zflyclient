//! CLI tool to verify FlyClient block inclusion proofs from a Zaino server.
//!
//! Usage:
//!   zflyclient --server http://localhost:8137 --blocks 3200000,3250000

use clap::Parser;
use tonic::transport::Channel;

pub mod proto {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

use proto::compact_tx_streamer_client::CompactTxStreamerClient;

#[derive(Parser)]
#[command(
    name = "zflyclient",
    about = "FlyClient chain proof verifier for Zcash"
)]
struct Cli {
    /// Zaino gRPC server address (e.g., http://localhost:8137)
    #[arg(short, long, default_value = "http://localhost:8137")]
    server: String,

    /// Block heights to request inclusion proofs for (comma-separated).
    #[arg(short, long, value_delimiter = ',')]
    blocks: Vec<u32>,

    /// Consensus branch ID (hex). Defaults to NU6 mainnet (0xc8e71055).
    #[arg(long, default_value = "c8e71055")]
    branch_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.blocks.is_empty() {
        eprintln!("Error: specify at least one block height with --blocks HEIGHT1,HEIGHT2,...");
        std::process::exit(1);
    }

    let branch_id = u32::from_str_radix(&cli.branch_id, 16)?;

    println!("Connecting to {}...", cli.server);
    let channel = Channel::from_shared(cli.server.clone())?.connect().await?;
    let mut client = CompactTxStreamerClient::new(channel);

    // Verify each block
    for &height in &cli.blocks {
        print!("Block {}: ", height);

        let resp = match client
            .get_block_inclusion_proof(proto::BlockId {
                height: height as u64,
                hash: vec![],
            })
            .await
        {
            Ok(resp) => resp.into_inner(),
            Err(e) => {
                println!("ERROR: {}", e.message());
                continue;
            }
        };

        // Fetch the block header at tip_height — this is the block whose header
        // commits to mmr_root and auth_data_root via hashBlockCommitments.
        let commit_height = resp.tip_height;
        let commit_block = client
            .get_block(proto::BlockId {
                height: commit_height as u64,
                hash: vec![],
            })
            .await?
            .into_inner();
        let commit_header = &commit_block.header;

        let mmr_root: [u8; 32] = resp
            .mmr_root
            .try_into()
            .map_err(|_| "mmr_root not 32 bytes")?;
        let auth_data_root: [u8; 32] = resp
            .auth_data_root
            .try_into()
            .map_err(|_| "auth_data_root not 32 bytes")?;

        let proof = zflyclient::BlockInclusionProof {
            mmr_root,
            auth_data_root,
            leaf: zflyclient::MmrNode {
                position: resp.leaf.as_ref().map(|l| l.position).unwrap_or(0),
                data: resp
                    .leaf
                    .as_ref()
                    .map(|l| l.data.clone())
                    .unwrap_or_default(),
            },
            siblings: resp
                .siblings
                .iter()
                .map(|s| zflyclient::MmrNode {
                    position: s.position,
                    data: s.data.clone(),
                })
                .collect(),
            tip_height: commit_height,
        };

        match zflyclient::verify_block_inclusion(commit_header, &proof, branch_id) {
            Ok(_header) => {
                println!(
                    "VERIFIED (tip={}, mmr_root={}, {} siblings)",
                    commit_height,
                    hex::encode(&proof.mmr_root[..8]),
                    proof.siblings.len()
                );
            }
            Err(e) => println!("FAILED: {}", e),
        }
    }

    println!("\nDone.");
    Ok(())
}
