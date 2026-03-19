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

    // Get the tip block header (for PoW + hashBlockCommitments verification)
    let tip = client
        .get_latest_block(proto::ChainSpec {})
        .await?
        .into_inner();
    println!("Chain tip: height {}", tip.height);

    let tip_block = client
        .get_block(proto::BlockId {
            height: tip.height,
            hash: vec![],
        })
        .await?
        .into_inner();
    let tip_header = &tip_block.header;
    println!("Tip header: {} bytes", tip_header.len());

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
        };

        match zflyclient::verify_block_inclusion(tip_header, &proof, branch_id) {
            Ok(_header) => {
                println!(
                    "VERIFIED (mmr_root={}, {} siblings)",
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
