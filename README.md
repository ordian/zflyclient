# zflyclient

FlyClient chain proof verifier for Zcash, built for the March 2026 Zcash hackathon.

## Motivation

Add support for FlyClient light client verification as specified in [ZIP-221](https://zips.z.cash/zip-0221).

Currently, light clients blindly trust the data provided by lightwallet-protocol server implementations (lightwalletd, Zaino). There is no mechanism for a light client to independently verify that the chain data it receives is authentic without downloading the entire header chain (as in SPV).

ZIP-221 specifies a Merkle Mountain Range (MMR) commitment in every block header that enables trustless verification:

> FlyClient reduces the number of block headers needed for light client verification of a valid chain, from linear (as in the current reference protocol) to logarithmic in block chain length. This verification is correct with high probability. It also allows creation of subtree proofs, so light clients need only check blocks later than the most recently verified block index.

## Changes

### [lightwallet-protocol](https://github.com/ordian/lightwallet-protocol) ([PR](https://github.com/zcash/lightwallet-protocol/pull/21))

Added proto messages and RPC to `service.proto`:

- **`MMRNode`** — a node in the MMR tree (position + serialized entry bytes)
- **`BlockInclusionProof`** — MMR root, auth data root, and Merkle path proving a block is in the committed chain
- **`GetBlockInclusionProof`** RPC — returns an inclusion proof for a specific block height

### [zaino](https://github.com/ordian/zaino) ([PR](https://github.com/zingolabs/zaino/pull/922))

Server-side MMR tree construction and proof generation:

- **`zaino-state/src/chain_index/mmr.rs`** — Core MMR tree implementation. Builds the tree in-memory from LMDB-stored block headers and commitment tree data. Supports incremental append (new blocks) and truncate (reorgs). Generates inclusion proofs for any block height.
- **Sync loop integration** — The MMR is updated in Zaino's existing sync loop immediately after finalized blocks are written, using a push-based design (no polling).
- **`GetBlockInclusionProof` handler** — Returns the MMR root, auth data root (ZIP-244), and a Merkle path proof for a requested block height.

### zflyclient (this repo)

Client-side verification library and CLI tool:

- **`src/lib.rs`** — `no_std`-compatible core verification library (compiles to WASM). Implements:
  - Block header parsing
  - Equihash PoW verification
  - `hashBlockCommitments` verification (ZIP-244)
  - MMR inclusion proof verification — reimplements `zcash_history`'s V2 combine/hash at the byte level to avoid `std` dependencies
- **`src/main.rs`** — CLI binary (behind `cli` feature flag) that connects to a Zaino server via gRPC, calls `GetBlockInclusionProof`, and runs the full verification pipeline.

#### Usage

```bash
# Run the CLI verifier against a Zaino server
cargo run -- --server http://localhost:8137 --blocks 3200000,3250000

# Build the library only (no_std, WASM-compatible)
cargo build --no-default-features

# Run tests
cargo test
```

## Architecture

```
                    ┌─────────────────┐
                    │   Light Client  │
                    │   (zflyclient)  │
                    └────────┬────────┘
                             │ gRPC
                    ┌────────▼────────┐
                    │     Zaino       │
                    │  (MMR server)   │
                    └────────┬────────┘
                             │ ReadStateService
                    ┌────────▼────────┐
                    │     Zebra       │
                    │  (full node)    │
                    └─────────────────┘
```

**Verification flow:**

1. Client calls `GetLatestBlock` to learn the tip height, then `GetBlock` to get the full tip block header
2. Client selects blocks to challenge using the [FlyClient sampling distribution](https://eprint.iacr.org/2019/226)
3. For each sampled block, client calls `GetBlockInclusionProof(height)` which returns the MMR root, auth data root, and Merkle path
4. Client verifies the tip header:
   - Equihash PoW (proves the header required real work)
   - `hashBlockCommitments = BLAKE2b-256("ZcashBlockCommit" || mmr_root || auth_data_root || [0u8;32])` (authenticates the MMR root)
5. Client verifies the MMR Merkle path from the leaf to the authenticated root (proves the block is in the committed chain)
6. Client reads cumulative work, timestamps, difficulty from the authenticated leaf data

## References

- [ZIP-221: FlyClient - Consensus-Layer Changes](https://zips.z.cash/zip-0221)
- [ZIP-244: Transaction Identifier and Signature Validation](https://zips.z.cash/zip-0244)
- [FlyClient paper](https://eprint.iacr.org/2019/226)
- [zcash_history crate](https://crates.io/crates/zcash_history)
