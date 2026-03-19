//! FlyClient chain proof verifier for Zcash.
//!
//! Verifies `BlockInclusionProof` responses from a Zaino server without any proto/gRPC
//! dependencies. Works on raw bytes. The core library has no `std`-only dependencies
//! (except via `zcash_history` which is only used in tests) and is designed to
//! compile to WASM.

#![cfg_attr(not(any(feature = "cli", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use blake2b_simd::Params as Blake2bParams;
use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("header too short: expected at least 141 bytes, got {0}")]
    HeaderTooShort(usize),

    #[error("invalid CompactSize in solution length")]
    InvalidCompactSize,

    #[error("equihash verification failed")]
    Equihash(String),

    #[error("hashBlockCommitments mismatch")]
    BlockCommitmentsMismatch,

    #[error("MMR proof verification failed for sample at height {0}")]
    MmrProofFailed(u32),

    #[error("entry deserialization failed: {0}")]
    EntryDeserialization(String),
}

// ---------------------------------------------------------------------------
// Data types (mirror protobuf, but no proto dependency)
// ---------------------------------------------------------------------------

/// A node in the MMR tree, as received in a proof.
#[derive(Debug, Clone)]
pub struct MmrNode {
    /// Position in the MMR array.
    pub position: u32,
    /// Serialized `zcash_history::Entry` bytes.
    pub data: Vec<u8>,
}

/// An MMR inclusion proof for a block, as returned by GetBlockInclusionProof.
///
/// Contains the MMR root and auth data root (for verifying hashBlockCommitments
/// against the tip header), plus the Merkle path proving the block is included.
#[derive(Debug, Clone)]
pub struct BlockInclusionProof {
    /// 32-byte MMR root hash for the current chain tip.
    pub mmr_root: [u8; 32],
    /// 32-byte ZIP-244 auth data root for the current chain tip.
    pub auth_data_root: [u8; 32],
    /// The MMR leaf entry for the requested block.
    pub leaf: MmrNode,
    /// Sibling nodes along the Merkle path to the root.
    pub siblings: Vec<MmrNode>,
}

/// Parsed block header fields.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub hash_block_commitments: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: [u8; 32],
    pub solution: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

/// Read a Bitcoin-style CompactSize from raw bytes, returning (value, bytes_consumed).
fn read_compact_size(data: &[u8]) -> Result<(usize, usize), VerifyError> {
    if data.is_empty() {
        return Err(VerifyError::InvalidCompactSize);
    }
    match data[0] {
        0..=0xfc => Ok((data[0] as usize, 1)),
        0xfd => {
            if data.len() < 3 {
                return Err(VerifyError::InvalidCompactSize);
            }
            Ok((LittleEndian::read_u16(&data[1..3]) as usize, 3))
        }
        0xfe => {
            if data.len() < 5 {
                return Err(VerifyError::InvalidCompactSize);
            }
            Ok((LittleEndian::read_u32(&data[1..5]) as usize, 5))
        }
        0xff => {
            if data.len() < 9 {
                return Err(VerifyError::InvalidCompactSize);
            }
            Ok((LittleEndian::read_u64(&data[1..9]) as usize, 9))
        }
    }
}

/// Read a compact uint (same encoding as CompactSize but for node_data fields).
fn read_compact_uint(data: &[u8]) -> Result<(u64, usize), VerifyError> {
    let (val, consumed) = read_compact_size(data)?;
    Ok((val as u64, consumed))
}

/// Write a compact uint to a buffer.
fn write_compact_uint(buf: &mut Vec<u8>, n: u64) {
    if n <= 0xfc {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        let mut b = [0u8; 2];
        LittleEndian::write_u16(&mut b, n as u16);
        buf.extend_from_slice(&b);
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        let mut b = [0u8; 4];
        LittleEndian::write_u32(&mut b, n as u32);
        buf.extend_from_slice(&b);
    } else {
        buf.push(0xff);
        let mut b = [0u8; 8];
        LittleEndian::write_u64(&mut b, n);
        buf.extend_from_slice(&b);
    }
}

/// Parse a raw Zcash block header.
pub fn parse_header(raw: &[u8]) -> Result<BlockHeader, VerifyError> {
    if raw.len() < 141 {
        return Err(VerifyError::HeaderTooShort(raw.len()));
    }

    let version = LittleEndian::read_i32(&raw[0..4]);

    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(&raw[4..36]);

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&raw[36..68]);

    let mut hash_block_commitments = [0u8; 32];
    hash_block_commitments.copy_from_slice(&raw[68..100]);

    let time = LittleEndian::read_u32(&raw[100..104]);
    let bits = LittleEndian::read_u32(&raw[104..108]);

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&raw[108..140]);

    let (sol_len, cs_size) = read_compact_size(&raw[140..])?;
    let sol_start = 140 + cs_size;
    let sol_end = sol_start + sol_len;
    if raw.len() < sol_end {
        return Err(VerifyError::HeaderTooShort(raw.len()));
    }
    let solution = raw[sol_start..sol_end].to_vec();

    Ok(BlockHeader {
        version,
        prev_block_hash,
        merkle_root,
        hash_block_commitments,
        time,
        bits,
        nonce,
        solution,
    })
}

// ---------------------------------------------------------------------------
// Step 2: Equihash PoW verification
// ---------------------------------------------------------------------------

/// Verify the Equihash proof-of-work on a parsed header.
///
/// Parameters for mainnet/testnet: (n=200, k=9).
/// The Equihash input is the first 108 bytes of the header (before the nonce).
/// The nonce is the 32-byte field at offset 108..140.
pub fn verify_equihash(raw_header: &[u8], header: &BlockHeader) -> Result<(), VerifyError> {
    let input = &raw_header[..108];
    let nonce = &raw_header[108..140];

    equihash::is_valid_solution(200, 9, input, nonce, &header.solution)
        .map_err(|e| VerifyError::Equihash(alloc::format!("{}", e)))
}

// ---------------------------------------------------------------------------
// Step 3: hashBlockCommitments verification (ZIP-244)
// ---------------------------------------------------------------------------

/// Verify that `hash_block_commitments` in the header matches:
///   BLAKE2b-256(personal="ZcashBlockCommit", mmr_root || auth_data_root || 0x00*32)
pub fn verify_block_commitments(
    header: &BlockHeader,
    mmr_root: &[u8; 32],
    auth_data_root: &[u8; 32],
) -> Result<(), VerifyError> {
    let expected = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZcashBlockCommit")
        .to_state()
        .update(mmr_root)
        .update(auth_data_root)
        .update(&[0u8; 32])
        .finalize();

    if expected.as_bytes() == &header.hash_block_commitments[..] {
        Ok(())
    } else {
        Err(VerifyError::BlockCommitmentsMismatch)
    }
}

// ---------------------------------------------------------------------------
// Step 4: MMR inclusion proof verification (ZIP-221)
//
// Reimplements the combine/hash logic from zcash_history to avoid the std
// dependency. The algorithm:
//   combine(left, right) = new node_data where:
//     subtree_commitment = BLAKE2b("ZcashHistory"||branch_id, left_bytes || right_bytes)
//     start_* fields from left, end_* fields from right
//     sums for work and tx counts
//   hash(node_data) = BLAKE2b("ZcashHistory"||branch_id, node_data_bytes)
// ---------------------------------------------------------------------------

/// BLAKE2b-256 with personalization "ZcashHistory" || branch_id (LE u32).
fn mmr_blake2b(branch_id: u32, data: &[u8]) -> [u8; 32] {
    let mut pers = [0u8; 16];
    pers[..12].copy_from_slice(b"ZcashHistory");
    LittleEndian::write_u32(&mut pers[12..], branch_id);

    let h = Blake2bParams::new()
        .hash_length(32)
        .personal(&pers)
        .to_state()
        .update(data)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Extract node_data bytes from a serialized Entry.
///
/// Entry format:
///   - Leaf:  0x01 || node_data_bytes
///   - Node:  0x00 || left_u32_le || right_u32_le || node_data_bytes
fn extract_node_data(entry_bytes: &[u8]) -> Result<&[u8], VerifyError> {
    if entry_bytes.is_empty() {
        return Err(VerifyError::EntryDeserialization(
            "empty entry bytes".into(),
        ));
    }
    match entry_bytes[0] {
        0x01 => Ok(&entry_bytes[1..]),
        0x00 => {
            if entry_bytes.len() < 9 {
                return Err(VerifyError::EntryDeserialization(
                    "node entry too short".into(),
                ));
            }
            Ok(&entry_bytes[9..])
        }
        other => Err(VerifyError::EntryDeserialization(alloc::format!(
            "unknown entry kind byte: 0x{:02x}",
            other
        ))),
    }
}

/// V2 node_data layout offsets (all little-endian):
///   [0..32]    subtree_commitment
///   [32..36]   start_time (u32)
///   [36..40]   end_time (u32)
///   [40..44]   start_target (u32)
///   [44..48]   end_target (u32)
///   [48..80]   start_sapling_root
///   [80..112]  end_sapling_root
///   [112..144] subtree_total_work (U256 LE)
///   [144..]    start_height (compact), end_height (compact), sapling_tx (compact)
///   then V2:   start_orchard_root(32), end_orchard_root(32), orchard_tx (compact)
const V1_FIXED_LEN: usize = 144; // up to subtree_total_work inclusive

/// Parse V2 node_data fields needed for combine.
struct V2Fields {
    subtree_commitment: [u8; 32],
    start_time: u32,
    end_time: u32,
    start_target: u32,
    end_target: u32,
    start_sapling_root: [u8; 32],
    end_sapling_root: [u8; 32],
    subtree_total_work: [u8; 32], // raw LE bytes, we just add them
    start_height: u64,
    end_height: u64,
    sapling_tx: u64,
    start_orchard_root: [u8; 32],
    end_orchard_root: [u8; 32],
    orchard_tx: u64,
}

fn parse_v2_node_data(data: &[u8]) -> Result<V2Fields, VerifyError> {
    if data.len() < V1_FIXED_LEN + 3 + 64 + 1 {
        // minimum: fixed + 3 compact uints (1 byte each) + 2 orchard roots + 1 compact
        return Err(VerifyError::EntryDeserialization(
            "node_data too short".into(),
        ));
    }

    let mut subtree_commitment = [0u8; 32];
    subtree_commitment.copy_from_slice(&data[0..32]);

    let start_time = LittleEndian::read_u32(&data[32..36]);
    let end_time = LittleEndian::read_u32(&data[36..40]);
    let start_target = LittleEndian::read_u32(&data[40..44]);
    let end_target = LittleEndian::read_u32(&data[44..48]);

    let mut start_sapling_root = [0u8; 32];
    start_sapling_root.copy_from_slice(&data[48..80]);
    let mut end_sapling_root = [0u8; 32];
    end_sapling_root.copy_from_slice(&data[80..112]);

    let mut subtree_total_work = [0u8; 32];
    subtree_total_work.copy_from_slice(&data[112..144]);

    let mut offset = V1_FIXED_LEN;
    let (start_height, n) = read_compact_uint(&data[offset..])?;
    offset += n;
    let (end_height, n) = read_compact_uint(&data[offset..])?;
    offset += n;
    let (sapling_tx, n) = read_compact_uint(&data[offset..])?;
    offset += n;

    // V2 extension fields
    if data.len() < offset + 64 + 1 {
        return Err(VerifyError::EntryDeserialization(
            "V2 extension too short".into(),
        ));
    }
    let mut start_orchard_root = [0u8; 32];
    start_orchard_root.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut end_orchard_root = [0u8; 32];
    end_orchard_root.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let (orchard_tx, _) = read_compact_uint(&data[offset..])?;

    Ok(V2Fields {
        subtree_commitment,
        start_time,
        end_time,
        start_target,
        end_target,
        start_sapling_root,
        end_sapling_root,
        subtree_total_work,
        start_height,
        end_height,
        sapling_tx,
        start_orchard_root,
        end_orchard_root,
        orchard_tx,
    })
}

/// Serialize V2 node_data fields to bytes.
fn serialize_v2_node_data(f: &V2Fields) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&f.subtree_commitment);
    buf.extend_from_slice(&f.start_time.to_le_bytes());
    buf.extend_from_slice(&f.end_time.to_le_bytes());
    buf.extend_from_slice(&f.start_target.to_le_bytes());
    buf.extend_from_slice(&f.end_target.to_le_bytes());
    buf.extend_from_slice(&f.start_sapling_root);
    buf.extend_from_slice(&f.end_sapling_root);
    buf.extend_from_slice(&f.subtree_total_work);
    write_compact_uint(&mut buf, f.start_height);
    write_compact_uint(&mut buf, f.end_height);
    write_compact_uint(&mut buf, f.sapling_tx);
    buf.extend_from_slice(&f.start_orchard_root);
    buf.extend_from_slice(&f.end_orchard_root);
    write_compact_uint(&mut buf, f.orchard_tx);
    buf
}

/// Add two 256-bit LE unsigned integers, returning the result as LE bytes.
fn add_u256_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

/// Combine two V2 node_data byte slices to produce the parent's node_data bytes.
///
/// This reimplements zcash_history::V2::combine at the byte level.
fn combine_node_data(branch_id: u32, left: &[u8], right: &[u8]) -> Result<Vec<u8>, VerifyError> {
    // 1. Hash left || right to get the parent's subtree_commitment
    let mut hash_input = Vec::with_capacity(left.len() + right.len());
    hash_input.extend_from_slice(left);
    hash_input.extend_from_slice(right);
    let subtree_commitment = mmr_blake2b(branch_id, &hash_input);

    // 2. Parse both sides
    let l = parse_v2_node_data(left)?;
    let r = parse_v2_node_data(right)?;

    // 3. Build parent: start fields from left, end fields from right, sums for work/tx
    let parent = V2Fields {
        subtree_commitment,
        start_time: l.start_time,
        end_time: r.end_time,
        start_target: l.start_target,
        end_target: r.end_target,
        start_sapling_root: l.start_sapling_root,
        end_sapling_root: r.end_sapling_root,
        subtree_total_work: add_u256_le(&l.subtree_total_work, &r.subtree_total_work),
        start_height: l.start_height,
        end_height: r.end_height,
        sapling_tx: l.sapling_tx + r.sapling_tx,
        start_orchard_root: l.start_orchard_root,
        end_orchard_root: r.end_orchard_root,
        orchard_tx: l.orchard_tx + r.orchard_tx,
    };

    Ok(serialize_v2_node_data(&parent))
}

/// Verify a single MMR inclusion proof.
///
/// The proof consists of a leaf and sibling nodes forming the Merkle path
/// from the leaf to the root. At each level we combine left+right node_data
/// to produce the parent. At the top, hashing the root node_data must match
/// the expected MMR root.
pub fn verify_mmr_proof(
    leaf: &MmrNode,
    siblings: &[MmrNode],
    expected_root: &[u8; 32],
    branch_id: u32,
) -> Result<(), VerifyError> {
    let mut current_data = extract_node_data(&leaf.data)?.to_vec();
    let mut current_pos = leaf.position;

    if siblings.is_empty() {
        // Single-node tree: hash leaf node_data directly
        let root_hash = mmr_blake2b(branch_id, &current_data);
        return if root_hash == *expected_root {
            Ok(())
        } else {
            Err(VerifyError::MmrProofFailed(0))
        };
    }

    for (i, sibling) in siblings.iter().enumerate() {
        let sib_data = extract_node_data(&sibling.data)
            .map_err(|_| VerifyError::EntryDeserialization(alloc::format!("sibling {i}")))?;

        // Left vs right based on position
        current_data = if sibling.position < current_pos {
            combine_node_data(branch_id, sib_data, &current_data)?
        } else {
            combine_node_data(branch_id, &current_data, sib_data)?
        };

        current_pos = core::cmp::max(current_pos, sibling.position) + 1;
    }

    // Hash the final root node_data
    let root_hash = mmr_blake2b(branch_id, &current_data);
    if root_hash == *expected_root {
        Ok(())
    } else {
        Err(VerifyError::MmrProofFailed(0))
    }
}

// ---------------------------------------------------------------------------
// Full verification
// ---------------------------------------------------------------------------

/// Verify a block inclusion proof from GetBlockInclusionProof.
///
/// The caller must also provide the tip block header (from GetBlock) so that
/// hashBlockCommitments can be verified. This authenticates the MMR root via PoW.
///
/// Steps:
/// 1. Parse the tip header and verify Equihash PoW.
/// 2. Verify hashBlockCommitments against mmr_root + auth_data_root from the proof.
/// 3. Verify the MMR Merkle path from the leaf to the root.
pub fn verify_block_inclusion(
    tip_header_bytes: &[u8],
    proof: &BlockInclusionProof,
    branch_id: u32,
) -> Result<BlockHeader, VerifyError> {
    // Verify the tip header PoW and hashBlockCommitments
    let header = parse_header(tip_header_bytes)?;
    verify_equihash(tip_header_bytes, &header)?;
    verify_block_commitments(&header, &proof.mmr_root, &proof.auth_data_root)?;

    // Verify the MMR inclusion proof
    verify_mmr_proof(&proof.leaf, &proof.siblings, &proof.mmr_root, branch_id)?;

    Ok(header)
}

// ---------------------------------------------------------------------------
// Tests — uses zcash_history (std) to generate reference data
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_history::{Entry, EntryLink, NodeData, Version, V2};

    fn make_leaf_data(height: u32, branch_id: u32) -> <V2 as Version>::NodeData {
        let v1 = NodeData {
            consensus_branch_id: branch_id,
            subtree_commitment: {
                let mut h = [0u8; 32];
                LittleEndian::write_u32(&mut h[..4], height);
                h
            },
            start_time: 1_600_000_000 + height,
            end_time: 1_600_000_000 + height,
            start_target: 0x2007_ffff,
            end_target: 0x2007_ffff,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: 1u64.into(),
            start_height: height as u64,
            end_height: height as u64,
            sapling_tx: 0,
        };
        let mut buf = Vec::new();
        v1.write(&mut buf).unwrap();
        buf.extend_from_slice(&[0u8; 32]); // start_orchard_root
        buf.extend_from_slice(&[0u8; 32]); // end_orchard_root
        buf.push(0); // orchard_tx
        V2::from_bytes(branch_id, &buf).unwrap()
    }

    fn entry_to_bytes<V: Version>(entry: &Entry<V>) -> Vec<u8> {
        let mut buf = Vec::new();
        entry.write(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_parse_header_too_short() {
        assert!(parse_header(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_block_commitments_hash() {
        let mmr_root = [0xaa; 32];
        let auth_data_root = [0xbb; 32];
        let expected = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZcashBlockCommit")
            .to_state()
            .update(&mmr_root)
            .update(&auth_data_root)
            .update(&[0u8; 32])
            .finalize();
        let mut commitments = [0u8; 32];
        commitments.copy_from_slice(expected.as_bytes());
        let header = BlockHeader {
            version: 5,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            hash_block_commitments: commitments,
            time: 0,
            bits: 0,
            nonce: [0; 32],
            solution: vec![],
        };
        assert!(verify_block_commitments(&header, &mmr_root, &auth_data_root).is_ok());
        assert!(verify_block_commitments(&header, &[0xcc; 32], &auth_data_root).is_err());
    }

    #[test]
    fn test_extract_node_data_leaf() {
        let mut entry_bytes = vec![0x01];
        entry_bytes.extend_from_slice(&[0xab; 50]);
        assert_eq!(extract_node_data(&entry_bytes).unwrap(), &[0xab; 50]);
    }

    #[test]
    fn test_extract_node_data_node() {
        let mut entry_bytes = vec![0x00];
        entry_bytes.extend_from_slice(&[1, 0, 0, 0]); // left
        entry_bytes.extend_from_slice(&[2, 0, 0, 0]); // right
        entry_bytes.extend_from_slice(&[0xcd; 50]);
        assert_eq!(extract_node_data(&entry_bytes).unwrap(), &[0xcd; 50]);
    }

    #[test]
    fn test_mmr_single_leaf_proof() {
        let branch_id: u32 = 0xc2d6_d0b4;
        let leaf_data = make_leaf_data(1, branch_id);
        let leaf_entry = Entry::<V2>::new_leaf(leaf_data.clone());
        let root_hash = V2::hash(&leaf_data);
        let mmr_leaf = MmrNode {
            position: 0,
            data: entry_to_bytes(&leaf_entry),
        };
        assert!(verify_mmr_proof(&mmr_leaf, &[], &root_hash, branch_id).is_ok());
    }

    #[test]
    fn test_mmr_three_node_proof() {
        let branch_id: u32 = 0xc2d6_d0b4;
        let ld0 = make_leaf_data(1, branch_id);
        let ld1 = make_leaf_data(2, branch_id);
        let e0 = Entry::<V2>::new_leaf(ld0.clone());
        let e1 = Entry::<V2>::new_leaf(ld1.clone());
        let root_hash = V2::hash(&V2::combine(&ld0, &ld1));

        // Proof for leaf0
        assert!(verify_mmr_proof(
            &MmrNode {
                position: 0,
                data: entry_to_bytes(&e0)
            },
            &[MmrNode {
                position: 1,
                data: entry_to_bytes(&e1)
            }],
            &root_hash,
            branch_id,
        )
        .is_ok());

        // Proof for leaf1
        assert!(verify_mmr_proof(
            &MmrNode {
                position: 1,
                data: entry_to_bytes(&e1)
            },
            &[MmrNode {
                position: 0,
                data: entry_to_bytes(&e0)
            }],
            &root_hash,
            branch_id,
        )
        .is_ok());
    }

    #[test]
    fn test_mmr_seven_node_proof() {
        let branch_id: u32 = 0xc2d6_d0b4;
        let ld0 = make_leaf_data(1, branch_id);
        let ld1 = make_leaf_data(2, branch_id);
        let ld2 = make_leaf_data(3, branch_id);
        let ld3 = make_leaf_data(4, branch_id);
        let e0 = Entry::<V2>::new_leaf(ld0.clone());
        let e1 = Entry::<V2>::new_leaf(ld1.clone());
        let e2 = Entry::<V2>::new_leaf(ld2.clone());
        let e3 = Entry::<V2>::new_leaf(ld3.clone());
        let nd2 = V2::combine(&ld0, &ld1);
        let nd5 = V2::combine(&ld2, &ld3);
        let nd6 = V2::combine(&nd2, &nd5);
        let root_hash = V2::hash(&nd6);
        let e2_node = Entry::<V2>::new(nd2.clone(), EntryLink::Stored(0), EntryLink::Stored(1));
        let e5_node = Entry::<V2>::new(nd5.clone(), EntryLink::Stored(3), EntryLink::Stored(4));

        // Proof for leaf 0: siblings [1, 5]
        assert!(verify_mmr_proof(
            &MmrNode {
                position: 0,
                data: entry_to_bytes(&e0)
            },
            &[
                MmrNode {
                    position: 1,
                    data: entry_to_bytes(&e1)
                },
                MmrNode {
                    position: 5,
                    data: entry_to_bytes(&e5_node)
                },
            ],
            &root_hash,
            branch_id,
        )
        .is_ok());

        // Proof for leaf 3: siblings [4, 2]
        assert!(verify_mmr_proof(
            &MmrNode {
                position: 3,
                data: entry_to_bytes(&e2)
            },
            &[
                MmrNode {
                    position: 4,
                    data: entry_to_bytes(&e3)
                },
                MmrNode {
                    position: 2,
                    data: entry_to_bytes(&e2_node)
                },
            ],
            &root_hash,
            branch_id,
        )
        .is_ok());
    }

    #[test]
    fn test_mmr_proof_wrong_root_fails() {
        let branch_id: u32 = 0xc2d6_d0b4;
        let ld0 = make_leaf_data(1, branch_id);
        let ld1 = make_leaf_data(2, branch_id);
        let e0 = Entry::<V2>::new_leaf(ld0.clone());
        let e1 = Entry::<V2>::new_leaf(ld1.clone());
        let mut wrong_root = V2::hash(&V2::combine(&ld0, &ld1));
        wrong_root[0] ^= 0xff;
        assert!(verify_mmr_proof(
            &MmrNode {
                position: 0,
                data: entry_to_bytes(&e0)
            },
            &[MmrNode {
                position: 1,
                data: entry_to_bytes(&e1)
            }],
            &wrong_root,
            branch_id,
        )
        .is_err());
    }

    #[test]
    fn test_compact_size_parsing() {
        assert_eq!(read_compact_size(&[42]).unwrap(), (42, 1));
        assert_eq!(read_compact_size(&[0xfc]).unwrap(), (252, 1));
        assert_eq!(read_compact_size(&[0xfd, 0x00, 0x01]).unwrap(), (256, 3));
        assert_eq!(
            read_compact_size(&[0xfe, 0x01, 0x00, 0x01, 0x00]).unwrap(),
            (65537, 5)
        );
    }

    #[test]
    fn test_mmr_personalization() {
        let mut pers = [0u8; 16];
        pers[..12].copy_from_slice(b"ZcashHistory");
        LittleEndian::write_u32(&mut pers[12..], 0xc2d6_d0b4);
        // Verify our mmr_blake2b uses the same personalization
        let h1 = mmr_blake2b(0xc2d6_d0b4, b"test");
        let h2 = Blake2bParams::new()
            .hash_length(32)
            .personal(&pers)
            .to_state()
            .update(b"test")
            .finalize();
        assert_eq!(&h1, h2.as_bytes());
    }

    #[test]
    fn test_add_u256_le() {
        let a = [1u8; 32]; // not actually 1, but 0x01010101...
        let b = [1u8; 32];
        let result = add_u256_le(&a, &b);
        assert_eq!(result, [2u8; 32]);

        // Carry test
        let mut a = [0u8; 32];
        a[0] = 0xff;
        let mut b = [0u8; 32];
        b[0] = 0x01;
        let result = add_u256_le(&a, &b);
        assert_eq!(result[0], 0x00);
        assert_eq!(result[1], 0x01);
    }
}
