//! Witnesses of NOMT sessions. These types encapsulate entire sets of reads and writes.

use crate::{
    proof::{shared_bits, MultiPathProof, PathProof},
    trie::{KeyPath, ValueHash},
    trie_pos::TriePosition,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bitvec::{order::Msb0, view::BitView};

/// A witness that can be used to prove the correctness of state trie retrievals and updates.
///
/// Expected to be serializable.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshDeserialize, borsh::BorshSerialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Witness {
    /// Various paths down the trie used as part of this witness.
    /// Note that the paths are not necessarily in lexicographic order.
    pub path_proofs: Vec<WitnessedPath>,
    /// The operations witnessed by the paths.
    pub operations: WitnessedOperations,
}

/// Operations provable by a corresponding witness.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshDeserialize, borsh::BorshSerialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WitnessedOperations {
    /// Read operations.
    pub reads: Vec<WitnessedRead>,
    /// Write operations.
    pub writes: Vec<WitnessedWrite>,
}

/// A path observed in the witness.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshDeserialize, borsh::BorshSerialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WitnessedPath {
    /// Proof of a query path along the trie.
    pub inner: PathProof,
    /// The query path itself.
    pub path: TriePosition,
}

/// A witness of a read value.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshDeserialize, borsh::BorshSerialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WitnessedRead {
    /// The key of the read value.
    pub key: KeyPath,
    /// The hash of the value witnessed. None means no value.
    pub value: Option<ValueHash>,
    /// The index of the path in the corresponding witness.
    pub path_index: u32,
}

/// A witness of a write operation.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshDeserialize, borsh::BorshSerialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WitnessedWrite {
    /// The key of the written value.
    pub key: KeyPath,
    /// The hash of the written value. `None` means "delete".
    pub value: Option<ValueHash>,
    /// The index of the path in the corresponding witness.
    pub path_index: u32,
}

/// Estimator of the witness size, for each read or write require to register
/// the relative [`EstimationInfo`] to create an over estimation of the final
/// endoded witness size. It estimates the `MultiProof` version of the witness.
pub struct WitnessSizeEstimator {
    /// Sorted vector with all the terminal's keys which has been
    /// searched throught the db, along with the depth at which the
    /// terminal nodes has been found and the sequence of terminators
    /// that connect to the higher neighbor within the trie.
    // terminals: Vec<(KeyPath, usize, Option<usize>, Option<usize>)>,
    terminals: Vec<(KeyPath, usize)>,
    /// Sum of each traversal depth performed throught the db.
    total_depth: usize,
    /// Estimation of the `paths` scale encoding
    paths_encoding: usize,
}

/// Data required to handle collisions within the Witness size Estimation logic.
pub struct CollisionInfo {
    /// The length in bytes of the first key within the collision group.
    pub base_key_len: usize,
    /// The amount of items present within a collision group.
    pub amount: usize,
}

/// Data required create an estimation of the finale proof size.
/// For each lookup within the trie or for every expected writes this struct
/// needs to be filled and used by the Estimator.
pub struct EstimationInfo {
    pub key: KeyPath,
    pub presence: bool,
    pub left_neighbor: Option<KeyPath>,
    pub right_neighbor: Option<KeyPath>,
    pub additional_neighbor: Option<Vec<u8>>,
    pub additional_collision: Option<CollisionInfo>,
    pub collision_info: Option<CollisionInfo>,
}

enum EstimationTerminalType {
    Terminator,
    Leaf { key_len: usize },
    CollisionLeaf { info: CollisionInfo },
}

struct TerminalInfo {
    depth: usize,
    key: KeyPath,
    variant: EstimationTerminalType,
}

impl WitnessSizeEstimator {
    pub fn new() -> Self {
        WitnessSizeEstimator {
            terminals: vec![],
            total_depth: 0,
            // 4 bytes of the main vector compact len encoding
            paths_encoding: 4,
        }
    }

    pub fn add_traversal(&mut self, estimation_info: EstimationInfo) {
        // 1. Calculate depth and add it to `total_depth`
        //
        // There are two possibilities:
        // If the key was present within the db:
        //    depth(k) = max(shared_bits(k, left_neighbor), shared_bits(k, right_neighbor)) + 1
        //
        // If it was not present more checks are needed. Given:
        // K = estimation_info.key, the key which is being traversed
        // L = estimation_info.left_neighbor
        // R = estimation_info.right_neighbor
        //
        // The key was not present thus we are sure that L < K < R.
        //
        // The bisection between L and R creates 2 subtrees, K falls into one of the two.
        // It goes into the one it shares more bits with.
        //
        // The logic is simmetric, let's say that it goes under R.
        //
        // R+ = additional neighbor where L < K < R < R+.
        //
        // L and R+ are the left and right neighbors of R, and we know that
        // R was present within the trie and thus we know the depth of its leaf.
        //
        // Now comparing the number of shared bits between K and R and the depth
        // of R let us know if K ends up in the same leaf, shared_bits(K, R) >= depth(R),
        // or it ends up within a previous terminal node with
        //     depth(k) = shared_bits(K, R) + 1

        let TerminalInfo {
            depth: terminal_depth,
            key: terminal_key,
            variant: terminal_info,
        } = self.terminal_info(estimation_info);

        if self
            .terminals
            .binary_search_by(|(key, _)| key.cmp(&terminal_key))
            .is_ok()
        {
            return;
        }

        // Save the depth reached by traversing the trie.
        self.total_depth += terminal_depth;

        // 2. Update `paths_encoding`
        // Vec<MultiPathProof> - compact_len, 4 bytes, up to 1073741823 elements
        //    MultiPathProof
        //      depth: u16 - 2 bytes
        //      terminal: PathProofTerminal - variant index, 1 byte
        //        Leaf:
        //          LeafData:
        //            KeyPath(Vec<u8>) - 2 bytes + bytes
        //            ValueHash - 32 bytes
        //            bool - 1 byte
        //        CollisionLeaf:
        //          LeafData
        //          Vec<(u16, ValueHash)> - 2 bytes + N*(2+32) bytes
        //        Terminator:
        //          TriePosition:
        //            path(Vec<u8>) - 2 bytes + bytes
        //            depth(u16) - 2 bytes
        //            node_index(u8) - 1 byte
        let leaf_data_encoding = |key_len| -> usize {
            let mut encoding = 2; // key_path len encoding
            encoding += key_len; // key_path raw bytes
            encoding += 32; // value_hash
            encoding += 1; // collision flag
            encoding
        };

        let multi_path_proof_encoding = 2 // paths len encoding
            + 1 // terminal enum variant
            + match terminal_info {
                EstimationTerminalType::Terminator => 2 + ((terminal_depth + 7) / 8) + 2 + 1,
                EstimationTerminalType::Leaf { key_len } => leaf_data_encoding(key_len),
                EstimationTerminalType::CollisionLeaf { info } => {
                    leaf_data_encoding(info.base_key_len) + 2 + (info.amount * (2 + 32))
                }
            };

        self.paths_encoding += multi_path_proof_encoding;

        // 3. Save the new terminal with its key
        self.terminals.push((terminal_key, terminal_depth));
        self.terminals.sort();
    }

    fn terminal_info(&mut self, estimation_info: EstimationInfo) -> TerminalInfo {
        let compute_depth = |left: &Option<Vec<u8>>,
                             right: &Option<Vec<u8>>,
                             key: &Vec<u8>|
         -> (Option<usize>, Option<usize>, usize) {
            let key = key.view_bits::<Msb0>();
            let left_shared_bits: Option<usize> = left
                .as_ref()
                .map(|left| shared_bits(key, left.view_bits::<Msb0>()));
            let right_shared_bits: Option<usize> = right
                .as_ref()
                .map(|right| shared_bits(key, right.view_bits::<Msb0>()));
            let depth = core::cmp::max(left_shared_bits, right_shared_bits).unwrap_or(0) + 1;
            (left_shared_bits, right_shared_bits, depth)
        };

        let (left_shared_bits, right_shared_bits, maybe_depth) = compute_depth(
            &estimation_info.left_neighbor,
            &estimation_info.right_neighbor,
            &estimation_info.key,
        );

        if estimation_info.presence {
            let variant = match estimation_info.collision_info {
                Some(info) => EstimationTerminalType::CollisionLeaf { info },
                None => EstimationTerminalType::Leaf {
                    key_len: estimation_info.key.len(),
                },
            };
            return TerminalInfo {
                depth: maybe_depth,
                key: estimation_info.key,
                variant,
            };
        }

        if left_shared_bits.is_none() && right_shared_bits.is_none() {
            // The item is not presetn and it has NO neighbors, that's just the only item within the db.
            return TerminalInfo {
                depth: 1,
                key: truncate_key_to_bits(estimation_info.key, 1),
                variant: EstimationTerminalType::Terminator,
            };
        }

        let (neighbor, depth, neighbor_shared_bits) = match (left_shared_bits, right_shared_bits) {
            (Some(left_shared_bits), right)
                if right.map_or(true, |right_shared_bits| {
                    left_shared_bits > right_shared_bits
                }) =>
            {
                let left_neighbor = estimation_info.left_neighbor.as_ref().cloned().unwrap();
                let (_, _, left_depth) = compute_depth(
                    &estimation_info.additional_neighbor,
                    &estimation_info.right_neighbor,
                    &left_neighbor,
                );
                (left_neighbor, left_depth, left_shared_bits)
            }

            (Some(_), Some(right_shared_bits)) | (None, Some(right_shared_bits)) => {
                let right_neighbor = estimation_info.right_neighbor.as_ref().cloned().unwrap();
                let (_, _, right_depth) = compute_depth(
                    &estimation_info.left_neighbor,
                    &estimation_info.additional_neighbor,
                    &right_neighbor,
                );
                (right_neighbor, right_depth, right_shared_bits)
            }
            _ => unreachable!(),
        };

        if depth > neighbor_shared_bits {
            return TerminalInfo {
                depth: neighbor_shared_bits + 1,
                // Truncating the key to exactly neighbor_shared_bits + 1 makes possible
                // to identify different keys which ends up within the same final
                // terminal position.
                key: truncate_key_to_bits(estimation_info.key, neighbor_shared_bits + 1),
                variant: EstimationTerminalType::Terminator,
            };
        } else {
            let variant = match estimation_info.additional_collision {
                Some(info) => EstimationTerminalType::CollisionLeaf { info },
                None => EstimationTerminalType::Leaf {
                    key_len: neighbor.len(),
                },
            };
            return TerminalInfo {
                depth,
                key: neighbor,
                variant,
            };
        }
    }

    pub fn estimate(&self) -> usize {
        // The total number of shared bits are removed from the total depth,
        // each of this shared bits imply that a node can be recostructed from
        // the unique nodes close to the terminals.
        let shared_bits: usize = self
            .terminals
            .windows(2)
            .map(|window| {
                // The nuber of shared bits between two keys could be deeper
                // than the depth of the two paths.
                let shared_bits = shared_bits(window[0].0.view_bits(), window[1].0.view_bits());
                let cap = core::cmp::min(window[0].1, window[1].1).saturating_sub(1);
                core::cmp::min(shared_bits, cap)
            })
            .sum();

        let terminators = 0;
        let n_sequences = 0;

        // Starting from the total depth, sum of each traversal.
        let mut unique_siblings = self.total_depth;
        // Remove the nodes associated to the bisection of each traversal.
        unique_siblings =
            unique_siblings.saturating_sub((self.terminals.len() * 2).saturating_sub(2));
        // Remove the shared bits which will be re-computed.
        unique_siblings = unique_siblings.saturating_sub(shared_bits);
        // Remove the sequence of terminators which are compacted by the
        // `SiblingChunk::Terminators` variant.
        unique_siblings = unique_siblings.saturating_sub(terminators);

        // Encoding of the siblings.
        let mut estimation = 4 + (unique_siblings * 33) + (n_sequences * 3);
        // Encoding of the siblings.
        estimation += self.paths_encoding;
        estimation
    }
}

// Truncate the key to the specify number or bits, zeroing out
// bits beyond n_bits within the last byte.
fn truncate_key_to_bits(key: Vec<u8>, n_bits: usize) -> Vec<u8> {
    let n_bytes = (n_bits + 7) / 8;
    let mut key = key;
    key.truncate(n_bytes);
    if n_bits % 8 != 0 {
        if let Some(last) = key.last_mut() {
            let mask = !((1u8 << (8 - n_bits % 8)) - 1);
            *last &= mask;
        }
    }
    key
}
