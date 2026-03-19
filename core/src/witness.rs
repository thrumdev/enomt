//! Witnesses of NOMT sessions. These types encapsulate entire sets of reads and writes.

use crate::{
    proof::PathProof,
    trie::{KeyPath, ValueHash},
    trie_pos::TriePosition,
};

#[cfg(feature = "codec")]
use crate::{collisions::collides, proof::shared_bits};
#[cfg(feature = "codec")]
use bitvec::{order::Msb0, view::BitView};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

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

/// Estimator of the witness size. For each read or write, the relative
/// [`EstimationInfo`] must be registered to create an overestimation of the final
/// encoded witness size. It estimates the `MultiProof` version of the witness.
#[cfg(feature = "codec")]
pub struct WitnessSizeEstimator {
    /// Sorted vector with all the terminal's data which have been
    /// searched through the db, needed to compute terminator sequences at estimation time.
    terminals: Vec<TerminalData>,
    /// Sum of each traversal depth performed through the db.
    total_depth: usize,
    /// Estimation of the `paths` scale encoding
    paths_encoding: usize,
}

/// Data required to handle collisions within the witness size estimation logic.
#[cfg(feature = "codec")]
pub struct CollisionInfo {
    /// The length in bytes of the first key within the collision group.
    pub base_key_len: usize,
    /// The amount of items present within a collision group.
    pub amount: usize,
}

/// Data required to create an estimation of the final proof size.
/// For each lookup within the trie or for every expected write this struct
/// needs to be filled and used by the Estimator.
#[cfg(feature = "codec")]
pub struct EstimationInfo {
    /// Key associated with the trie traversal.
    pub key: KeyPath,
    /// Whether the key is present within the trie.
    pub presence: bool,
    /// Whether a key is not present within the trie but collides
    /// with an existing one, resulting in reaching the same
    /// terminal as if the key were present.
    pub collision: bool,
    /// The left neighbor, None if the key is the smallest one.
    pub left_neighbor: Option<KeyPath>,
    /// The right neighbor, None if the key is the biggest one.
    pub right_neighbor: Option<KeyPath>,
    /// It could happen that the reached terminal is a collision
    /// leaf, and thus this stores every piece of information needed to create
    /// a proper estimation.
    pub collision_info: Option<CollisionInfo>,
    /// If the key is not present, to understand the depth
    /// reached by the traversal an additional neighbor is needed,
    /// this could be the neighbor of the left or right neighbor.
    /// The flag is true if on the left, false otherwise.
    pub additional_neighbor: Option<(bool, Option<Vec<u8>>)>,
}

#[cfg(feature = "codec")]
enum EstimationTerminalType {
    Terminator,
    Leaf { key_len: usize },
    CollisionLeaf { info: CollisionInfo },
}

/// Data needed to recompute terminator sequences at estimation time,
/// when the full sorted terminal list is known.
#[cfg(feature = "codec")]
#[derive(Debug, Clone)]
pub struct TerminalData {
    /// The key associated with the reached terminal.
    pub key: KeyPath,
    /// The depth within the trie of this terminal.
    pub depth: usize,
    // TODO: Thos will be needed to reduce the over estimation
    // and take into accounts sequences of terminators that are
    // compressed into a chunks represented by just the length
    // of the sequence.
    //
    // Shared bits between the key and its trie left neighbor.
    // pub left_shared_bits: Option<usize>,
    // Shared bits between the key and its trie right neighbor.
    // pub right_shared_bits: Option<usize>,
}

pub struct EstimationResult {
    pub byte_length: usize,
    #[cfg(feature = "witness-estimation-testing")]
    pub testing_data: TestingEstimationResult,
}

#[cfg(feature = "witness-estimation-testing")]
#[derive(Default)]
pub struct TestingEstimationResult {
    pub paths: usize,
    pub paths_encoding: usize,
    pub siblings_encoding: usize,
    pub unique_siblings: usize,
    pub tot_siblings: usize,
    pub shared_bits: usize,
    pub pair_bits: usize,
    pub terminators: usize,
    pub terminator_sequences: usize,
    pub terminals: Vec<TerminalData>,
}

#[cfg(feature = "codec")]
impl WitnessSizeEstimator {
    /// Create an empty `WitnessSizeEstimator`.
    pub fn new() -> Self {
        WitnessSizeEstimator {
            terminals: vec![],
            total_depth: 0,
            // 4 bytes of the main vector compact len encoding
            paths_encoding: 4,
        }
    }

    /// Given an `EstimationInfo`, estimate the trie traversal that will
    /// be performed to reach a terminal node.
    pub fn add_traversal(&mut self, estimation_info: EstimationInfo) {
        // Calculate all terminal information needed to create a proper
        // witness estimation.
        let (terminal_data, terminal_variant) = self.terminal_info(estimation_info);

        if self
            .terminals
            .binary_search_by(|terminal| {
                // Make sure that colliding keys end up in the same terminal.
                if collides(&terminal.key, &terminal_data.key) {
                    core::cmp::Ordering::Equal
                } else {
                    terminal.key.cmp(&terminal_data.key)
                }
            })
            .is_ok()
        {
            return;
        }

        // Save the depth reached by traversing the trie.
        self.total_depth += terminal_data.depth;

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
            + match terminal_variant {
                EstimationTerminalType::Terminator => 2 + ((terminal_data.depth+ 7) / 8) + 2 + 1,
                EstimationTerminalType::Leaf { key_len } => leaf_data_encoding(key_len),
                EstimationTerminalType::CollisionLeaf { info } => {
                    leaf_data_encoding(info.base_key_len) + 2 + (info.amount * (2 + 32))
                }
            };

        self.paths_encoding += multi_path_proof_encoding;

        // 3. Save the new terminal with its key
        self.terminals.push(terminal_data);
        self.terminals.sort_by(|a, b| a.key.cmp(&b.key));
    }

    fn terminal_info(
        &mut self,
        estimation_info: EstimationInfo,
    ) -> (TerminalData, EstimationTerminalType) {
        // There are two possibilities:
        // If the key was present within the db:
        //    depth(k) = max(shared_bits(k, left_neighbor), shared_bits(k, right_neighbor)) + 1
        //
        // If it was not present, more checks are needed. Given:
        // K = estimation_info.key, the key which is being traversed
        // L = estimation_info.left_neighbor
        // R = estimation_info.right_neighbor
        //
        // The key was not present thus we are sure that L < K < R.
        //
        // The bisection between L and R creates 2 subtrees, K falls into one of the two.
        // It goes into the one it shares more bits with.
        //
        // The logic is symmetric, let's say that it goes under R.
        //
        // R+ = additional neighbor where L < K < R < R+.
        //
        // L and R+ are the left and right neighbors of R, and we know that
        // R was present within the trie and thus we know the depth of its leaf.
        //
        // Now comparing the number of shared bits between K and R and the depth
        // of R lets us know if K ends up in the same leaf, shared_bits(K, R) >= depth(R),
        // or it ends up within a previous terminal node with
        //     depth(k) = shared_bits(K, R) + 1
        //
        // NOTE: compute_depth is never expected to find collisions
        // between left, right and the key
        let compute_depth = |left: &Option<Vec<u8>>,
                             right: &Option<Vec<u8>>,
                             key: &Vec<u8>|
         -> (Option<usize>, Option<usize>, usize) {
            let left_shared_bits: Option<usize> = left
                .as_ref()
                .map(|left| shared_bits(key.view_bits::<Msb0>(), left.view_bits::<Msb0>()));
            let right_shared_bits: Option<usize> = right
                .as_ref()
                .map(|right| shared_bits(key.view_bits::<Msb0>(), right.view_bits::<Msb0>()));
            let depth = core::cmp::max(left_shared_bits, right_shared_bits).unwrap_or(0) + 1;
            (left_shared_bits, right_shared_bits, depth)
        };

        let (left_shared_bits, right_shared_bits, maybe_depth) = compute_depth(
            &estimation_info.left_neighbor,
            &estimation_info.right_neighbor,
            &estimation_info.key,
        );

        let mut terminal_data = TerminalData {
            depth: maybe_depth,
            key: estimation_info.key,
            // TODO: future optimization, reduce overestimation.
            // left_shared_bits,
            // right_shared_bits,
        };
        let leaf_variant = |key: &KeyPath| match estimation_info.collision_info {
            Some(info) => EstimationTerminalType::CollisionLeaf { info },
            None => EstimationTerminalType::Leaf { key_len: key.len() },
        };

        // If the key was present or the key collides with an already existing
        // leaf or collision leaf, the computation of the depth doesn't require
        // any additional logic.
        if estimation_info.presence || estimation_info.collision {
            let leaf_variant = leaf_variant(&terminal_data.key);
            return (terminal_data, leaf_variant);
        }

        // No presence, no collision and no neighbors implies an empty trie.
        if left_shared_bits.is_none() && right_shared_bits.is_none() {
            terminal_data.depth = 0;
            terminal_data.key = vec![];
            return (terminal_data, EstimationTerminalType::Terminator);
        }

        // If the additional neighbor needs to be used to compute the depth of the terminal,
        // this determines whether the additional neighbor is neighbor to the left or
        // right initial neighbors.
        //
        // Once it is known under which subtree the traversal goes, it could happen that
        // the traversal reaches the existing left or right terminals (leaves) or stops earlier
        // on a terminator node.
        //
        // UNWRAP: A non-present key which doesn't collide with any other on a non-empty trie
        // is expected to have an additional neighbor to determine the reached depth of the traversal.
        let (key_on_the_left, additional_neighbor) = estimation_info.additional_neighbor.unwrap();

        if key_on_the_left {
            // The key is under the left subtree, thus this computes the depth of the left neighbor
            // keeping the right one as right neighbor and the additional as left.
            // UNWRAPs: key is on the left thus left_neighbor is expected to be present.
            let left_neighbor = estimation_info.left_neighbor.as_ref().cloned().unwrap();
            let left_shared_bits = left_shared_bits.unwrap();
            let (_, _, left_depth) = compute_depth(
                &additional_neighbor,
                &estimation_info.right_neighbor,
                &left_neighbor,
            );

            if left_depth > left_shared_bits {
                // The traversal ends before reaching the left neighbor
                // within a terminator node.
                let terminal_depth = left_shared_bits + 1;
                terminal_data.depth = terminal_depth;
                // Fitting the key to exactly terminal_depth makes it possible
                // to identify different keys which end up within the same terminator.
                terminal_data.key = fit_key_to_bits(terminal_data.key, terminal_depth);
                return (terminal_data, EstimationTerminalType::Terminator);
            } else {
                // The traversal has reached the left neighbor.
                let terminal_depth = left_depth;

                // TODO:
                // let key = left_neighbor.view_bits::<Msb0>();
                // let additional_left_shared_bits: Option<usize> = additional_neighbor
                //     .as_ref()
                //     .map(|left| shared_bits(key, left.view_bits::<Msb0>()));
                // terminal_data.left_shared_bits = additional_left_shared_bits;
                // let right_shared_bits = estimation_info
                //     .right_neighbor
                //     .map(|right_k| shared_bits(right_k.view_bits::<Msb0>(), key));
                // terminal_data.right_shared_bits = right_shared_bits;
                let leaf_variant = leaf_variant(&left_neighbor);
                terminal_data.depth = terminal_depth;
                terminal_data.key = left_neighbor;

                return (terminal_data, leaf_variant);
            }
        }

        // The key is under the right subtree, thus this computes the depth of the right neighbor
        // keeping the left one as left neighbor and the additional as right.
        let right_neighbor = estimation_info.right_neighbor.as_ref().cloned().unwrap();
        let right_shared_bits = right_shared_bits.unwrap();
        let (_, _, right_depth) = compute_depth(
            &estimation_info.left_neighbor,
            &additional_neighbor,
            &right_neighbor,
        );

        if right_depth > right_shared_bits {
            // The traversal ends before reaching the right neighbor
            // within a terminator node.
            let terminal_depth = right_shared_bits + 1;
            terminal_data.depth = terminal_depth;
            // Fit the key to exactly terminal_depth makes it possible
            // to identify different keys which end up within the same terminator.
            terminal_data.key = fit_key_to_bits(terminal_data.key, terminal_depth);
            return (terminal_data, EstimationTerminalType::Terminator);
        } else {
            // The traversal has reached the right neighbor.
            let terminal_depth = right_depth;

            // TODO:
            // let key = right_neighbor.view_bits::<Msb0>();
            // let additional_right_shared_bits: Option<usize> = additional_neighbor
            //     .as_ref()
            //     .map(|right| shared_bits(key, right.view_bits::<Msb0>()));
            // let left_shared_bits = estimation_info
            //     .left_neighbor
            //     .map(|left_k| shared_bits(left_k.view_bits::<Msb0>(), key));
            // terminal_data.right_shared_bits = additional_right_shared_bits;
            // terminal_data.left_shared_bits = left_shared_bits;
            let leaf_variant = leaf_variant(&right_neighbor);
            terminal_data.depth = terminal_depth;
            terminal_data.key = right_neighbor;

            return (terminal_data, leaf_variant);
        }
    }

    /// Estimate the final encoded size of the Witness given all the added traversals.
    ///
    /// This is an overestimate, not a precise one.
    pub fn estimate(&self) -> EstimationResult {
        let mut estimation = EstimationResult {
            byte_length: 0,
            #[cfg(feature = "witness-estimation-testing")]
            testing_data: Default::default(),
        };

        // Starting from the total depth, sum of each traversal.
        let mut unique_siblings = self.total_depth;
        // Remove the nodes associated with the bisection of each traversal.
        // UNWRAP: unique siblings are never expected to underflow
        unique_siblings = unique_siblings
            .checked_sub((self.terminals.len() * 2).saturating_sub(2))
            .unwrap();

        // The total number of shared bits is removed from the total depth;
        // each of these shared bits implies that a node can be reconstructed from
        // the unique nodes close to the terminals.
        // let mut prev_shared = None;
        let mut terminals_shared_bits = 0;
        // TODO: future optimization, reduce overestimation.
        // let mut terminators_amount = 0;
        // let mut sequences_amount = 0;

        for w in self.terminals.windows(2) {
            let (curr_terminal, next_terminal) = (&w[0], &w[1]);
            // The number of shared bits between two keys could be deeper
            // than the depth of the two paths.
            let raw_shared_bits =
                shared_bits(curr_terminal.key.view_bits(), next_terminal.key.view_bits());
            let cap = core::cmp::min(curr_terminal.depth, next_terminal.depth).saturating_sub(1);
            let shared_bits = core::cmp::min(raw_shared_bits, cap);

            terminals_shared_bits += shared_bits;

            // TODO: future optimization, reduce overestimation.
            // let max_terminal_shared_bits =
            //     core::cmp::max(prev_shared, Some(raw_shared_bits)).unwrap_or(0);

            // prev_shared = Some(raw_shared_bits);

            // if max_terminal_shared_bits >= curr_terminal.depth {
            //     continue;
            // }

            // // Remove the sequence of terminators which are compacted by the
            // // `SiblingChunk::Terminators` variant.
            // let (terminators, sequnces) =
            //     compute_terminator_sequences(curr_terminal, max_terminal_shared_bits);
            // terminators_amount += terminators;
            // sequences_amount += sequnces;
        }

        // TODO: future optimization, reduce overestimation.
        // if let Some(last_terminal) = self.terminals.last() {
        //     let max_terminal_shared_bits = prev_shared.unwrap_or(0);
        //     if max_terminal_shared_bits < last_terminal.depth {
        //         let (terminators, sequences) =
        //             compute_terminator_sequences(last_terminal, max_terminal_shared_bits);
        //         terminators_amount += terminators;
        //         sequences_amount += sequences;
        //     }
        // }
        //// UNWRAP: unique siblings are never expected to underflow
        //unique_siblings = unique_siblings.checked_sub(terminators_amount).unwrap();

        // Remove the shared bits which will be re-computed.
        // UNWRAP: unique siblings are never expected to underflow
        unique_siblings = unique_siblings.checked_sub(terminals_shared_bits).unwrap();

        // Encoding of the siblings.

        // TODO: future optimization, reduce overestimation.
        // let siblings_encoding_estimation = 4 + (unique_siblings * 33) + (sequences_amount * 3);
        let siblings_encoding_estimation = 4 + (unique_siblings * 33);

        #[cfg(feature = "witness-estimation-testing")]
        {
            estimation.testing_data.paths = self.terminals.len();
            estimation.testing_data.paths_encoding = self.paths_encoding;
            estimation.testing_data.siblings_encoding = siblings_encoding_estimation;

            estimation.testing_data.tot_siblings = self.total_depth;
            estimation.testing_data.shared_bits = terminals_shared_bits;
            estimation.testing_data.pair_bits = (self.terminals.len() * 2).saturating_sub(2);

            estimation.testing_data.unique_siblings = unique_siblings;
            // estimation.testing_data.terminators = terminators_amount;
            // estimation.testing_data.terminator_sequences = sequences_amount;
            estimation.testing_data.terminals = self.terminals.clone();
        }

        // Encoding of the witnessed paths.
        estimation.byte_length = siblings_encoding_estimation + self.paths_encoding;
        estimation
    }
}

// TODO: future optimization, reduce overestimation.
// #[cfg(feature = "codec")]
// fn compute_terminator_sequences(
//     terminal: &TerminalData,
//     terminal_shared_lower_bound: usize,
// ) -> (usize, usize) {
//     // The traversal has gone through the neighbor with which fewer bits are shared.
//     // Between two neighbor nodes we are sure that there are no other nodes and
//     // thus on that side of the path there are only terminator nodes.
//     let (shared_bits, looking_for_bit) =
//         match (&terminal.left_shared_bits, &terminal.right_shared_bits) {
//             (None, None) => return (0, 0),
//             (Some(_), None) => (0, false),
//             (None, Some(_)) => (0, true),
//             (Some(left), Some(right)) if left > right => (*right, false),
//             (Some(left), Some(_)) => (*left, true),
//             // (_, _) => return (0, 0),
//         };
//     // Cap the amount of shared bits to the max amount of shared bits
//     // between trie and terminal neighbors.
//     // if shared_bits < terminal_shared_lower_bound {
//     //     return (0, 0);
//     // }
//     let shared_bits = core::cmp::max(shared_bits, terminal_shared_lower_bound);
//     // There cannot be terminators for depth 0 and 1, also
//     // if between shared_bits and depth there aren't at least
//     // 2 bits, there cannot be any terminator in between.
//     if terminal.depth <= 1 || shared_bits >= terminal.depth - 2 {
//         return (0, 0);
//     }
//     let count = |bits_iter| {
//         let mut terminators = 0;
//         let mut sequences = 0;
//         let mut init_sequence = false;
//         for bit in bits_iter {
//             if bit == looking_for_bit {
//                 init_sequence = true;
//                 terminators += 1;
//             } else {
//                 if init_sequence {
//                     sequences += 1;
//                 }
//                 init_sequence = false;
//             }
//         }

//         if init_sequence {
//             sequences += 1;
//         }

//         (terminators, sequences)
//     };

//     let n_bits = terminal.depth - 2 - shared_bits;
//     let key_bits = terminal.key.len() * 8;
//     if key_bits >= terminal.depth {
//         count(
//             terminal.key.view_bits::<Msb0>()[..terminal.depth - 1]
//                 .iter()
//                 .rev()
//                 .take(n_bits),
//         )
//     } else {
//         let mut bits = terminal.key.view_bits::<Msb0>().to_bitvec();
//         if bits.len() < terminal.depth {
//             bits.extend(core::iter::repeat(false).take(terminal.depth - 1 - bits.len()));
//         }
//         count(bits.iter().rev().take(n_bits))
//     }
// }

// Truncate the key to the specified number of bits, zeroing out
// bits beyond n_bits within the last byte.
#[cfg(feature = "codec")]
fn fit_key_to_bits(key: Vec<u8>, n_bits: usize) -> Vec<u8> {
    let n_bytes = (n_bits + 7) / 8;
    let mut key = key;
    key.resize(n_bytes, 0);
    if n_bits % 8 != 0 {
        if let Some(last) = key.last_mut() {
            let mask = !((1u8 << (8 - n_bits % 8)) - 1);
            *last &= mask;
        }
    }
    key
}
