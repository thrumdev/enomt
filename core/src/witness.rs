//! Witnesses of NOMT sessions. These types encapsulate entire sets of reads and writes.

use crate::{
    proof::PathProof,
    trie::{KeyPath, ValueHash},
    trie_pos::TriePosition,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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
    /// Key associated with the trie traversal.
    pub key: KeyPath,
    /// Whether the key is present within the trie.
    pub presence: bool,
    /// Whether a key is not present within the trie but collides
    /// with an existing one, resulting into reaching the same
    /// terminal as if the key would have been the present one.
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
