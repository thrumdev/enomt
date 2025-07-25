//! Hashers (feature-gated) and utilities for implementing them.

use crate::trie::{InternalData, LeafData, LeafDataRef, Node, NodeKind, TERMINATOR};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A trie node hash function specialized for 64 bytes of data.
///
/// Note that it is illegal for the produced hash to equal [0; 32], as this value is reserved
/// for the terminator node.
///
/// A node hasher should domain-separate internal and leaf nodes in some specific way. The
/// recommended approach for binary hashes is to set the two MSBs depending on the node kind.
/// However, for other kinds of hashes (e.g. Poseidon2 or other algebraic hashes), other labeling
/// schemes may be required.
pub trait NodeHasher {
    /// Hash a leaf. This should domain-separate the hash
    /// according to the node kind.
    fn hash_leaf(data: &LeafData) -> [u8; 32];

    /// Hash a leaf reference. This should domain-separate the hash
    /// according to the node kind.
    fn hash_leaf_ref(data: &LeafDataRef) -> [u8; 32];

    /// Hash an internal node. This should domain-separate
    /// the hash according to the node kind.
    fn hash_internal(data: &InternalData) -> [u8; 32];

    /// Get the kind of the given node.
    fn node_kind(node: &Node) -> NodeKind;
}

/// A hasher for arbitrary-length values.
pub trait ValueHasher {
    /// Hash an arbitrary-length value.
    fn hash_value(value: &[u8]) -> [u8; 32];
}

/// Get the node kind, according to a most-significant bit labeling scheme.
///
/// If the MSB is true, it's a leaf. If the node is empty, it's a [`TERMINATOR`]. Otherwise, it's
/// an internal node.
pub fn node_kind_by_msbs(node: &Node) -> NodeKind {
    match node[0] >> 6 {
        0b00 if node == &TERMINATOR => NodeKind::Terminator,
        0b00 => NodeKind::Internal,
        0b01 => NodeKind::Leaf,
        0b10 => NodeKind::CollisionLeaf,
        _ => unreachable!(),
    }
}

/// Set the most-significant bits of the node.
pub fn set_msbs_by_node_kind(node: &mut Node, kind: NodeKind) {
    node[0] &= 0b00111111;
    match kind {
        NodeKind::Internal => (),
        NodeKind::Leaf => node[0] |= 0b01000000,
        NodeKind::CollisionLeaf => node[0] |= 0b10000000,
        NodeKind::Terminator => unreachable!(),
    }
}

/// A simple trait for representing binary hash functions.
pub trait BinaryHash {
    /// Given a bit-string, produce a 32-bit hash.
    fn hash(input: &[u8]) -> [u8; 32];

    /// An optional specialization of `hash` where there are two 32-byte inputs, left and right.
    fn hash2_32_concat(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(left);
        buf[32..64].copy_from_slice(right);
        Self::hash(&buf)
    }

    /// An optional specialization of `hash` where there are two inputs, left and right.
    fn hash2_concat(left: &[u8], right: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(left.len() + right.len());
        buf[0..left.len()].copy_from_slice(left);
        buf[left.len()..right.len()].copy_from_slice(right);
        Self::hash(&buf)
    }
}

/// A node and value hasher constructed from a simple binary hasher.
///
/// This implements a [`ValueHasher`] and [`NodeHasher`] where the node kind is tagged by setting
/// or unsetting the MSB of the hash value.
///
/// The binary hash wrapped by this structure must behave approximately like a random oracle over
/// the space 2^256, i.e. all 256 bit outputs are valid and inputs are uniformly distributed.
///
/// Functions like Sha2/Blake3/Keccak/Groestl all meet these criteria.
pub struct BinaryHasher<H>(core::marker::PhantomData<H>);

impl<H: BinaryHash> ValueHasher for BinaryHasher<H> {
    fn hash_value(value: &[u8]) -> [u8; 32] {
        H::hash(value)
    }
}

impl<H: BinaryHash> NodeHasher for BinaryHasher<H> {
    fn hash_leaf(data: &LeafData) -> [u8; 32] {
        let mut h = H::hash2_concat(&data.key_path, &data.value_hash);
        if data.collision {
            set_msbs_by_node_kind(&mut h, NodeKind::CollisionLeaf);
        } else {
            set_msbs_by_node_kind(&mut h, NodeKind::Leaf);
        };
        h
    }

    fn hash_leaf_ref(data: &LeafDataRef) -> [u8; 32] {
        let mut h = H::hash2_concat(data.key_path, &data.value_hash);
        if data.collision {
            set_msbs_by_node_kind(&mut h, NodeKind::CollisionLeaf);
        } else {
            set_msbs_by_node_kind(&mut h, NodeKind::Leaf);
        };
        h
    }

    fn hash_internal(data: &InternalData) -> [u8; 32] {
        if data.left == TERMINATOR {
            data.right
        } else if data.right == TERMINATOR {
            data.left
        } else {
            let mut h = H::hash2_32_concat(&data.left, &data.right);
            set_msbs_by_node_kind(&mut h, NodeKind::Internal);
            h
        }
    }

    fn node_kind(node: &Node) -> NodeKind {
        node_kind_by_msbs(node)
    }
}

/// Blanket implementation for all implementations of `Digest`
impl<H: digest::Digest<OutputSize = digest::typenum::U32> + Send + Sync> BinaryHash for H {
    fn hash(input: &[u8]) -> [u8; 32] {
        H::digest(input).into()
    }
}

#[cfg(any(feature = "blake3-hasher", test))]
pub use blake3::Blake3Hasher;

/// A node hasher making use of blake3.
#[cfg(any(feature = "blake3-hasher", test))]
pub mod blake3 {
    use super::{BinaryHash, BinaryHasher};

    /// A [`BinaryHash`] implementation for Blake3.
    pub struct Blake3BinaryHasher;

    /// A wrapper around Blake3 for use in NOMT.
    pub type Blake3Hasher = BinaryHasher<Blake3BinaryHasher>;

    impl BinaryHash for Blake3BinaryHasher {
        fn hash(value: &[u8]) -> [u8; 32] {
            blake3::hash(value).into()
        }

        fn hash2_32_concat(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            Self::hash2_concat(left, right)
        }

        fn hash2_concat(left: &[u8], right: &[u8]) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(left);
            hasher.update(right);
            hasher.finalize().into()
        }
    }
}

#[cfg(feature = "sha2-hasher")]
pub use sha2::Sha2Hasher;

/// A node and value hasher making use of sha2-256.
#[cfg(feature = "sha2-hasher")]
pub mod sha2 {
    use super::{BinaryHash, BinaryHasher};
    use sha2::{Digest, Sha256};

    /// A [`BinaryHash`] implementation for Sha2.
    pub struct Sha2BinaryHasher;

    /// A wrapper around sha2-256 for use in NOMT.
    pub type Sha2Hasher = BinaryHasher<Sha2BinaryHasher>;

    impl BinaryHash for Sha2BinaryHasher {
        fn hash(value: &[u8]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(value);
            hasher.finalize().into()
        }

        fn hash2_32_concat(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            Self::hash2_concat(left, right)
        }

        fn hash2_concat(left: &[u8], right: &[u8]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            hasher.finalize().into()
        }
    }
}
