//! Trie proofs and proof verification.
//!
//! The Merkle Trie defined in NOMT is an authenticated data structure, which means that it permits
//! efficient proving against the root. This module exposes types and functions necessary for
//! handling these kinds of proofs.
//!
//! Using the types and functions exposed from this module, you can verify the value of a single
//! key within the trie ([`PathProof`]), the values of multiple keys ([`MultiProof`]), or the result
//! of updating a trie with a set of changes ([`verify_update`]).

use bitvec::{order::Msb0, slice::BitSlice};
pub use multi_proof::{
    verify as verify_multi_proof, verify_update as verify_multi_proof_update, MultiPathProof,
    MultiProof, MultiProofVerificationError, VerifiedMultiProof,
};
pub use path_proof::{
    compact_siblings, sibling_chunks_depth, verify_update, KeyOutOfScope, PathProof,
    PathProofTerminal, PathProofVerificationError, PathUpdate, SiblingChunk, VerifiedPathProof,
    VerifyUpdateError,
};

mod multi_proof;
mod path_proof;

// Count the number of shared bits for the given two bit slices.
// Take into consideration possibly zero padded bits.
pub fn shared_bits(k1: &BitSlice<u8, Msb0>, k2: &BitSlice<u8, Msb0>) -> usize {
    let (k_min, k_max) = if k1.len() < k2.len() {
        (k1, k2)
    } else {
        (k2, k1)
    };

    let mut shared_bits = k_min
        .iter()
        .zip(k_max.iter())
        .take_while(|(a, b)| a == b)
        .count();

    if shared_bits == k_min.len() {
        // count the possibly shared padded zeros
        shared_bits += k_max[shared_bits..].leading_zeros()
    }
    shared_bits
}
