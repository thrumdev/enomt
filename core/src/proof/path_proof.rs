//! Proving and verifying inclusion, non-inclusion, and updates to the trie.

use crate::hasher::NodeHasher;
use crate::trie::{
    self, InternalData, KeyPath, LeafData, Node, NodeKind, MAX_KEY_PATH_LEN, TERMINATOR,
};
use crate::trie_pos::TriePosition;

use bitvec::prelude::*;
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Wrapper for a terminal node, it will store the LeafData if it is a leaf node,
/// and just the KeyPath to that terminal if it is a terminator node
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshDeserialize, borsh::BorshSerialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PathProofTerminal {
    Leaf(LeafData),
    Terminator(TriePosition),
}

impl PathProofTerminal {
    /// Return the bit-path to the Terminal Node
    pub fn path(&self) -> &BitSlice<u8, Msb0> {
        match self {
            Self::Leaf(leaf_data) => &leaf_data.key_path.view_bits(),
            Self::Terminator(key_path) => key_path.path(),
        }
    }

    pub fn node<H: NodeHasher>(&self) -> Node {
        match self {
            Self::Leaf(leaf_data) => H::hash_leaf(leaf_data),
            Self::Terminator(_key_path) => TERMINATOR,
        }
    }

    /// Transform this into an optional LeafData.
    pub fn as_leaf_option(&self) -> Option<LeafData> {
        match self {
            Self::Leaf(leaf_data) => Some(leaf_data.clone()),
            Self::Terminator(_) => None,
        }
    }
}

/// A proof of some particular path through the trie.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshDeserialize, borsh::BorshSerialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathProof {
    /// The terminal node encountered when looking up a key. This is always either a terminator or
    /// leaf.
    pub terminal: PathProofTerminal,
    /// Sibling nodes encountered during lookup, in descending order by depth.
    pub siblings: Vec<Node>,
}

impl PathProof {
    /// Verify this path proof.
    /// This ONLY verifies the path proof. It does not verify the key path or value of the terminal
    /// node.
    ///
    /// You MUST use this in conjunction with `confirm_value` or `confirm_nonexistence`.
    ///
    /// Provide the root node and a key path. The key path can be any key that results in the
    /// lookup of the terminal node and must be at least as long as the siblings vector.
    pub fn verify<H: NodeHasher>(
        &self,
        key_path: &BitSlice<u8, Msb0>,
        root: Node,
    ) -> Result<VerifiedPathProof, PathProofVerificationError> {
        if self.siblings.len() > core::cmp::min(key_path.len(), MAX_KEY_PATH_LEN * 8) {
            return Err(PathProofVerificationError::TooManySiblings);
        }

        let mut relevant_path = key_path.to_bitvec();
        relevant_path.resize_with(self.siblings.len(), |_| false);

        let cur_node = self.terminal.node::<H>();

        let new_root = hash_path::<H>(
            cur_node,
            &relevant_path,
            self.siblings.iter().rev().cloned(),
        );

        if new_root == root {
            Ok(VerifiedPathProof {
                key_path: relevant_path.into(),
                terminal: match &self.terminal {
                    PathProofTerminal::Leaf(leaf_data) => Some(leaf_data.clone()),
                    PathProofTerminal::Terminator(_) => None,
                },
                siblings: self.siblings.clone(),
                root,
            })
        } else {
            Err(PathProofVerificationError::RootMismatch)
        }
    }
}

/// Given a node, a path, and a set of siblings, hash up to the root and return it.
/// This only consumes the last `siblings.len()` bits of the path, or the whole path.
/// Siblings are in ascending order from the last bit of `path`.
pub fn hash_path<H: NodeHasher>(
    mut node: Node,
    path: &BitSlice<u8, Msb0>,
    siblings: impl IntoIterator<Item = Node>,
) -> Node {
    for (bit, sibling) in path.iter().by_vals().rev().zip(siblings) {
        let (left, right) = if bit {
            (sibling, node)
        } else {
            (node, sibling)
        };

        let next = InternalData {
            left: left.clone(),
            right: right.clone(),
        };
        node = H::hash_internal(&next);
    }

    node
}

/// An error type indicating that a key is out of scope of a path proof.
#[derive(Debug, Clone, Copy)]
pub struct KeyOutOfScope;

/// Errors in path proof verification.
#[derive(Debug, Clone, Copy)]
pub enum PathProofVerificationError {
    /// Amount of provided siblings is impossible for the expected trie depth.
    TooManySiblings,
    /// Root hash mismatched at the end of the verification.
    RootMismatch,
}

/// A verified path through the trie.
///
/// Each verified path can be used to check up to two kinds of statements:
///   1. That a single key has a specific value.
///   2. That a single or multiple keys do not have a value.
///
/// Statement (1) is true when the path leads to a leaf node and the leaf has the provided key and
/// value.
///
/// Statement (2) is true for any key which begins with the proven path, where the terminal node is
/// either not a leaf or contains a value for a different key.
#[derive(Clone)]
#[must_use = "VerifiedPathProof only checks the trie path, not whether it actually looks up to your expected value."]
pub struct VerifiedPathProof {
    key_path: BitVec<u8, Msb0>,
    terminal: Option<LeafData>,
    siblings: Vec<Node>,
    root: Node,
}

impl VerifiedPathProof {
    /// Get the terminal node. `None` signifies that this path concludes with a [`TERMINATOR`].
    pub fn terminal(&self) -> Option<&LeafData> {
        self.terminal.as_ref()
    }

    /// Get the proven path.
    pub fn path(&self) -> &BitSlice<u8, Msb0> {
        &self.key_path[..]
    }

    /// Get the proven root.
    pub fn root(&self) -> Node {
        self.root
    }

    /// Check whether this path resolves to the given leaf.
    ///
    /// A return value of `Ok(true)` confirms that the key indeed has this value in the trie.
    /// `Ok(false)` confirms that this key has a different value or does not exist.
    ///
    /// Fails if the key is out of the scope of this path.
    pub fn confirm_value(&self, expected_leaf: &LeafData) -> Result<bool, KeyOutOfScope> {
        self.in_scope(&expected_leaf.key_path)
            .map(|_| self.terminal() == Some(expected_leaf))
    }

    /// Check whether this proves that a key has no value in the trie.
    ///
    /// A return value of `Ok(true)` confirms that the key indeed has no value in the trie.
    /// A return value of `Ok(false)` means that the key definitely exists within the trie.
    ///
    /// Fails if the key is out of the scope of this path.
    pub fn confirm_nonexistence(&self, key_path: &KeyPath) -> Result<bool, KeyOutOfScope> {
        self.in_scope(key_path).map(|_| {
            self.terminal()
                .as_ref()
                .map_or(true, |d| &d.key_path != key_path)
        })
    }

    fn in_scope(&self, key_path: &KeyPath) -> Result<(), KeyOutOfScope> {
        let terminal_position = TriePosition::from_bitslice(self.path());
        if terminal_position.subtrie_contains(key_path) {
            Ok(())
        } else {
            Err(KeyOutOfScope)
        }
    }
}

impl fmt::Debug for VerifiedPathProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedPathProof")
            .field("path", &self.path())
            .field("terminal", &self.terminal())
            .field("root", &self.root())
            .finish()
    }
}

/// Errors that can occur when verifying an update proof.
#[derive(Debug, Clone, Copy)]
pub enum VerifyUpdateError {
    /// The paths through the trie were provided out-of-order.
    PathsOutOfOrder,
    /// The operations on the trie were provided out-of-order.
    OpsOutOfOrder,
    /// An operation was out of scope for the path it was provided with.
    OpOutOfScope,
    /// A path was provided without any operations.
    PathWithoutOps,
    /// Paths were verified against different state-roots.
    RootMismatch,
}

/// An update to the node at some path.
pub struct PathUpdate {
    /// The proven path.
    pub inner: VerifiedPathProof,
    /// Update operations to perform on keys that all start with the path.
    pub ops: Vec<(KeyPath, Option<trie::ValueHash>)>,
}

impl fmt::Debug for PathUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PathUpdate")
            .field("inner", &self.inner)
            .field("ops", &self.ops)
            .finish()
    }
}

/// Verify an update operation against the root node. This follows a similar algorithm to the
/// multi-item update, but without altering any backing storage.
///
/// Paths should be ascending, ops should be ascending, all ops should look up to one of the
/// paths in `paths`.
///
/// All paths should share the same root.
///
/// Returns the root of the trie obtained after application of the given updates in the `paths`
/// vector. In case the `paths` is empty, `prev_root` is returned.
// TODO: adapt to FullPrefixSubstree handling
pub fn verify_update<H: NodeHasher>(
    prev_root: Node,
    paths: &[PathUpdate],
) -> Result<Node, VerifyUpdateError> {
    if paths.is_empty() {
        return Ok(prev_root);
    }

    // Verify important properties about the paths.
    for (i, path) in paths.iter().enumerate() {
        // All paths must stem from the same starting root.
        if path.inner.root() != prev_root {
            return Err(VerifyUpdateError::RootMismatch);
        }

        // All paths must be ascending.
        if i != 0 && paths[i - 1].inner.path() >= path.inner.path() {
            return Err(VerifyUpdateError::PathsOutOfOrder);
        }

        // Path's operations must be non-empty.
        if path.ops.is_empty() {
            return Err(VerifyUpdateError::PathWithoutOps);
        }

        for (j, (key, _value)) in path.ops.iter().enumerate() {
            if j != 0 && &path.ops[j - 1].0 >= key {
                return Err(VerifyUpdateError::OpsOutOfOrder);
            }

            let path = path.inner.path();
            if path.len() == 0 {
                continue;
            }

            if !TriePosition::from_bitslice(path).subtrie_contains(key) {
                return Err(VerifyUpdateError::OpOutOfScope);
            }
        }
    }

    // left frontier
    let mut pending_siblings: Vec<(Node, usize)> = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let leaf = path.inner.terminal().map(|x| x.clone());
        let ops = &path.ops;
        let skip = path.inner.path().len();

        let up_layers = match paths.get(i + 1) {
            None => skip, // go to root
            Some(p) => {
                let n = shared_bits(p.inner.path(), path.inner.path());
                // n always < skip
                // we want to end at layer n + 1
                skip - (n + 1)
            }
        };

        let ops = crate::update::leaf_ops_spliced(leaf, ops);
        let sub_root = crate::update::build_trie::<H>(skip, ops, |_| {});

        let mut cur_node = sub_root;
        let mut cur_layer = skip;
        let end_layer = skip - up_layers;
        // iterate siblings up to the point of collision with next path, replacing with pending
        // siblings, and compacting where possible.
        // push (node, end_layer) to pending siblings when done.

        let mut bit_path = path.inner.path().to_bitvec();
        if bit_path.len() < up_layers {
            bit_path.resize_with(up_layers, |_| false);
        }

        for (bit, sibling) in bit_path
            .iter()
            .by_vals()
            .rev()
            .take(up_layers)
            .zip(path.inner.siblings.iter().rev())
        {
            let sibling = if pending_siblings.last().map_or(false, |p| p.1 == cur_layer) {
                // unwrap: checked above
                pending_siblings.pop().unwrap().0
            } else {
                *sibling
            };

            match (NodeKind::of::<H>(&cur_node), NodeKind::of::<H>(&sibling)) {
                (NodeKind::Terminator, NodeKind::Terminator) => {}
                (NodeKind::Leaf, NodeKind::Terminator) => {}
                (NodeKind::Terminator, NodeKind::Leaf) => {
                    // relocate sibling upwards.
                    cur_node = sibling;
                }
                _ => {
                    // otherwise, internal
                    let node_data = if bit {
                        trie::InternalData {
                            left: sibling,
                            right: cur_node,
                        }
                    } else {
                        trie::InternalData {
                            left: cur_node,
                            right: sibling,
                        }
                    };
                    cur_node = H::hash_internal(&node_data);
                }
            }
            cur_layer -= 1;
        }
        pending_siblings.push((cur_node, end_layer));
    }

    // UNWRAP: If `paths` is not empty this can never be `None` since `pending_siblings` is
    // unconditionally appended to.
    Ok(pending_siblings.pop().map(|n| n.0).unwrap())
}

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
