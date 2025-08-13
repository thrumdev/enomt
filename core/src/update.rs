//! Trie update logic helpers.

use crate::hasher::NodeHasher;
use crate::trie::{
    self, InternalData, KeyPath, LeafData, LeafDataRef, Node, ValueHash, TERMINATOR,
};

use bitvec::prelude::*;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// TODO: feels extremely out of place.
pub(crate) fn shared_bits(a: &BitSlice<u8, Msb0>, b: &BitSlice<u8, Msb0>) -> usize {
    a.iter().zip(b.iter()).take_while(|(a, b)| a == b).count()
}

fn common_after_prefix(k1: &KeyPath, k2: &KeyPath, skip: usize) -> usize {
    let (k_min, k_max) = if k1.len() < k2.len() {
        (k1.view_bits::<Msb0>(), k2.view_bits::<Msb0>())
    } else {
        (k2.view_bits::<Msb0>(), k1.view_bits::<Msb0>())
    };

    if k_min.len() < skip {
        // If k_min is smaller than skip, it is expected to be padded with zeros.
        // Thus, the number of shared bits will be the number of leading zeros
        // in k_max after skip.
        if k_max.len() < skip {
            // This is not reachable, this would be a case of a full shared prefix.
            unreachable!()
        }
        return k_max[skip..].leading_zeros();
    }

    let mut shared_bits = shared_bits(&k_min[skip..], &k_max[skip..]);
    if shared_bits == k_min.len() - skip {
        // count the possibly shared padded zeros
        // NOTE: No FullPrefixSubtrees are expected here, thus,
        // k_max is not expected to be filled with zeros
        shared_bits += k_max[skip + shared_bits..].leading_zeros()
    }
    shared_bits
}

/// Creates an iterator of all provided operations, with the leaf value and possibly
/// the collision ops spliced in if their keys do not appear in the original ops list.
/// Filters out all `None`s.
pub fn leaf_ops_spliced(
    leaf: Option<LeafData>,
    collision_leaf_ops: Option<Vec<(KeyPath, ValueHash)>>,
    ops: &[(KeyPath, Option<ValueHash>)],
) -> impl Iterator<Item = (KeyPath, ValueHash)> + Clone + '_ {
    // The leaf and the collision ops could be left unchanged, modified, or deleted
    // within ops. What we want to achieve is: prev_ops | leaf / collision_ops | after_ops
    let splice_index = leaf
        .as_ref()
        .and_then(|leaf| ops.binary_search_by_key(&&leaf.key_path, |x| &x.0).err());
    let leaf_in_ops = splice_index.is_none();
    let splice_index = splice_index.unwrap_or(0);

    let mut final_ops = Vec::with_capacity(ops.len());

    // pref_ops
    final_ops.extend(
        ops[..splice_index]
            .iter()
            .filter_map(|(k, o)| o.map(move |value| (k.clone(), value))),
    );

    let mut ops_iter = ops[splice_index..].iter().cloned().peekable();

    // leaf / collision_ops
    if let Some(collision_ops) = collision_leaf_ops {
        let mut collision_ops_iter = collision_ops.into_iter().peekable();

        while let (Some((collision_key, _)), Some((key, value))) =
            (collision_ops_iter.peek(), ops_iter.peek())
        {
            // UNWRAPs: Each unwrap is called after a peek or after
            // ensuring that the value is Some.
            match collision_key.cmp(key) {
                // A collision item is being modified by ops.
                core::cmp::Ordering::Equal if value.is_some() => {
                    let item = ops_iter.next().map(|(k, v)| (k, v.unwrap())).unwrap();
                    collision_ops_iter.next();
                    final_ops.push(item);
                }
                // A collision item is being deleted by ops.
                core::cmp::Ordering::Equal => {
                    ops_iter.next();
                    collision_ops_iter.next();
                }
                // A new collision item is being added.
                core::cmp::Ordering::Greater => {
                    let item = ops_iter.next().map(|(k, v)| (k, v.unwrap())).unwrap();
                    final_ops.push(item);
                }
                // Collision operation is smaller, so save it and skip to the next.
                core::cmp::Ordering::Less => {
                    let item = collision_ops_iter.next().unwrap();
                    final_ops.push(item);
                }
            }
        }

        // Store all remaining collision ops.
        final_ops.extend(collision_ops_iter);
    } else if leaf.is_some() && !leaf_in_ops {
        // UNWRAP: leaf has just been checked to be Some.
        final_ops.push(
            leaf.as_ref()
                .map(|l| (l.key_path.clone(), l.value_hash))
                .unwrap(),
        );
    }

    // after_ops
    final_ops.extend(ops_iter.filter_map(|(k, o)| o.map(move |value| (k.clone(), value))));
    final_ops.into_iter()
}

pub enum WriteNode<'a> {
    Leaf {
        up: bool,
        down: &'a BitSlice<u8, Msb0>,
        leaf_data: LeafDataRef<'a>,
        node: Node,
    },
    Internal {
        jump: usize,
        internal_data: trie::InternalData,
        node: Node,
    },
    Terminator,
}

impl<'a> WriteNode<'a> {
    /// Whether to move up a step before writing the node.
    pub fn up(&self) -> bool {
        match self {
            WriteNode::Leaf { up, .. } => *up,
            WriteNode::Internal { .. } => true,
            WriteNode::Terminator => false,
        }
    }

    /// What path to follow down (after going up) before writing the node.
    pub fn down(&self) -> &BitSlice<u8, Msb0> {
        match self {
            WriteNode::Leaf { down, .. } => down,
            _ => BitSlice::empty(),
        }
    }

    /// The node itself.
    pub fn node(&self) -> Node {
        match self {
            WriteNode::Leaf { node, .. } | WriteNode::Internal { node, .. } => *node,
            WriteNode::Terminator => trie::TERMINATOR,
        }
    }

    /// How many steps to move up after writing the node.
    pub fn jump(&self) -> usize {
        match self {
            WriteNode::Internal { jump, .. } => *jump,
            _ => 0,
        }
    }
}

// Build a trie out of the given prior terminal and operations. Operations should all start
// with the same prefix of len `skip` and be ordered lexicographically. The root node of the
// generated trie is the one residing at path `prefix[..skip]`. When skip=0, this is the actual
// root.
//
// Provide a visitor which will be called for each computed node of the trie.
//
// The visitor is assumed to have a default position at the root of the trie and from
// there will be controlled with `WriteNode`. The changes to the position before writing the node
// can be extracted from the command.
// The root is always visited at the end. If the written node is a leaf, the leaf-data preimage
// will be provided.
pub fn build_trie<H: NodeHasher>(
    skip: usize,
    ops: impl IntoIterator<Item = (KeyPath, ValueHash, bool)>,
    mut visit: impl FnMut(WriteNode),
) -> Node {
    // we build a compact addressable sub-trie in-place based on the given set of ordered keys,
    // ignoring deletions as they are implicit in a fresh sub-trie.
    //
    // an algorithm for building the compact sub-trie follows:
    //
    // consider any three leaves, A, B, C in sorted order by key, with different keys.
    // A and B have some number of shared bits n1
    // B and C have some number of shared bits n2
    //
    // We can make an accurate statement about the position of B regardless of what other material
    // appears in the trie, as long as there is no A' s.t. A < A' < B and no C' s.t. B < C' < C.
    //
    // A is a leaf somewhere to the left of B, which is in turn somewhere to the left of C
    // A and B share an internal node at depth n1, while B and C share an internal node at depth n2.
    // n1 cannot equal n2, as there are only 2 keys with shared prefix n and a != b != c.
    // If n1 is less than n2, then B is a leaf at depth n2+1 along its path (always left)
    // If n2 is less than n1, then B is a leaf at depth n1+1 along its path (always right)
    // QED
    //
    // A similar process applies to the first leaf in the list: it is a leaf on the left of an
    // internal node at depth n, where n is the number of shared bits with the following key.
    //
    // Same for the last leaf in the list: it is on the right of an internal node at depth n,
    // where n is the number of shared bits with the previous key.
    //
    // If the list has a single item, the sub-trie is a single leaf.
    // And if the list is empty, the sub-trie is a terminator.

    // A left-frontier: all modified nodes are to the left of
    // `b`, so this stores their layers.
    let mut pending_siblings: Vec<(Node, usize)> = Vec::new();

    let mut leaf_ops = ops.into_iter();

    let mut a = None;
    let mut b = leaf_ops.next();
    let mut c = leaf_ops.next();

    match (&b, &c) {
        (None, _) => {
            // fast path: delete single node.
            visit(WriteNode::Terminator);
            return trie::TERMINATOR;
        }
        (Some((k, v, collision)), None) => {
            // fast path: place single leaf.
            let leaf_data = trie::LeafDataRef {
                key_path: &k,
                value_hash: *v,
                collision: *collision,
            };
            let leaf = H::hash_leaf_ref(&leaf_data);
            visit(WriteNode::Leaf {
                up: false,
                down: BitSlice::empty(),
                leaf_data,
                node: leaf,
            });

            return leaf;
        }
        _ => {}
    }

    while let Some((this_key, this_val, this_collision)) = b {
        let n1 = a
            .as_ref()
            .map(|(k, _, _)| common_after_prefix(k, &this_key, skip));
        let n2 = c
            .as_ref()
            .map(|(k, _, _)| common_after_prefix(k, &this_key, skip));

        let leaf_data = trie::LeafDataRef {
            key_path: &this_key,
            value_hash: this_val,
            collision: this_collision,
        };
        let leaf = H::hash_leaf_ref(&leaf_data);
        let (leaf_depth, hash_up_layers) = match (n1, n2) {
            (None, None) => {
                // single value - no hashing required.
                (0, 0)
            }
            (None, Some(n2)) => {
                // first value, n2 ancestor will be affected by next.
                (n2 + 1, 0)
            }
            (Some(n1), None) => {
                // last value, hash up to sub-trie root.
                (n1 + 1, n1 + 1)
            }
            (Some(n1), Some(n2)) => {
                // middle value, hash up to incoming ancestor + 1.
                (core::cmp::max(n1, n2) + 1, n1.saturating_sub(n2))
            }
        };

        let mut current_depth = leaf_depth;
        let mut last_node = leaf;
        let down_start = skip + n1.unwrap_or(0);
        let leaf_end_bit = skip + leaf_depth;

        let mut bits = this_key.view_bits::<Msb0>().to_bitvec();
        if bits.len() < leaf_end_bit {
            bits.extend(std::iter::repeat(false).take(leaf_end_bit - bits.len()));
        }

        visit(WriteNode::Leaf {
            up: n1.is_some(), // previous iterations always get to current current_depth + 1
            down: &bits[down_start..leaf_end_bit],
            node: leaf,
            leaf_data,
        });

        let target_depth = current_depth - hash_up_layers;
        let mut last_internal = None;

        // Loop until we reached the target depth compacting up.
        while current_depth != target_depth {
            // next_depth cannot be smaller than the target, it could happen
            // that pending siblings are higher within the subtree,
            // higher than the next subtree that needs to be built.
            let next_depth = std::cmp::max(
                pending_siblings.last().map(|l| l.1).unwrap_or(target_depth),
                target_depth,
            );

            let delta_depth = current_depth - next_depth;

            if delta_depth > 0 {
                // UNWRAP: A branch node and thus relative internal data must
                // have been previously set.
                let last_internal: trie::InternalData = last_internal.take().unwrap();
                visit(WriteNode::Internal {
                    jump: delta_depth,
                    internal_data: last_internal.clone(),
                    node: last_node,
                });
            } else if last_internal.is_some() {
                // UNWRAP: TODO
                let last_internal: trie::InternalData = last_internal.take().unwrap();
                visit(WriteNode::Internal {
                    jump: 0,
                    internal_data: last_internal,
                    node: last_node,
                });
            }

            // No pending siblings in between the last node and the target.
            if next_depth == target_depth {
                current_depth = target_depth;
                break;
            }

            // Hash up with the pending sibling.
            // UNWRAP: if no pending siblings than next_depth is the same as target_depth
            let (sibling, depth) = pending_siblings.pop().unwrap();
            let bit = bits[skip + depth - 1];

            let internal_data = if bit {
                trie::InternalData {
                    left: sibling,
                    right: last_node,
                }
            } else {
                trie::InternalData {
                    left: last_node,
                    right: sibling,
                }
            };

            last_internal.replace(internal_data.clone());
            last_node = H::hash_internal(&internal_data);
            current_depth = next_depth.saturating_sub(1);
        }

        if let Some(internal_data) = last_internal.take() {
            visit(WriteNode::Internal {
                jump: 0,
                internal_data,
                node: last_node,
            });
        }

        pending_siblings.push((last_node, current_depth));

        a = Some((this_key, this_val, this_collision));
        b = c;
        c = leaf_ops.next();
    }

    let new_root = pending_siblings
        .pop()
        .map(|n| n.0)
        .unwrap_or(trie::TERMINATOR);
    new_root
}

#[cfg(test)]
mod tests {
    use crate::trie::{NodeKind, TERMINATOR};

    use super::{bitvec, build_trie, trie, BitVec, LeafData, Msb0, Node, NodeHasher, WriteNode};

    struct DummyNodeHasher;

    impl NodeHasher for DummyNodeHasher {
        fn hash_leaf(data: &trie::LeafData) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&data.key_path);
            hasher.update(&data.value_hash);
            let mut hash: [u8; 32] = hasher.finalize().into();

            // Label with MSB
            hash[0] &= 0b00111111;
            if data.collision {
                hash[0] |= 0b10000000;
            } else {
                hash[0] |= 0b01000000;
            }
            hash
        }

        fn hash_leaf_ref(data: &trie::LeafDataRef) -> [u8; 32] {
            Self::hash_leaf(&LeafData {
                key_path: data.key_path.clone(),
                value_hash: data.value_hash,
                collision: data.collision,
            })
        }

        fn hash_internal(data: &trie::InternalData) -> [u8; 32] {
            let mut hash = if data.left == TERMINATOR {
                data.right
            } else if data.right == TERMINATOR {
                data.left
            } else {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&data.left);
                hasher.update(&data.right);
                hasher.finalize().into()
            };

            // Label with MSB
            hash[0] &= 0b00111111;
            hash
        }

        fn node_kind(node: &Node) -> NodeKind {
            if node[0] >> 7 == 1 {
                NodeKind::Leaf
            } else if node == &TERMINATOR {
                NodeKind::Terminator
            } else {
                NodeKind::Internal
            }
        }
    }

    fn leaf(key: u8) -> (LeafData, [u8; 32]) {
        let key = [key; 32];
        let leaf = trie::LeafData {
            key_path: key.to_vec(),
            value_hash: key.clone(),
            collision: false,
        };

        let hash = DummyNodeHasher::hash_leaf(&leaf);
        (leaf, hash)
    }

    fn branch_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let data = trie::InternalData { left, right };

        let hash = DummyNodeHasher::hash_internal(&data);
        hash
    }

    #[derive(Default)]
    struct Visited {
        key: BitVec<u8, Msb0>,
        visited: Vec<(BitVec<u8, Msb0>, Node)>,
        visited_jumps: Vec<(BitVec<u8, Msb0>, usize, Node)>,
    }

    impl Visited {
        fn at(key: BitVec<u8, Msb0>) -> Self {
            Visited {
                key,
                visited: Vec::new(),
                visited_jumps: Vec::new(),
            }
        }

        fn visit(&mut self, control: WriteNode) {
            if matches!(control, WriteNode::Internal{ jump, ..} if jump > 0) {
                let n = self.key.len() - control.up() as usize;
                let mut from_pos = self.key.clone();
                from_pos.truncate(n);

                let jump = control.jump() as usize;
                let node = control.node();
                self.visited_jumps.push((from_pos, jump, node));

                let n = self.key.len() - control.up() as usize - jump;
                self.key.truncate(n);
                self.key.extend_from_bitslice(&control.down());
                return;
            }

            let n = self.key.len() - control.up() as usize;
            self.key.truncate(n);
            self.key.extend_from_bitslice(&control.down());
            self.visited.push((self.key.clone(), control.node()));
        }
    }

    #[test]
    fn build_empty_trie() {
        let mut visited = Visited::default();
        let root = build_trie::<DummyNodeHasher>(0, vec![], |control| visited.visit(control));

        let visited = visited.visited;

        assert_eq!(visited, vec![(bitvec![u8, Msb0;], [0u8; 32]),],);

        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn build_single_value_trie() {
        let mut visited = Visited::default();

        let (leaf, leaf_hash) = leaf(0xff);
        let root = build_trie::<DummyNodeHasher>(
            0,
            vec![(leaf.key_path, leaf.value_hash, false)],
            |control| visited.visit(control),
        );

        let visited = visited.visited;

        assert_eq!(visited, vec![(bitvec![u8, Msb0;], leaf_hash),],);

        assert_eq!(root, leaf_hash);
    }

    #[test]
    fn sub_trie() {
        let (leaf_a, leaf_hash_a) = leaf(0b0001_0001);
        let (leaf_b, leaf_hash_b) = leaf(0b0001_0010);
        let (leaf_c, leaf_hash_c) = leaf(0b0001_0100);

        let mut visited = Visited::at(bitvec![u8, Msb0; 0, 0, 0, 1]);

        let ops = [leaf_a, leaf_b, leaf_c]
            .into_iter()
            .map(|l| (l.key_path, l.value_hash, false /*collision*/))
            .collect::<Vec<_>>();

        let root = build_trie::<DummyNodeHasher>(4, ops, |control| visited.visit(control));

        let visited_jumps = visited.visited_jumps;
        let visited = visited.visited;

        let branch_ab_hash = branch_hash(leaf_hash_a, leaf_hash_b);
        let branch_abc_hash = branch_hash(branch_ab_hash, leaf_hash_c);
        let root_branch_hash = branch_abc_hash;

        assert_eq!(
            visited,
            vec![
                (bitvec![u8, Msb0; 0, 0, 0, 1, 0, 0, 0], leaf_hash_a),
                (bitvec![u8, Msb0; 0, 0, 0, 1, 0, 0, 1], leaf_hash_b),
                (bitvec![u8, Msb0; 0, 0, 0, 1, 0, 0], branch_ab_hash),
                (bitvec![u8, Msb0; 0, 0, 0, 1, 0, 1], leaf_hash_c),
            ],
        );

        assert_eq!(
            visited_jumps,
            vec![(bitvec![u8, Msb0; 0, 0, 0, 1, 0], 1, branch_abc_hash),],
        );

        assert_eq!(root, root_branch_hash);
    }

    #[test]
    fn multi_value() {
        let (leaf_a, leaf_hash_a) = leaf(0b0001_0000);
        let (leaf_b, leaf_hash_b) = leaf(0b0010_0000);
        let (leaf_c, leaf_hash_c) = leaf(0b0100_0000);
        let (leaf_d, leaf_hash_d) = leaf(0b1010_0000);
        let (leaf_e, leaf_hash_e) = leaf(0b1011_0000);

        let mut visited = Visited::default();

        let ops = [leaf_a, leaf_b, leaf_c, leaf_d, leaf_e]
            .into_iter()
            .map(|l| (l.key_path, l.value_hash, false /*collision*/))
            .collect::<Vec<_>>();

        let root = build_trie::<DummyNodeHasher>(0, ops, |control| visited.visit(control));

        let visited_jumps = visited.visited_jumps;
        let visited = visited.visited;

        let branch_ab_hash = branch_hash(leaf_hash_a, leaf_hash_b);
        let branch_abc_hash = branch_hash(branch_ab_hash, leaf_hash_c);

        let branch_de = branch_hash(leaf_hash_d, leaf_hash_e);

        let branch_abc_de_hash = branch_hash(branch_abc_hash, branch_de);

        assert_eq!(
            visited,
            vec![
                (bitvec![u8, Msb0; 0, 0, 0], leaf_hash_a),
                (bitvec![u8, Msb0; 0, 0, 1], leaf_hash_b),
                (bitvec![u8, Msb0; 0, 0], branch_ab_hash),
                (bitvec![u8, Msb0; 0, 1], leaf_hash_c),
                (bitvec![u8, Msb0; 0], branch_abc_hash),
                (bitvec![u8, Msb0; 1, 0, 1, 0], leaf_hash_d),
                (bitvec![u8, Msb0; 1, 0, 1, 1], leaf_hash_e),
                (bitvec![u8, Msb0;], branch_abc_de_hash),
            ],
        );

        assert_eq!(
            visited_jumps,
            vec![(bitvec![u8, Msb0; 1, 0, 1], 2, branch_de),],
        );

        assert_eq!(root, branch_abc_de_hash);
    }

    #[test]
    fn test_common_after_prefix() {
        let k1 = vec![12, 56, 32];
        let k2 = vec![12, 56, 16];
        assert_eq!(2, super::common_after_prefix(&k1, &k2, 16));

        let k1 = vec![12, 56, 0b11001100];
        let k2 = vec![12, 56, 0b11000100];
        assert_eq!(12, super::common_after_prefix(&k1, &k2, 8));

        let k1 = vec![12, 56];
        let k2 = vec![12, 56, 0b00000001];
        assert_eq!(15, super::common_after_prefix(&k1, &k2, 8));

        let k2 = vec![12, 56, 0b00000001];
        let k1 = vec![12, 56];
        assert_eq!(15, super::common_after_prefix(&k1, &k2, 8));

        let k1 = vec![12, 56];
        let k2 = vec![12, 56, 0b00000001];
        assert_eq!(6, super::common_after_prefix(&k1, &k2, 17));
    }

    fn leaf_from_slice(key: &[u8]) -> (LeafData, [u8; 32]) {
        let leaf = trie::LeafData {
            key_path: key.to_vec(),
            value_hash: [key[0]; 32],
            collision: false,
        };

        let hash = DummyNodeHasher::hash_leaf(&leaf);
        (leaf, hash)
    }

    #[test]
    fn subtree_root_is_jump_node() {
        let (leaf_a, leaf_hash_a) = leaf_from_slice(&[0b0001_0001, 0b0001_0000]);
        let (leaf_b, leaf_hash_b) = leaf_from_slice(&[0b0001_0001, 0b0001_0001]);

        let mut visited = Visited::at(bitvec![u8, Msb0;]);

        let ops = [leaf_a, leaf_b]
            .into_iter()
            .map(|l| (l.key_path, l.value_hash, false /*collision*/))
            .collect::<Vec<_>>();

        build_trie::<DummyNodeHasher>(0, ops, |control| visited.visit(control));

        let visited_jumps = visited.visited_jumps;

        let expected_jump_node = branch_hash(leaf_hash_a, leaf_hash_b);
        assert_eq!(visited_jumps.len(), 1);
        assert_eq!(
            visited_jumps[0].0,
            bitvec![u8, Msb0; 0,0,0,1,0,0,0,1,0,0,0,1,0,0,0]
        );
        assert_eq!(visited_jumps[0].1, 15);
        assert_eq!(visited_jumps[0].2, expected_jump_node);
    }

    #[test]
    fn jumps_to_subtree_root() {
        let (leaf_a, leaf_hash_a) =
            leaf_from_slice(&[0b00100000, 0b00100000, 0b00000000, 0b00100000]);
        let (leaf_b, leaf_hash_b) =
            leaf_from_slice(&[0b00100000, 0b00100000, 0b00000000, 0b00100001]);
        let (leaf_c, leaf_hash_c) =
            leaf_from_slice(&[0b00100000, 0b00100000, 0b00100000, 0b00100000, 0b00100000]);
        let (leaf_d, leaf_hash_d) =
            leaf_from_slice(&[0b00100000, 0b00100000, 0b00100000, 0b00100000, 0b00100001]);

        let mut visited = Visited::at(bitvec![u8, Msb0;]);

        let ops = [leaf_a, leaf_b, leaf_c, leaf_d]
            .into_iter()
            .map(|l| (l.key_path, l.value_hash, false /*collision*/))
            .collect::<Vec<_>>();

        build_trie::<DummyNodeHasher>(0, ops, |control| visited.visit(control));

        let visited_jumps = visited.visited_jumps;

        let jump_ab = branch_hash(leaf_hash_a, leaf_hash_b);
        assert_eq!(visited_jumps.len(), 3);

        assert_eq!(visited_jumps[0].0.len(), 31);
        assert_eq!(visited_jumps[0].1, 12);
        assert_eq!(visited_jumps[0].2, jump_ab);

        let jump_cd = branch_hash(leaf_hash_c, leaf_hash_d);
        assert_eq!(visited_jumps[1].0.len(), 39);
        assert_eq!(visited_jumps[1].1, 20);
        assert_eq!(visited_jumps[1].2, jump_cd);

        let jump = branch_hash(jump_ab, jump_cd);
        assert_eq!(visited_jumps[2].0.len(), 18);
        assert_eq!(visited_jumps[2].1, 18);
        assert_eq!(visited_jumps[2].2, jump);
    }

    #[test]
    fn jump_node_in_subtree() {
        let (leaf_a, leaf_hash_a) = leaf_from_slice(&[0b0001_0101, 0b1001_0000]);
        let (leaf_b, leaf_hash_b) = leaf_from_slice(&[0b0001_0101, 0b1001_0001]);
        let (leaf_c, _leaf_hash_c) = leaf_from_slice(&[0b1000_0000]);

        let mut visited = Visited::at(bitvec![u8, Msb0;]);

        let ops = [leaf_a, leaf_b, leaf_c]
            .into_iter()
            .map(|l| (l.key_path, l.value_hash, false /*collision*/))
            .collect::<Vec<_>>();

        build_trie::<DummyNodeHasher>(0, ops, |control| visited.visit(control));

        let visited_jumps = visited.visited_jumps;

        let expected_jump_node = branch_hash(leaf_hash_a, leaf_hash_b);
        assert_eq!(visited_jumps.len(), 1);
        assert_eq!(
            visited_jumps[0].0,
            bitvec![u8, Msb0; 0,0,0,1,0,1,0,1,1,0,0,1,0,0,0]
        );
        assert_eq!(visited_jumps[0].1, 14);
        assert_eq!(visited_jumps[0].2, expected_jump_node);
    }

    #[test]
    fn jump_nodes_in_subtree() {
        let (leaf_a, leaf_hash_a) = leaf_from_slice(&[0b0001_0001, 0b0001_0000]);
        let (leaf_b, leaf_hash_b) = leaf_from_slice(&[0b0001_0001, 0b0001_0001]);
        let (leaf_c, leaf_hash_c) = leaf_from_slice(&[0b1000_0000, 0b1000_0000, 0b1000_0000]);
        let (leaf_d, leaf_hash_d) = leaf_from_slice(&[0b1000_0000, 0b1000_0000, 0b1000_0001]);

        let mut visited = Visited::at(bitvec![u8, Msb0;]);

        let ops = [leaf_a, leaf_b, leaf_c, leaf_d]
            .into_iter()
            .map(|l| (l.key_path, l.value_hash, false /*collision*/))
            .collect::<Vec<_>>();

        build_trie::<DummyNodeHasher>(0, ops, |control| visited.visit(control));

        let visited_jumps = visited.visited_jumps;

        let expected_jump_node = branch_hash(leaf_hash_a, leaf_hash_b);
        assert_eq!(visited_jumps.len(), 2);
        assert_eq!(
            visited_jumps[0].0,
            bitvec![u8, Msb0; 0,0,0,1,0,0,0,1,0,0,0,1,0,0,0]
        );
        assert_eq!(visited_jumps[0].1, 14);
        assert_eq!(visited_jumps[0].2, expected_jump_node);

        let expected_jump_node = branch_hash(leaf_hash_c, leaf_hash_d);
        assert_eq!(
            visited_jumps[1].0,
            bitvec![u8, Msb0; 1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0]
        );
        assert_eq!(visited_jumps[1].1, 22);
        assert_eq!(visited_jumps[1].2, expected_jump_node);
    }

    #[test]
    fn chain_of_jump_nodes_in_subtree() {
        let (leaf_a, leaf_hash_a) =
            leaf_from_slice(&[0b0001_0001, 0b0001_0000, 0b0001_0000, 0b0001_0000]);
        let (leaf_b, leaf_hash_b) =
            leaf_from_slice(&[0b0001_0001, 0b0001_0001, 0b0001_0000, 0b0001_0000]);
        let (leaf_c, leaf_hash_c) =
            leaf_from_slice(&[0b0001_0001, 0b0001_0001, 0b0001_0000, 0b0001_0001]);
        let (leaf_d, _leaf_hash_d) = leaf_from_slice(&[0b1000_0000]);

        let mut visited = Visited::at(bitvec![u8, Msb0;]);

        let ops = [leaf_a, leaf_b, leaf_c, leaf_d]
            .into_iter()
            .map(|l| (l.key_path, l.value_hash, false /*collision*/))
            .collect::<Vec<_>>();

        build_trie::<DummyNodeHasher>(0, ops, |control| visited.visit(control));

        let visited_jumps = visited.visited_jumps;

        let jump_bc = branch_hash(leaf_hash_b, leaf_hash_c);
        assert_eq!(visited_jumps.len(), 2);
        assert_eq!(
            visited_jumps[0].0,
            bitvec![u8, Msb0; 0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0]
        );
        assert_eq!(visited_jumps[0].1, 15);
        assert_eq!(visited_jumps[0].2, jump_bc);

        let expected_jump = branch_hash(leaf_hash_a, jump_bc);
        assert_eq!(
            visited_jumps[1].0,
            bitvec![u8, Msb0; 0,0,0,1,0,0,0,1,0,0,0,1,0,0,0]
        );
        assert_eq!(visited_jumps[1].1, 14);
        assert_eq!(visited_jumps[1].2, expected_jump);
    }
}
