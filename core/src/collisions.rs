//! This module provides some helper functions to handle key collisions.
//! Two keys collide if they are padded indefinitely with zeros,
//! resulting in the same padded key. The difference between them
//! becomes their initial length.

use crate::{
    hasher::NodeHasher,
    trie::{self, KeyPath, Node, ValueHash},
};
use core::ops::Range;

/// The collision key associated with a key is simply its encoded length.
pub fn collision_key(key: &KeyPath) -> Vec<u8> {
    (key.len() as u16).to_be_bytes().to_vec()
}

/// Check if two key collides and thus fall under the same collision subtree.
pub fn collides(k1: &KeyPath, k2: &KeyPath) -> bool {
    let (k_min, k_max) = if k1.len() < k2.len() {
        (k1, k2)
    } else {
        (k2, k1)
    };
    k_max.starts_with(k_min) && k_max[k_min.len()..].iter().all(|b| *b == 0)
}

/// From an iterator over raw operations, keys, and values, extract all the collision
/// keys and build a subtree for each of them. Use the roots of the newly created tries
/// to replace the batch of collision keys in the initial operations.
pub fn build_collision_subtries<H: NodeHasher>(
    ops: impl Iterator<Item = (KeyPath, ValueHash)>,
) -> Vec<(KeyPath, ValueHash, bool)> {
    let mut ops: Vec<_> = ops.into_iter().map(|(k, h)| (k, h, false)).collect();
    let collision_ranges = extract_collision_ranges(&ops);

    // Build collision subtries and replace batch of ops
    for Range { start, end } in collision_ranges.into_iter().rev() {
        // UNWRAP: start is a valid ops index.
        let collision_subtree_key = ops.get(start).unwrap().0.clone();
        let collision_subtree_root = build_subtrie::<H>(ops.drain(start..end));
        ops.insert(
            start,
            (
                collision_subtree_key,
                collision_subtree_root,
                true, /*collision*/
            ),
        );
    }

    ops
}

/// Use the specified ops to build a collision subtrie.
pub fn build_subtrie<H: NodeHasher>(
    ops: impl IntoIterator<Item = (KeyPath, ValueHash, bool)>,
) -> Node {
    let collision_ops = ops.into_iter().map(|(key, value_hash, _)| {
        let collision_key = collision_key(&key);
        let leaf = trie::LeafData {
            key_path: key,
            value_hash,
            collision: false,
        };
        (collision_key, H::hash_leaf(&leaf), false)
    });

    crate::update::build_trie::<H>(0, collision_ops, |_control| {})
}

// Given a vector of operations, extract the ranges of collision operations.
fn extract_collision_ranges(ops: &Vec<(KeyPath, ValueHash, bool)>) -> Vec<Range<usize>> {
    let mut collision_keys_ranges = vec![];

    let mut pending_range: Option<usize> = None;
    for (idx, window) in ops.windows(2).enumerate() {
        let (k1, k2) = (&window[0].0, &window[1].0);

        let collides = collides(k1, k2);

        match (collides, &pending_range) {
            // range did not started
            (false, None) => (),
            // range starts
            (true, None) => {
                pending_range.replace(idx);
            }
            // range already started
            (true, Some(_)) => (),
            // range finishes
            (false, Some(start)) => {
                collision_keys_ranges.push(*start..idx + 1);
                pending_range = None;
            }
        }

        if idx == ops.len() - 2 && collides {
            // UNWRAP: if collides is true pending_range must be some
            let start = pending_range.take().unwrap();
            collision_keys_ranges.push(start..ops.len());
        }
    }
    collision_keys_ranges
}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    #[test]
    fn extract_collision_ranges() {
        let ops = vec![
            vec![0, 0],
            vec![0, 0, 0],
            vec![0, 1],
            vec![0, 2, 3],
            vec![0, 2, 3, 0],
            vec![0, 2, 3, 0, 0],
            vec![0, 2, 3, 0, 0, 0, 0, 0],
            vec![0, 2, 3, 0, 0, 0, 0, 0, 0],
            vec![0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            vec![1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![2],
            vec![2, 0, 0, 0, 0, 0],
            vec![6, 0, 0, 0, 0, 0],
            vec![128, 0, 0, 0, 0, 0],
            vec![128, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![128, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ]
        .into_iter()
        .map(|key| (key, [0; 32], false))
        .collect();

        let expected_collision_ranges: Vec<Range<usize>> = vec![0..2, 3..9, 11..13, 14..17];

        let collision_ranges = super::extract_collision_ranges(&ops);

        assert_eq!(expected_collision_ranges, collision_ranges);
    }
}
