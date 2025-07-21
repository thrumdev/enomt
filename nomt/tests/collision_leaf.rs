mod common;

use common::Test;
use nomt::{
    hasher::{Blake3Hasher, NodeHasher, ValueHasher},
    trie::{KeyPath, LeafData},
};
use nomt_core::collisions::collision_key;

fn build_collision_subtree(items: &[(KeyPath, Vec<u8>)]) -> (KeyPath, [u8; 32], bool) {
    let first_key = items[0].0.clone();

    let collision_ops = items.iter().map(|(k, v)| {
        let leaf = LeafData {
            key_path: k.clone(),
            value_hash: Blake3Hasher::hash_value(&v),
            collision: false,
        };
        (collision_key(k), Blake3Hasher::hash_leaf(&leaf), false)
    });

    let subtree_root =
        nomt_core::update::build_trie::<Blake3Hasher>(0, collision_ops, |_control| {});

    (first_key, subtree_root, true)
}

#[test]
fn collision_leaves() {
    let mut t = Test::new("collision_leaves");

    // Writing two leaves
    let (key_a, value_a) = (vec![0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 1], vec![2]);

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    t.commit();

    // Creating a collision leaf from a leaf
    let (key_c, value_c) = (vec![0, 0, 0], vec![3]);
    t.write(key_c.clone(), Some(value_c.clone()));
    t.commit();

    let op_collision_ac = build_collision_subtree(&[
        (key_a.clone(), value_a.clone()),
        (key_c.clone(), value_c.clone()),
    ]);
    let ops = [
        op_collision_ac.clone(),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());

    // From a leaf creating a subtree containing 2 collision leaves and 2 leaves
    let (key_d, value_d) = (vec![0, 1, 0, 1], vec![4]);
    let (key_e, value_e) = (vec![0, 1, 0, 0], vec![5]);
    let (key_f, value_f) = (vec![0, 1, 1, 1], vec![6]);
    t.write(key_d.clone(), Some(value_d.clone()));
    t.write(key_e.clone(), Some(value_e.clone()));
    t.write(key_f.clone(), Some(value_f.clone()));
    t.commit();

    let op_collision_be =
        build_collision_subtree(&[(key_b.clone(), value_b), (key_e.clone(), value_e.clone())]);
    let ops = [
        op_collision_ac,
        op_collision_be.clone(),
        (key_d.clone(), Blake3Hasher::hash_value(&value_d), false),
        (key_f.clone(), Blake3Hasher::hash_value(&value_f), false),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());

    // Add an item to a collisoin leaf
    let (key_g, value_g) = (vec![0, 0, 0, 0, 0], vec![7]);
    t.write(key_g.clone(), Some(value_g.clone()));
    t.commit();

    let op_collision_acg = build_collision_subtree(&[
        (key_a.clone(), value_a),
        (key_c.clone(), value_c.clone()),
        (key_g.clone(), value_g.clone()),
    ]);
    let ops = [
        op_collision_acg,
        op_collision_be.clone(),
        (key_d.clone(), Blake3Hasher::hash_value(&value_d), false),
        (key_f.clone(), Blake3Hasher::hash_value(&value_f), false),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());

    // Remove an item from a collisoin leaf
    t.write(key_a.clone(), None);
    t.commit();

    let op_collision_cg = build_collision_subtree(&[
        (key_c.clone(), value_c.clone()),
        (key_g.clone(), value_g.clone()),
    ]);
    let ops = [
        op_collision_cg.clone(),
        op_collision_be.clone(),
        (key_d.clone(), Blake3Hasher::hash_value(&value_d), false),
        (key_f.clone(), Blake3Hasher::hash_value(&value_f), false),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());

    // From a collision leaf terminal add an item to the collision subtree and a leaf
    let (key_h, value_h) = (vec![0, 0, 0, 0], vec![8]);
    let (key_i, value_i) = (vec![0, 0, 0, 0, 1], vec![9]);
    t.write(key_h.clone(), Some(value_h.clone()));
    t.write(key_i.clone(), Some(value_i.clone()));
    t.commit();

    let op_collision_cgh = build_collision_subtree(&[
        (key_c.clone(), value_c.clone()),
        (key_g.clone(), value_g.clone()),
        (key_h.clone(), value_h),
    ]);
    let ops = [
        op_collision_cgh.clone(),
        (key_i.clone(), Blake3Hasher::hash_value(&value_i), false),
        op_collision_be.clone(),
        (key_d.clone(), Blake3Hasher::hash_value(&value_d), false),
        (key_f.clone(), Blake3Hasher::hash_value(&value_f), false),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());

    // Delete two leaves and the collision leaf be should move as a standard leaf
    t.write(key_d.clone(), None);
    t.write(key_f.clone(), None);
    t.commit();

    let ops = [
        op_collision_cgh,
        (key_i.clone(), Blake3Hasher::hash_value(&value_i), false),
        op_collision_be.clone(),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());

    // Delete the last item from a collision node
    t.write(key_h.clone(), None);
    t.commit();

    let ops = [
        op_collision_cg,
        (key_i.clone(), Blake3Hasher::hash_value(&value_i), false),
        op_collision_be.clone(),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());

    // Modify and insert new items in collision nodes
    let (key_j, value_j) = (vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0], vec![10]);
    let (key_k, value_k) = (vec![0, 1, 0, 0, 0, 0, 0, 0, 0], vec![11]);
    let new_value_g = vec![12];
    let new_value_b = vec![13];
    t.write(key_g.clone(), Some(new_value_g.clone()));
    t.write(key_b.clone(), Some(new_value_b.clone()));
    t.write(key_j.clone(), Some(value_j.clone()));
    t.write(key_k.clone(), Some(value_k.clone()));
    t.commit();

    let op_collision_cgj = build_collision_subtree(&[
        (key_c.clone(), value_c.clone()),
        (key_g.clone(), new_value_g.clone()),
        (key_j.clone(), value_j.clone()),
    ]);
    let op_collision_bek = build_collision_subtree(&[
        (key_b.clone(), new_value_b.clone()),
        (key_e.clone(), value_e.clone()),
        (key_k.clone(), value_k.clone()),
    ]);

    let ops = [
        op_collision_cgj.clone(),
        (key_i.clone(), Blake3Hasher::hash_value(&value_i), false),
        op_collision_bek.clone(),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());

    // Add a leaf and the collision leaf be should down as a standard leaf
    let (key_l, value_l) = (vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], vec![13]);
    t.write(key_l.clone(), Some(value_l.clone()));
    t.commit();

    let ops = [
        op_collision_cgj,
        (key_i.clone(), Blake3Hasher::hash_value(&value_i), false),
        op_collision_bek,
        (key_l.clone(), Blake3Hasher::hash_value(&value_l), false),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});
    assert_eq!(t.root(), expected_root.into());
}
