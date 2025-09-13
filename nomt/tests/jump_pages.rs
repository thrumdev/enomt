mod common;

use common::Test;
use nomt::hasher::{Blake3Hasher, ValueHasher};

#[test]
fn skip_jump() {
    let mut t = Test::new("skip_jump");

    // Writing jump page
    let (key_a, value_a) = (vec![0, 0, 0, 0, 0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 0, 0, 0, 0, 2], vec![2]);
    let new_value_a = vec![3];

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    t.commit();

    // Seek through a jump page modifying a value.
    t.write(key_a.clone(), Some(vec![3]));
    let (root, _) = t.commit();

    let ops = vec![
        (key_a.clone(), Blake3Hasher::hash_value(&new_value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});

    assert_eq!(expected_root, root.into_inner());
}

#[test]
fn split_jump_on_the_left() {
    let mut t = Test::new("split_jump_on_the_left");

    // Writing jump page
    let (key_a, value_a) = (vec![0, 0, 0, 32, 0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 0, 0, 32, 0, 2], vec![2]);

    // root_page -> [0] -> [0, 0] -> [0, 0, 0]
    // -> [0, 0, 0, 0] -> [0, 0, 0, 0, 0] -> [0, 0, 0, 0, 0, 0] -> [0, 0, 0, 0, 0, 0, 0]
    //
    // jump: [0] -> [0, 0, 0, 0, 0, 0, 0]

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    t.commit();

    // Split on the left the jump.
    let (key_c, value_c) = (vec![0, 0, 0, 0], vec![3]);

    // should split at [0, 0, 0, 0]

    t.write(key_c.clone(), Some(value_c.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_a.clone(), Blake3Hasher::hash_value(&value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
        (key_c.clone(), Blake3Hasher::hash_value(&value_c), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {});

    assert_eq!(expected_root, root.into_inner());
}

#[test]
fn split_jump_on_the_right() {
    let mut t = Test::new("split_jump_on_the_right");

    // Writing jump page
    let (key_a, value_a) = (vec![0, 0, 0, 0, 0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 0, 0, 0, 0, 2], vec![2]);

    // root_page -> [0] -> [0, 0] -> [0, 0, 0]
    // -> [0, 0, 0, 0] -> [0, 0, 0, 0, 0] -> [0, 0, 0, 0, 0, 0] -> [0, 0, 0, 0, 0, 0, 0]
    //
    // jump: [0] -> [0, 0, 0, 0, 0, 0, 0]

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    t.commit();

    // Split on the left the jump.
    let (key_c, value_c) = (vec![0, 0, 0, 0b00100000], vec![3]);

    // should split at [0, 0, 0, 0]

    t.write(key_c.clone(), Some(value_c.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_a.clone(), Blake3Hasher::hash_value(&value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
        (key_c.clone(), Blake3Hasher::hash_value(&value_c), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_control| {});

    assert_eq!(expected_root, root.into_inner());
}

#[test]
fn split_jump_left_and_bottom() {
    let mut t = Test::new_with_params(
        "split_jump_left_and_bottom",
        1,      // commit concurrency
        10_000, // hashtable buckets
        None,   // panic on sync
        true,   // cleanup dir
    );

    // Writing jump page
    let (key_a, value_a) = (vec![0, 0, 0, 32, 0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 0, 0, 32, 0, 2], vec![2]);

    // root_page -> [0] -> [0, 0] -> [0, 0, 0]
    // -> [0, 0, 0, 0] -> [0, 0, 0, 0, 8] -> [0, 0, 0, 0, 8, 0] -> [0, 0, 0, 0, 8, 0, 0]
    //
    // jump: [0] -> [0, 0, 0, 0, 8, 0, 0]

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    t.commit();

    // Split on the left the jump.
    let (key_c, value_c) = (vec![0, 0, 0, 0], vec![3]);
    let new_value_a = vec![4];

    // should split at [0, 0, 0, 0]
    t.write(key_c.clone(), Some(value_c.clone()));
    // should modify leaf at [0, 0, 0, 0, 8, 0, 0]
    t.write(key_a.clone(), Some(new_value_a.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_a.clone(), Blake3Hasher::hash_value(&new_value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
        (key_c.clone(), Blake3Hasher::hash_value(&value_c), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {});

    assert_eq!(expected_root, root.into_inner());
}

#[test]
fn split_jump_left_bottom_right_second_half() {
    let mut t = Test::new_with_params(
        "split_jump_left_bottom_right_second_half",
        1,      // commit concurrency
        10_000, // hashtable buckets
        None,   // panic on sync
        true,   // cleanup dir
    );

    // Writing jump page
    let (key_a, value_a) = (vec![0, 0, 0, 32, 0, 0, 0, 0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 0, 0, 32, 0, 0, 0, 0, 2], vec![2]);

    // root_page -> [0] -> [0, 0] -> [0, 0, 0]
    // -> [0, 0, 0, 0] -> [0, 0, 0, 0, 8] -> [0, 0, 0, 0, 8, 0] -> [0, 0, 0, 0, 8, 0, 0]
    // -> [0, 0, 0, 0, 8, 0, 0, 0] -> [0, 0, 0, 0, 8, 0, 0, 0, 0] -> [0, 0, 0, 0, 8, 0, 0, 0, 0, 0] -> [0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0]
    //
    // jump: [0] -> [0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0]

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    t.commit();

    // Split on the left of the jump, then modify the bottom page and then split on the right
    // of the second split of the first jump
    let (key_c, value_c) = (vec![0, 0, 0, 0], vec![3]);
    let (key_d, value_d) = (vec![0, 0, 0, 32, 0, 2], vec![4]);
    let new_value_a = vec![5];

    // should split at [0, 0, 0, 0]
    t.write(key_c.clone(), Some(value_c.clone()));
    // should modify leaf at [0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0]
    t.write(key_a.clone(), Some(new_value_a.clone()));
    // should split at [0, 0, 0, 0, 8, 0, 0, 0]
    t.write(key_d.clone(), Some(value_d.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_c.clone(), Blake3Hasher::hash_value(&value_c), false),
        (key_a.clone(), Blake3Hasher::hash_value(&new_value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
        (key_d.clone(), Blake3Hasher::hash_value(&value_d), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {});

    assert_eq!(expected_root, root.into_inner());
}

#[test]
fn split_jump_left_bottom_right_first_half() {
    let mut t = Test::new_with_params(
        "split_jump_left_bottom_right",
        1,      // commit concurrency
        10_000, // hashtable buckets
        None,   // panic on sync
        true,   // cleanup dir
    );

    // Writing jump page
    let (key_a, value_a) = (vec![0, 0, 0, 0, 0, 0, 32, 0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 0, 0, 0, 0, 0, 32, 0, 2], vec![2]);

    // root_page -> [0] -> [0, 0] -> [0, 0, 0]
    // -> [0, 0, 0, 0] -> [0, 0, 0, 0, 0] -> [0, 0, 0, 0, 0, 0] -> [0, 0, 0, 0, 0, 0, 0]
    // -> [0, 0, 0, 0, 0, 0, 0, 8] -> [0, 0, 0, 0, 0, 0, 0, 8, 0] -> [0, 0, 0, 0, 0, 0, 0, 8, 0, 0] -> [0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0]
    //
    // jump: [0] -> [0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0]

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    t.commit();

    // Split on the left of the jump, then modify the bottom page and then split on the right
    // of the second split of the first jump
    let (key_c, value_c) = (vec![0, 0, 0, 0], vec![3]);
    let (key_d, value_d) = (vec![0, 2], vec![4]);
    let new_value_a = vec![5];

    // should split at [0, 0, 0, 0, 0, 0, 0]
    t.write(key_c.clone(), Some(value_c.clone()));
    // should modify leaf at [0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0]
    t.write(key_a.clone(), Some(new_value_a.clone()));
    // should split at [0, 0]
    t.write(key_d.clone(), Some(value_d.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_c.clone(), Blake3Hasher::hash_value(&value_c), false),
        (key_a.clone(), Blake3Hasher::hash_value(&new_value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
        (key_d.clone(), Blake3Hasher::hash_value(&value_d), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {});

    assert_eq!(expected_root, root.into_inner());
}

#[test]
fn split_jump_twice_on_the_left() {
    let mut t = Test::new_with_params(
        "split_jump_twice_on_the_left",
        1,      // commit concurrency
        10_000, // hashtable buckets
        None,   // panic on sync
        true,   // cleanup dir
    );

    // Writing jump page
    let (key_a, value_a) = (vec![0, 1, 0, 16, 0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 1, 0, 16, 0, 128], vec![2]);

    // root_page -> [0] -> [0, 0] -> [0, 0, 4]
    // -> [0, 0, 4, 0] -> [0, 0, 4, 0, 4] -> [0, 0, 4, 0, 4, 0]
    // jump: [0] -> [0, 0, 4, 0, 4, 0]

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_a.clone(), Blake3Hasher::hash_value(&value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
    ];
    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {});

    assert_eq!(expected_root, root.into_inner());

    // Split on the left of the jump, then modify the bottom page and then split on the right
    // of the second split of the first jump
    let (key_c, value_c) = (vec![0, 0], vec![3]);
    let (key_d, value_d) = (vec![0, 1, 0, 0], vec![4]);

    // should split at [0, 0]
    t.write(key_c.clone(), Some(value_c.clone()));
    // should split at [0, 0, 4, 0]
    t.write(key_d.clone(), Some(value_d.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_c.clone(), Blake3Hasher::hash_value(&value_c), false),
        (key_d.clone(), Blake3Hasher::hash_value(&value_d), false),
        (key_a.clone(), Blake3Hasher::hash_value(&value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {});

    assert_eq!(expected_root, root.into_inner());
}

#[test]
fn split_jump_twice_on_the_right() {
    let mut t = Test::new_with_params(
        "split_jump_twice_on_the_right",
        1,      // commit concurrency
        10_000, // hashtable buckets
        None,   // panic on sync
        true,   // cleanup dir
    );

    // Writing jump page
    let (key_a, value_a) = (vec![0, 0, 0, 0, 0, 0], vec![1]);
    let (key_b, value_b) = (vec![0, 0, 0, 0, 0, 128], vec![2]);

    // root_page -> [0] -> [0, 0] -> [0, 0, 0]
    // -> [0, 0, 0, 0] -> [0, 0, 0, 0, 0] -> [0, 0, 0, 0, 0, 0]
    // jump: [0] -> [0, 0, 0, 0, 0, 0]

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    let (_root, _) = t.commit();

    // Split on the left of the jump, then modify the bottom page and then split on the right
    // of the second split of the first jump
    let (key_c, value_c) = (vec![0, 0, 0, 16], vec![3]);
    let (key_d, value_d) = (vec![0, 1], vec![4]);

    // should split at [0, 0, 0, 0]
    t.write(key_c.clone(), Some(value_c.clone()));
    // should split at [0, 0]
    t.write(key_d.clone(), Some(value_d.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_a.clone(), Blake3Hasher::hash_value(&value_a), false),
        (key_b.clone(), Blake3Hasher::hash_value(&value_b), false),
        (key_c.clone(), Blake3Hasher::hash_value(&value_c), false),
        (key_d.clone(), Blake3Hasher::hash_value(&value_d), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {});

    assert_eq!(expected_root, root.into_inner());
}

#[test]
fn making_jump_longer() {
    let mut t = Test::new_with_params(
        "making_jump_longer",
        1,      // commit concurrency
        10_000, // hashtable buckets
        None,   // panic on sync
        true,   // cleanup dir
    );

    // Writing jump page
    let (key_a, value_a) = (vec![0], vec![1]);
    let (key_b, value_b) = (vec![1], vec![2]);
    let (key_c, value_c) = (vec![1, 0, 0, 128], vec![3]);
    let new_value_b = vec![4];

    t.write(key_a.clone(), Some(value_a.clone()));
    t.write(key_b.clone(), Some(value_b.clone()));
    t.write(key_c.clone(), Some(value_c.clone()));
    t.commit();

    // should make longer [0, 16] -> [0, 16, 0, 0] to [0] -> [0, 16, 0, 0]
    t.write(key_a.clone(), None);
    // update [0, 16, 0, 0]
    t.write(key_b.clone(), Some(new_value_b.clone()));
    let (root, _) = t.commit();

    let ops = vec![
        (key_b.clone(), Blake3Hasher::hash_value(&new_value_b), false),
        (key_c.clone(), Blake3Hasher::hash_value(&value_c), false),
    ];

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {});

    assert_eq!(expected_root, root.into_inner());
}
