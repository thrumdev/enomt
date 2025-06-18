mod common;

use common::Test;

// TODO: with var-len keys this test will be removed
#[test]
fn last_layer_trie() {
    let mut t = Test::new_with_params(
        "last_layer_trie", // name
        1,                 // commit_concurrency
        10_000,            // hashtable_buckets
        None,              // panic_on_sync
        true,              // cleanup_dir
    );

    let key1 = vec![170; 32];
    let mut key2 = key1.clone();
    key2[31] = 171;

    // write two leaf nodes at the last layer of the trie
    t.write(key1.clone(), Some(vec![1; 128]));
    t.write(key2.clone(), Some(vec![2; 128]));
    t.commit();
    assert_eq!(t.read(key1.clone()), Some(vec![1; 128]));
    assert_eq!(t.read(key2.clone()), Some(vec![2; 128]));

    // modify two leaf nodes at the last layer of the trie
    t.write(key1.clone(), Some(vec![3; 100]));
    t.write(key2.clone(), Some(vec![4; 100]));
    t.commit();
    assert_eq!(t.read(key1.clone()), Some(vec![3; 100]));
    assert_eq!(t.read(key2.clone()), Some(vec![4; 100]));

    // delete two leaf nodes at the last layer of the trie
    t.write(key1.clone(), None);
    t.write(key2.clone(), None);
    t.commit();
    assert_eq!(t.read(key1.clone()), None);
    assert_eq!(t.read(key2.clone()), None);
}
