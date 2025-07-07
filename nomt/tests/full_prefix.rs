mod common;
use common::Test;

// TODO: Do not expect to panic once FullSharedPrefix keys are handled
#[test]
#[should_panic]
fn full_prefix() {
    let mut t = Test::new("add_remove");
    let k1 = vec![4, 5, 128, 0];
    let mut k2 = k1.clone();
    k2[2] += 1;

    t.write(k1.clone(), Some(vec![1]));
    t.write(k2.clone(), Some(vec![2]));
    t.commit();

    assert_eq!(t.read(k1.clone()), Some(vec![1]));
    assert_eq!(t.read(k2), Some(vec![2]));
    t.commit();

    let k3 = k1[..3].to_vec();

    t.write(k3.clone(), Some(vec![3]));
    t.commit();

    assert_eq!(t.read(k3), Some(vec![3]));
    t.commit();
}
