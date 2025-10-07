mod common;

use common::Test;

#[test]
fn beatree_iterator() {
    let mut t = Test::new("iterator");

    for k in 1..100 {
        t.write(vec![k as u8; k], Some(vec![k as u8; k]));
    }
    let _ = t.commit();

    for k in 1..100 {
        let start = vec![k as u8; k];

        let mut iter = t.iterator(start, None);
        for i in k..100 {
            assert_eq!(Some((vec![i as u8; i], vec![i as u8; i])), iter.next());
        }
        assert_eq!(None, iter.next());
    }
}
