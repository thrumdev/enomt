mod common;
use common::Test;

#[test]
#[should_panic]
fn key_exceed_limit_removal() {
    let mut t = Test::new("key_exceed_limit");
    t.write(vec![1; 1025], None);
    t.commit();
}

#[test]
#[should_panic]
fn key_exceed_limit_insertion() {
    let mut t = Test::new("key_exceed_limit");
    t.write(vec![1; 1025], Some(vec![1]));
    t.commit();
}
