mod common;

use common::Test;

#[test]
fn inserting_and_seeking_collision_leaf() {
    let mut t = Test::new("inserting_and_seeking_collision_leaf");

    let k1 = vec![0; 56];
    let mut k2 = k1.clone();
    *k2.last_mut().unwrap() += 1;

    let (_, _) = {
        t.write(k1.clone(), Some(vec![1]));
        t.write(k2.clone(), Some(vec![2]));
        t.commit()
    };

    let k3 = vec![0; 12];
    let (_, _) = {
        t.write(k3.clone(), Some(vec![3]));
        t.commit()
    };
}
