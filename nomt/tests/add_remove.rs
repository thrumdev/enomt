mod common;

use common::Test;
use hex_literal::hex;
use nomt::trie::Node;

#[test]
fn add_remove_1000() {
    let mut accounts = 0;
    let mut t = Test::new("add_remove");

    let expected_roots = [
        hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        hex!("2e33178da69d2e40de96d6df45e0689809d2725a463a32c4fa9e3bdb31ca7fba"),
        hex!("15dd2153cc9ff8f16d3fce1e83c3b7a966fd82eee43c1b48dfec060e3e309791"),
        hex!("1e3b0cb4d6159cbd87c3d174429669cccb0a6370b8d99b816899f669126ffcc3"),
        hex!("147ae7bd1727e8977944651b9c6e40c03b1a7c66b6365a1faef61de4372a9092"),
        hex!("0740f618d8b29a1da613ac37b78b9f0cfef02ccfc392b7f347dfee1ace26e89f"),
        hex!("2750ccea329ce8d7e3715f836fb88e70d6c12f685cee7e05e13697c15865b753"),
        hex!("1607cad5b1bb597afad927738c19c279433f79d46b62a1a923700c624d667c87"),
        hex!("24285193721cd8797b43c0ad0c77c7075eb8d4f652505f83cebd381fe007d916"),
        hex!("21f78c2189c425f466039e3ebdc25b74e61000b99dcdb636c047b0cdc35ebb69"),
        hex!("0f088ab3fb1f329a6b50d52be777fe224318394d8458b22db4854615e034b3f5"),
    ];

    let mut root = Node::default();
    for i in 0..10 {
        let _ = t.read_id(0);
        for _ in 0..100 {
            common::set_balance(&mut t, accounts, 1000);
            accounts += 1;
        }
        {
            root = t.commit().0.into_inner();
        }

        assert_eq!(root, common::expected_root(accounts));
        assert_eq!(root, expected_roots[i + 1]);
    }

    assert_eq!(root, expected_roots[10]);

    for i in 0..10 {
        for _ in 0..100 {
            accounts -= 1;
            common::kill(&mut t, accounts);
        }
        {
            root = t.commit().0.into_inner();
        }

        assert_eq!(root, common::expected_root(accounts));
        assert_eq!(root, expected_roots[10 - i - 1]);
    }
}
