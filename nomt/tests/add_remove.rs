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
        hex!("200ab71043f626e3f7317cd31cdc6d5685d44d95b00e886b9573b0dca0f6be9e"),
        hex!("24eae8e13695ec388b03e27834c4aa17d4ee622587efe9a045d2c347af8081ca"),
        hex!("11a0447201e309923fbc80c25ecc077ce217dd07a70edba3d21a1308fe8dd56f"),
        hex!("054fe72610350fbd50a96f1831fe59d6634aba65605669ae561752b56620a0de"),
        hex!("39e2187ac766bc5097c6828fc442b165a95beda98b4e8129c6d4e30e930b400a"),
        hex!("0ea8c56f0552ec46c81cfd81cdee5694c89298db53f6b11dd511fe19e5425a51"),
        hex!("1de1da23dbcd955bfe2f2fbfbcb1f0faddd3bb327bdabe8c750ab1464605df42"),
        hex!("16891698734e2cd6b0c7f992951e5f8dbd33e50017a47bfbcab22218161cf71b"),
        hex!("166394fe2bf86644f25e42f8b82720d7000f072ad420d8d54deb2da6b8a52fd5"),
        hex!("384ce73c08b878a5cb288da5791c47b5ecc866e77523c6646482c276f2d5b592"),
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
