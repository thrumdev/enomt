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
        hex!("13ef673f0b992275c822a99f38a44e3c79b0c1624e4d5c408dc42ce8f24e805d"),
        hex!("1da948be9f974feea5dc2f1b05dcac8c231dbae360f04580382da90625e6c175"),
        hex!("0f4a5ea7ca5710cdd61ac2c4186bf2bb3b5c9bf2853f130fc2829c424cabb247"),
        hex!("22bfddab042377063902ea2a6cf5d48db8e67898a7c707319362f36d42556e50"),
        hex!("008ff4bbe85e460b5d20417a4050b66394fbf87cc6ae111853951c4ee48e5605"),
        hex!("21bfbf20b1f28b758cc203d2dbd06534ca6de4ad27684369bb18f962a95ebf81"),
        hex!("11a66bb46c620458f39e0ac481e7ecca2def776ae0670ad1690d3e0641414b10"),
        hex!("363ddf688b26e326b75fe83aa74723afff7a5d230fd3bb40888f44911d753240"),
        hex!("0b534189c02b5d37b7211c9184860bb432a7a902f4ef3e73dd6c7f655c764934"),
        hex!("281bc50d2c5eeba3ddcf981fae0e796c85a9b86d5b7d64ac758657314b49a37d"),
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
