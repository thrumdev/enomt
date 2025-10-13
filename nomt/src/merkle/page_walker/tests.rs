use super::{
    trie, Node, NodeHasher, Output, PageSet, PageWalker, TriePosition, UpdatedPage, ROOT_PAGE_ID,
};
use crate::{
    hasher::Blake3Hasher,
    io::PagePool,
    merkle::{page_set::PageOrigin, ElidedChildren},
    page_cache::{Page, PageMut},
    page_diff::PageDiff,
};
use bitvec::prelude::*;
use imbl::HashMap;
use nomt_core::{
    page_id::{ChildPageIndex, PageId, PageIdsIterator},
    trie::LeafData,
};
use std::ops::Deref;

macro_rules! trie_pos {
        ($($t:tt)+) => {
            TriePosition::from_bitslice(bits![u8, Msb0; $($t)+])
        }
    }

macro_rules! key_path {
        ($($t:tt)+) => {{
            let mut path = [0u8; 32];
            let slice = bits![u8, Msb0; $($t)+];
            path.view_bits_mut::<Msb0>()[..slice.len()].copy_from_bitslice(&slice);
            path.to_vec()
        }}
    }

fn val(i: u8) -> [u8; 32] {
    [i; 32]
}

struct MockPageSet {
    page_pool: PagePool,
    inner: HashMap<PageId, Page>,
    reconstructed: HashMap<PageId, (Page, PageOrigin)>,
}

impl Default for MockPageSet {
    fn default() -> Self {
        let page_pool = PagePool::new();
        let mut inner = HashMap::new();
        let reconstructed = HashMap::new();
        inner.insert(ROOT_PAGE_ID, PageMut::pristine_empty(&page_pool).freeze());
        MockPageSet {
            page_pool,
            inner,
            reconstructed,
        }
    }
}

impl MockPageSet {
    fn apply(&mut self, updates: Vec<UpdatedPage>) {
        for page in updates {
            self.inner.insert(page.page_id, page.page.freeze());
        }
    }
}

impl PageSet for MockPageSet {
    fn fresh(&self) -> PageMut {
        let page = PageMut::pristine_empty(&self.page_pool);
        page
    }

    fn contains(&self, page_id: &PageId) -> bool {
        self.inner.contains_key(page_id)
    }

    fn get(&self, page_id: &PageId) -> Option<(Page, PageOrigin)> {
        if let Some(res) = self.reconstructed.get(page_id) {
            return Some(res.clone());
        };

        self.inner.get(page_id).map(|p| {
            (
                p.clone(),
                PageOrigin::Reconstructed {
                    page_leaves_counter: 0,
                    children_leaves_counter: 0,
                    diff: PageDiff::default(),
                },
            )
        })
    }

    fn insert(&mut self, page_id: PageId, page: Page, _page_origin: PageOrigin) {
        self.inner.insert(page_id, page);
    }
}

#[test]
#[should_panic]
fn advance_backwards_panics() {
    let root = trie::TERMINATOR;
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    let page_set = MockPageSet::default();

    let trie_pos_a = trie_pos![1];
    let trie_pos_b = trie_pos![0];
    walker.advance(trie_pos_a, &page_set);
    walker.advance(trie_pos_b, &page_set);
}

#[test]
#[should_panic]
fn advance_same_panics() {
    let root = trie::TERMINATOR;
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    let page_set = MockPageSet::default();
    let trie_pos_a = trie_pos![0];
    walker.advance(trie_pos_a.clone(), &page_set);
    walker.advance(trie_pos_a, &page_set);
}

#[test]
#[should_panic]
fn advance_to_parent_page_panics() {
    let root = trie::TERMINATOR;
    let mut walker = PageWalker::<Blake3Hasher>::new(root, Some(ROOT_PAGE_ID));
    let page_set = MockPageSet::default();
    let trie_pos_a = trie_pos![0, 0, 0, 0, 0, 0];
    walker.advance(trie_pos_a, &page_set);
}

#[test]
#[should_panic]
fn advance_to_root_with_parent_page_panics() {
    let root = trie::TERMINATOR;
    let mut walker = PageWalker::<Blake3Hasher>::new(root, Some(ROOT_PAGE_ID));
    let page_set = MockPageSet::default();
    walker.advance(TriePosition::new(), &page_set);
}

#[test]
fn compacts_and_updates_root_single_page() {
    let root = trie::TERMINATOR;
    let page_set = MockPageSet::default();

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    let trie_pos_a = trie_pos![0, 0];
    walker.advance_and_replace(
        &page_set,
        trie_pos_a,
        vec![
            (key_path![0, 0, 1, 0], val(1)),
            (key_path![0, 0, 1, 1], val(2)),
        ],
    );

    let trie_pos_b = trie_pos![0, 1];
    walker.advance(trie_pos_b, &page_set);

    let trie_pos_c = trie_pos![1];
    walker.advance_and_replace(
        &page_set,
        trie_pos_c,
        vec![(key_path![1, 0], val(3)), (key_path![1, 1], val(4))],
    );

    match walker.conclude(&page_set) {
        Output::Root(new_root, diffs) => {
            assert_eq!(
                new_root,
                nomt_core::update::build_trie::<Blake3Hasher>(
                    0,
                    vec![
                        (key_path![0, 0, 1, 0], val(1), false /*collision*/),
                        (key_path![0, 0, 1, 1], val(2), false),
                        (key_path![1, 0], val(3), false),
                        (key_path![1, 1], val(4), false)
                    ],
                    |_| {}
                )
            );
            assert_eq!(diffs.len(), 1);
            assert_eq!(&diffs[0].page_id, &ROOT_PAGE_ID);
        }
        _ => unreachable!(),
    }
}

#[test]
fn compacts_and_updates_root_multiple_pages() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    walker.advance_and_replace(
        &page_set,
        TriePosition::new(),
        vec![
            (key_path![0, 1, 0, 1, 1, 0], val(1)),
            (key_path![0, 1, 0, 1, 1, 1], val(2)),
        ],
    );

    match walker.conclude(&page_set) {
        Output::Root(_, updates) => {
            page_set.apply(updates);
        }
        _ => unreachable!(),
    }
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    walker.advance_and_replace(
        &page_set,
        trie_pos![0, 1, 0, 1, 1, 0],
        vec![
            (key_path![0, 1, 0, 1, 1, 0], val(1)),
            (key_path![0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0], val(3)),
            (key_path![0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1], val(4)),
        ],
    );

    match walker.conclude(&page_set) {
        Output::Root(new_root, updates) => {
            assert_eq!(
                new_root,
                nomt_core::update::build_trie::<Blake3Hasher>(
                    0,
                    vec![
                        (key_path![0, 1, 0, 1, 1, 0], val(1)),
                        (key_path![0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0], val(3)),
                        (key_path![0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1], val(4)),
                        (key_path![0, 1, 0, 1, 1, 1], val(2)),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k, v, false /*collision*/)),
                    |_| {}
                )
            );
            assert_eq!(updates.len(), 3);
        }
        _ => unreachable!(),
    }
}

#[test]
fn multiple_pages_compacts_up_to_root() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    let leaf_a_key_path = key_path![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let leaf_b_pos = trie_pos![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let leaf_b_key_path = key_path![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let leaf_c_pos = trie_pos![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0];
    let leaf_c_key_path = key_path![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0];
    let leaf_d_pos = trie_pos![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
    let leaf_d_key_path = key_path![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
    let leaf_e_pos = trie_pos![0, 1, 0, 1, 0, 1, 0, 0, 0, 0];
    let leaf_e_key_path = key_path![0, 1, 0, 1, 0, 1, 0, 0, 0, 0];
    let leaf_f_pos = trie_pos![0, 1, 0, 1, 0, 1, 0, 0, 0, 1];
    let leaf_f_key_path = key_path![0, 1, 0, 1, 0, 1, 0, 0, 0, 1];

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();
    walker.advance_and_replace(
        &page_set,
        TriePosition::new(),
        vec![
            (leaf_a_key_path.clone(), val(1)),
            (leaf_b_key_path.clone(), val(2)),
            (leaf_c_key_path.clone(), val(3)),
            (leaf_d_key_path.clone(), val(4)),
            (leaf_e_key_path.clone(), val(5)),
            (leaf_f_key_path.clone(), val(6)),
        ],
    );

    let new_root = match walker.conclude(&page_set) {
        Output::Root(new_root, diffs) => {
            page_set.apply(diffs);
            assert_eq!(
                new_root,
                nomt_core::update::build_trie::<Blake3Hasher>(
                    0,
                    vec![
                        (leaf_a_key_path.clone(), val(1), false),
                        (leaf_b_key_path, val(2), false),
                        (leaf_c_key_path, val(3), false),
                        (leaf_d_key_path, val(4), false),
                        (leaf_e_key_path, val(5), false),
                        (leaf_f_key_path, val(6), false),
                    ],
                    |_| {}
                )
            );
            new_root
        }
        _ => unreachable!(),
    };

    let mut walker = PageWalker::<Blake3Hasher>::new(new_root, None);
    walker.set_inhibit_elision();

    walker.advance_and_replace(&page_set, leaf_b_pos, vec![]);
    walker.advance_and_replace(&page_set, leaf_c_pos, vec![]);
    walker.advance_and_replace(&page_set, leaf_d_pos, vec![]);
    walker.advance_and_replace(&page_set, leaf_e_pos, vec![]);
    walker.advance_and_replace(&page_set, leaf_f_pos, vec![]);

    match walker.conclude(&page_set) {
        Output::Root(new_root, diffs) => {
            assert_eq!(
                new_root,
                nomt_core::update::build_trie::<Blake3Hasher>(
                    0,
                    vec![(leaf_a_key_path, val(1), false /*collision*/),],
                    |_| {}
                )
            );
            assert_eq!(diffs.len(), 0);
        }
        _ => unreachable!(),
    }
}

#[test]
fn sets_child_page_roots() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    let mut walker = PageWalker::<Blake3Hasher>::new(root, Some(ROOT_PAGE_ID));
    let trie_pos_a = trie_pos![0, 0, 0, 0, 0, 0, 0];
    let trie_pos_b = trie_pos![0, 0, 0, 0, 0, 0, 1];
    let trie_pos_c = trie_pos![0, 0, 0, 0, 0, 1, 0];
    let trie_pos_d = trie_pos![0, 0, 0, 0, 0, 1, 1];
    let page_id_a = trie_pos![0, 0, 0, 0, 0, 0, 0].page_id().unwrap();
    let page_id_b = trie_pos![0, 0, 0, 0, 0, 1, 0].page_id().unwrap();
    page_set.inner.insert(
        page_id_a.clone(),
        PageMut::pristine_empty(&page_set.page_pool).freeze(),
    );
    page_set.inner.insert(
        page_id_b.clone(),
        PageMut::pristine_empty(&page_set.page_pool).freeze(),
    );

    walker.advance_and_replace(
        &page_set,
        trie_pos_a,
        vec![(key_path![0, 0, 0, 0, 0, 0, 0], val(1))],
    );

    walker.advance_and_replace(
        &page_set,
        trie_pos_b,
        vec![(key_path![0, 0, 0, 0, 0, 0, 1], val(2))],
    );

    walker.advance_and_replace(
        &page_set,
        trie_pos_c,
        vec![(key_path![0, 0, 0, 0, 0, 1, 0], val(3))],
    );

    walker.advance_and_replace(
        &page_set,
        trie_pos_d,
        vec![(key_path![0, 0, 0, 0, 0, 1, 1], val(4))],
    );

    match walker.conclude(&page_set) {
        Output::ChildPageRoots(page_roots, diffs) => {
            assert_eq!(page_roots.len(), 2);
            assert_eq!(diffs.len(), 2);
            let left_page_id = ROOT_PAGE_ID
                .child_page_id(ChildPageIndex::new(0).unwrap())
                .unwrap();
            let right_page_id = ROOT_PAGE_ID
                .child_page_id(ChildPageIndex::new(1).unwrap())
                .unwrap();

            let diffed_ids = diffs.iter().map(|p| p.page_id.clone()).collect::<Vec<_>>();
            assert!(diffed_ids.contains(&left_page_id));
            assert!(diffed_ids.contains(&right_page_id));
            assert_eq!(page_roots[0].0, trie_pos![0, 0, 0, 0, 0, 0]);
            assert_eq!(page_roots[1].0, trie_pos![0, 0, 0, 0, 0, 1]);

            assert_eq!(
                page_roots[0].1,
                nomt_core::update::build_trie::<Blake3Hasher>(
                    6,
                    vec![
                        (key_path![0, 0, 0, 0, 0, 0, 0], val(1)),
                        (key_path![0, 0, 0, 0, 0, 0, 1], val(2)),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k, v, false /*collision*/)),
                    |_| {}
                )
            );

            assert_eq!(
                page_roots[1].1,
                nomt_core::update::build_trie::<Blake3Hasher>(
                    6,
                    vec![
                        (key_path![0, 0, 0, 0, 0, 1, 0], val(3)),
                        (key_path![0, 0, 0, 0, 0, 1, 1], val(4)),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k, v, false /*collision*/)),
                    |_| {}
                )
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn tracks_sibling_prev_values() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    let path_1 = key_path![0, 0, 0, 0];
    let path_2 = key_path![1, 0, 0, 0];
    let path_3 = key_path![1, 1, 0, 0];
    let path_4 = key_path![1, 1, 1, 0];
    let path_5 = key_path![1, 1, 1, 1];

    // first build a trie with these 5 key-value pairs. it happens to have the property that
    // all the "left" nodes are leaves.
    let root = {
        let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
        walker.advance_and_replace(
            &page_set,
            TriePosition::new(),
            vec![
                (path_1.clone(), val(1)),
                (path_2.clone(), val(2)),
                (path_3.clone(), val(3)),
                (path_4.clone(), val(4)),
                (path_5.clone(), val(5)),
            ],
        );

        match walker.conclude(&page_set) {
            Output::Root(new_root, diffs) => {
                page_set.apply(diffs);
                new_root
            }
            _ => unreachable!(),
        }
    };

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);

    let node_hash = |key_path, val| {
        Blake3Hasher::hash_leaf(&trie::LeafData {
            key_path,
            value_hash: val,
            collision: false,
        })
    };

    let expected_siblings = vec![
        (node_hash(path_1.clone(), val(1)), 1),
        (node_hash(path_2.clone(), val(2)), 2),
        (node_hash(path_3.clone(), val(3)), 3),
        (node_hash(path_4.clone(), val(4)), 4),
    ];

    // replace those leaf nodes one at a time.
    // the sibling stack will be populated as we go.

    walker.advance_and_replace(
        &page_set,
        TriePosition::from_path_and_depth(path_1.clone(), 4),
        vec![(path_1, val(11))],
    );
    assert_eq!(walker.siblings(), &expected_siblings[..0]);

    walker.advance_and_replace(
        &page_set,
        TriePosition::from_path_and_depth(path_2.clone(), 4),
        vec![(path_2, val(12))],
    );
    assert_eq!(walker.siblings(), &expected_siblings[..1]);

    walker.advance_and_replace(
        &page_set,
        TriePosition::from_path_and_depth(path_3.clone(), 4),
        vec![(path_3, val(13))],
    );
    assert_eq!(walker.siblings(), &expected_siblings[..2]);

    walker.advance_and_replace(
        &page_set,
        TriePosition::from_path_and_depth(path_4.clone(), 4),
        vec![(path_4, val(14))],
    );
    assert_eq!(walker.siblings(), &expected_siblings[..3]);

    walker.advance_and_replace(
        &page_set,
        TriePosition::from_path_and_depth(path_5.clone(), 4),
        vec![(path_5, val(15))],
    );
    assert_eq!(walker.siblings(), &expected_siblings[..4]);
}

#[test]
fn internal_node_zeroes_sibling() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    // this is going to create new leaves, with internal nodes going up to the root.
    let leaf_1 = key_path![0, 0, 0, 0, 0, 0, 0, 0];
    let leaf_2 = key_path![0, 0, 0, 0, 0, 0, 0, 1];

    let terminator_1 = TriePosition::from_path_and_depth(key_path![1], 1);
    let terminator_2 = TriePosition::from_path_and_depth(key_path![0, 1], 2);
    let terminator_3 = TriePosition::from_path_and_depth(key_path![0, 0, 1], 3);
    let terminator_4 = TriePosition::from_path_and_depth(key_path![0, 0, 0, 1], 4);
    let terminator_5 = TriePosition::from_path_and_depth(key_path![0, 0, 0, 0, 1], 5);
    let terminator_6 = TriePosition::from_path_and_depth(key_path![0, 0, 0, 0, 0, 1], 6);
    let terminator_7 = TriePosition::from_path_and_depth(key_path![0, 0, 0, 0, 0, 0, 1], 7);

    let mut root_page = PageMut::pristine_empty(&page_set.page_pool);
    let mut page1 = PageMut::pristine_empty(&page_set.page_pool);

    // we place garbage in all the sibling positions for those internal  nodes.
    {
        let garbage: Node = val(69);

        root_page.set_node(terminator_1.node_index(), garbage);
        root_page.set_node(terminator_2.node_index(), garbage);
        root_page.set_node(terminator_3.node_index(), garbage);
        root_page.set_node(terminator_4.node_index(), garbage);
        root_page.set_node(terminator_5.node_index(), garbage);
        root_page.set_node(terminator_6.node_index(), garbage);
        page1.set_node(terminator_7.node_index(), garbage);
    }

    page_set.inner.insert(ROOT_PAGE_ID, root_page.freeze());
    page_set
        .inner
        .insert(terminator_7.page_id().unwrap(), page1.freeze());

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);

    walker.advance_and_replace(
        &page_set,
        TriePosition::new(),
        vec![(leaf_1, val(1)), (leaf_2, val(2))],
    );

    match walker.conclude(&page_set) {
        Output::Root(_, diffs) => {
            page_set.apply(diffs);
        }
        _ => panic!(),
    }

    let root_page = page_set.inner.get(&ROOT_PAGE_ID).unwrap();
    let page1 = page_set
        .inner
        .get(&terminator_7.page_id().unwrap())
        .unwrap();

    // building the internal nodes must zero the garbage slots, now, anything reachable from the
    // root is consistent.
    {
        assert_eq!(root_page.node(terminator_1.node_index()), trie::TERMINATOR);
        assert_eq!(root_page.node(terminator_2.node_index()), trie::TERMINATOR);
        assert_eq!(root_page.node(terminator_3.node_index()), trie::TERMINATOR);
        assert_eq!(root_page.node(terminator_4.node_index()), trie::TERMINATOR);
        assert_eq!(root_page.node(terminator_5.node_index()), trie::TERMINATOR);
        assert_eq!(root_page.node(terminator_6.node_index()), trie::TERMINATOR);
        assert_eq!(page1.node(terminator_7.node_index()), trie::TERMINATOR);
    }
}

#[test]
fn clear_bit_set_on_erased_page() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    let leaf_a_key_path = key_path![0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0];
    let leaf_b_key_path = key_path![0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
    let leaf_c_key_path = key_path![0, 0, 1, 0, 0, 0, 0];

    let leaf_b_pos = trie_pos![0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
    let leaf_c_pos = trie_pos![0, 0, 1, 0, 0, 0, 0];

    let mut page_id_iter = PageIdsIterator::new(leaf_a_key_path.clone());
    let root_page = page_id_iter.next().unwrap();
    let page_id_1 = page_id_iter.next().unwrap();
    let page_id_2 = page_id_iter.next().unwrap();

    let root = {
        let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
        walker.set_inhibit_elision();
        walker.advance_and_replace(
            &page_set,
            TriePosition::new(),
            vec![
                (leaf_a_key_path, val(1)),
                (leaf_b_key_path, val(2)),
                (leaf_c_key_path, val(3)),
            ],
        );

        match walker.conclude(&page_set) {
            Output::Root(new_root, diffs) => {
                page_set.apply(diffs);
                new_root
            }
            _ => unreachable!(),
        }
    };

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    // Remove leaf B. This should clear page 2.
    walker.advance_and_replace(&page_set, leaf_b_pos, vec![]);

    let root = match walker.conclude(&page_set) {
        Output::Root(new_root, updates) => {
            let res = updates.iter().find(|update| update.page_id == page_id_2);
            assert!(res.is_none());
            page_set.apply(updates);
            new_root
        }
        _ => unreachable!(),
    };

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);

    // Now removing leaf C will clear page 1 and the root page.
    walker.advance_and_replace(&page_set, leaf_c_pos, vec![]);

    match walker.conclude(&page_set) {
        Output::Root(_new_root, updates) => {
            let res = updates.iter().find(|update| update.page_id == root_page);
            assert!(res.is_none());
            let res = updates.iter().find(|update| update.page_id == page_id_1);
            assert!(res.is_none());
        }
        _ => unreachable!(),
    }
}

#[test]
fn clear_bit_updated_correctly_within_same_page_walker_pass() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    // Leaves a and b are siblings at positions 2 and 3 on page `page_id_1`.
    // Upon deletion, the page walker will compact up, clearing the page diff
    // at the top of the stack. The insertion of leaves c and d will populate
    // page_id_1 with internal nodes, expecting to erase the clear bit.
    // Finally, leaves will be placed on `page_id_2`.
    let leaf_a_key_path = key_path![0, 0, 1, 0, 1, 0, 0, 0];
    let leaf_b_key_path = key_path![0, 0, 1, 0, 1, 0, 0, 1];
    let a_pos = trie_pos![0, 0, 1, 0, 1, 0, 0, 0];
    let b_pos = trie_pos![0, 0, 1, 0, 1, 0, 0, 1];
    let leaf_c_key_path = key_path![0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0];
    let leaf_d_key_path = key_path![0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1];
    let cd_pos = trie_pos![0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1];

    let mut page_id_iter = PageIdsIterator::new(leaf_c_key_path.clone());
    page_id_iter.next(); // root
    let page_id_1 = page_id_iter.next().unwrap();
    let page_id_2 = page_id_iter.next().unwrap();

    let root = {
        let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
        walker.set_inhibit_elision();
        walker.advance_and_replace(
            &page_set,
            TriePosition::new(),
            vec![(leaf_a_key_path, val(1)), (leaf_b_key_path, val(2))],
        );

        let Output::Root(new_root, updates) = walker.conclude(&page_set) else {
            panic!();
        };

        let diffs: HashMap<PageId, PageDiff> = updates
            .iter()
            .map(|p| (p.page_id.clone(), p.diff.clone()))
            .collect();
        let diff = diffs.get(&page_id_1).unwrap().clone();
        let mut expected_diff = PageDiff::default();
        expected_diff.set_changed(0);
        expected_diff.set_changed(1); // the sibling is zeroed
        expected_diff.set_changed(2);
        expected_diff.set_changed(3);
        assert_eq!(diff, expected_diff);

        page_set.apply(updates);
        new_root
    };

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    walker.advance_and_replace(&page_set, a_pos, vec![]);
    walker.advance_and_replace(&page_set, b_pos, vec![]);
    // During this step, the clear bit is set during the first compaction
    // and later it is expected to be removed.
    walker.advance_and_replace(
        &page_set,
        cd_pos,
        vec![(leaf_c_key_path, val(3)), (leaf_d_key_path, val(4))],
    );

    let Output::Root(_new_root, updates) = walker.conclude(&page_set) else {
        panic!();
    };
    // No page is expected to be cleared.
    let diffs: HashMap<PageId, PageDiff> = updates
        .iter()
        .map(|p| (p.page_id.clone(), p.diff.clone()))
        .collect();
    assert!(!diffs.get(&page_id_1).unwrap().cleared());
    assert!(!diffs.get(&page_id_2).unwrap().cleared());
}

#[test]
fn count_leaves() {
    let root = trie::TERMINATOR;
    let page_set = MockPageSet::default();

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.advance_and_replace(
        &page_set,
        TriePosition::new(),
        vec![
            (key_path![0, 0, 0, 0, 0], val(1)),
            (key_path![0, 0, 0, 1], val(2)),
            (key_path![0, 0, 1, 0, 0], val(3)),
            (key_path![0, 0, 1, 0, 1, 0], val(4)),
            (key_path![0, 0, 1, 0, 1, 1], val(5)),
            (key_path![0, 1, 0, 0], val(6)),
            (key_path![0, 1, 0, 1], val(7)),
            (key_path![1, 0], val(8)),
            (key_path![1, 1, 0, 0], val(9)),
            (key_path![1, 1, 0, 1, 0], val(10)),
            (key_path![1, 1, 0, 1, 1, 0], val(11)),
            (key_path![1, 1, 0, 1, 1, 1], val(12)),
            (key_path![1, 1, 1, 0], val(13)),
        ],
    );

    match walker.conclude(&page_set) {
        Output::Root(_, diffs) => {
            assert_eq!(diffs.len(), 1);
            let n_leaves = super::count_leaves::<Blake3Hasher>(&diffs[0].page);
            assert_eq!(13, n_leaves);
        }
        _ => unreachable!(),
    }
}

#[test]
fn count_cumulative_leaves() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    // Build pages in the first two layers.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    #[rustfmt::skip]
    walker.advance_and_replace(
        &page_set,
        TriePosition::new(),
        vec![
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0], val(1),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1], val(2),),
        ],
    );

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    page_set.apply(updates);

    // Construct leaves in multiple pages and make sure the parent page's leaves counter has been updated correctly.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    #[rustfmt::skip]
    walker.advance_and_replace(
        &page_set,
        trie_pos![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        vec![
            // [8, 8, 8, 16] 2 leaves
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0], val(1),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1], val(2),),

            // [8, 8, 8, 17] 3 leaves
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0], val(3),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0], val(3),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1], val(4),),

            // [8, 8, 8] 1 leaf
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1], val(5),),

            // [8, 8, 8, 49] 3 leaves
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0], val(6),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0], val(7),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1], val(8),),
        ],
    );

    let stack_top = walker.stack.last().unwrap();
    println!("stack_top page id {:?}", stack_top.page_id);
    assert_eq!(stack_top.elision_data.children_leaves_counter, Some(9));
}

#[test]
fn cumulative_delta_leaves() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    // Build pages in the first two layers.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);

    #[rustfmt::skip]
        let ops1 = vec![
            // [8] 2 leaves
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0], val(1),),
        ];

    #[rustfmt::skip]
        let ops2 = vec![
            // [8, 8, 16] 2 leaves
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0], val(1),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1], val(2),),
            // [8, 8, 17] 3 leaves
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0], val(3),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0], val(3),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1], val(4),),
            // [8, 8] 1 leaf
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1], val(5),),
            // [8, 8, 49] 3 leaves
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0], val(6),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0], val(7),),
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1], val(8),),
        ];

    #[rustfmt::skip]
        let ops3 = vec![
            // [8] 2 leaves
            (key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1], val(2),),
        ];

    walker.advance_and_replace(
        &page_set,
        TriePosition::new(),
        [ops1.clone(), ops2.clone(), ops3.clone()].concat(),
    );

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    page_set.apply(updates);

    let page_id = PageId::decode(&[8]).unwrap();
    let (page, _) = page_set.get(&page_id).unwrap();
    let position = trie_pos![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0];
    let maybe_pages = super::reconstruct_pages::<Blake3Hasher>(
        &page,
        page_id,
        position,
        &mut page_set,
        [ops1.clone(), ops2.clone()].concat(),
    );

    if let Some(pages) = maybe_pages {
        for (page_id, page, diff, page_leaves_counter, children_leaves_counter) in pages {
            page_set.reconstructed.insert(
                page_id,
                (
                    page,
                    PageOrigin::Reconstructed {
                        page_leaves_counter,
                        children_leaves_counter,
                        diff,
                    },
                ),
            );
        }
    }

    // Construct leaves in multiple pages and make sure the parent page's leaves counter has been updated correctly.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    #[rustfmt::skip]
        walker.advance_and_replace(
            &page_set,
            // [8, 8, 16] 0 leaf
            trie_pos![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            vec![],
        );
    #[rustfmt::skip]
        walker.advance_and_replace(
            &page_set,
            // [8, 8, 16] 0 leaf
            trie_pos![ 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1],
            vec![],
        );
    walker.advance_and_replace(
        &page_set,
        // [8, 8, 17] 2 leaf
        trie_pos![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        vec![],
    );
    #[rustfmt::skip]
        walker.advance_and_replace(
            &page_set,
            trie_pos![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0],
            vec![
                // [8, 8, 49] 4 leaf
                (key_path![ 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0], val(11),),
                (key_path![ 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1], val(12),),
            ],
        );
    #[rustfmt::skip]
        walker.advance(
            trie_pos![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1],
            &page_set
        );

    let stack_top = &walker.stack.last_mut().unwrap().elision_data;
    assert_eq!(stack_top.children_leaves_counter, Some(6));
}

#[test]
fn cumulative_delta_children() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    // Build pages in the first two layers.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);

    #[rustfmt::skip]
    let ops = vec![
        // [21, 21] 1 leaves
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0], val(1),),
        //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1], val(2),),

        // [21, 21, 21, 0] 4 leaves
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], val(2),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0], val(3),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0], val(4),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1], val(4),),

        // [21, 21, 21] 1 leaves
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1], val(8),),

        // [21, 21, 21, 63] 3 leaves
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0], val(5),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1], val(6),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1], val(7),),
    ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };
    page_set.apply(updates);

    let page_id = PageId::decode(&[21]).unwrap();
    let (page, _) = page_set.get(&page_id).unwrap();
    let position = trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
    let maybe_pages =
        super::reconstruct_pages::<Blake3Hasher>(&page, page_id, position, &mut page_set, ops);

    if let Some(pages) = maybe_pages {
        for (page_id, page, diff, page_leaves_counter, children_leaves_counter) in pages {
            page_set.reconstructed.insert(
                page_id,
                (
                    page,
                    PageOrigin::Reconstructed {
                        page_leaves_counter,
                        children_leaves_counter,
                        diff,
                    },
                ),
            );
        }
    }

    // Construct leaves in multiple pages and make sure the parent page's leaves counter has been updated correctly.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    #[rustfmt::skip]
    walker.advance_and_replace(
        &page_set,
        // [21, 21, 21, 0] 3 leaves
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0],
        vec![],
    );
    #[rustfmt::skip]
    walker.advance_and_replace(
        &page_set,
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
        vec![
            // [21, 21, 21] 2 leaves
            (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0], val(11),),
            (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1], val(12),),
        ],
    );
    #[rustfmt::skip]
    walker.advance_and_replace(
        &page_set,
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1],
        vec![
            // [21, 21, 21, 63] 5 leaves
            (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0], val(11),),
            (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1 ,0], val(12),),
            (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1], val(12),),
        ],
    );
    #[rustfmt::skip]
    walker.advance(
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1],
        &page_set
    );

    let stack_top = walker.stack.last_mut().unwrap();
    assert_eq!(stack_top.elision_data.children_leaves_counter, Some(10));
}

#[test]
fn delete_chain_of_elided_pages() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    // Build pages in the first two layers.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);

    #[rustfmt::skip]
    let ops = vec![
        // [21, 21] 1 leaves
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0], val(1),),

        // [21, 21, 21, 21, 0] 4 leaves
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], val(2),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0], val(3),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0], val(4),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1], val(4),),

        // [21, 21, 21, 21] 1 leaves
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1], val(8),),

        // [21, 21, 21, 21, 63] 3 leaves
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0], val(5),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1], val(6),),
        (key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1], val(7),),
    ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };
    page_set.apply(updates);

    let page_id = PageId::decode(&[21]).unwrap();
    let (page, _) = page_set.get(&page_id).unwrap();
    let position = trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
    let maybe_pages =
        super::reconstruct_pages::<Blake3Hasher>(&page, page_id, position, &mut page_set, ops);

    if let Some(pages) = maybe_pages {
        for (page_id, page, diff, page_leaves_counter, children_leaves_counter) in pages {
            page_set.reconstructed.insert(
                page_id,
                (
                    page,
                    PageOrigin::Reconstructed {
                        page_leaves_counter,
                        children_leaves_counter,
                        diff,
                    },
                ),
            );
        }
    }

    // Construct leaves in multiple pages and make sure the parent page's leaves counter has been updated correctly.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    let mut delete_leaf = |trie_pos| {
        walker.advance_and_replace(&page_set, trie_pos, vec![]);
    };

    #[rustfmt::skip]
    let leaf_positions = vec![
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0],
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1],
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1],
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1],
    ];

    for trie_pos in leaf_positions {
        delete_leaf(trie_pos);
    }

    #[rustfmt::skip]
    walker.advance(
        trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1],
        &page_set
    );

    let stack_top = walker.stack.last_mut().unwrap();
    assert_eq!(stack_top.elision_data.children_leaves_counter, Some(0));
}

#[test]
fn reconstruct_pages() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    #[rustfmt::skip]
        let ops = vec![
                (key_path![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], val(1),),
                (key_path![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], val(2),),
                (key_path![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0], val(3),),
                (key_path![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1], val(4),),
                (key_path![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0], val(5),),
                (key_path![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1], val(6),),
                (key_path![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0], val(7),),
                (key_path![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1], val(8),),
            ];

    // Build all correct pages:
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();
    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());
    let Output::Root(_root, mut correct_pages) = walker.conclude(&page_set) else {
        unreachable!();
    };

    // Build pages in the first two layers.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());
    let Output::Root(_root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };
    assert_eq!(updates.len(), 2);
    updates.iter().find(|update| update.page_id == ROOT_PAGE_ID);
    updates
        .iter()
        .find(|update| update.page_id.encode() == &[24]);
    page_set.apply(updates);

    let mut page_id = ROOT_PAGE_ID;
    page_id = page_id
        .child_page_id(ChildPageIndex::new(24).unwrap())
        .unwrap();
    let page = page_set.get(&page_id).unwrap().0;

    // Reconstruct pages which are expected to be elided.
    let reconstructed_pages: Vec<_> = super::reconstruct_pages::<Blake3Hasher>(
        &page,
        page_id,
        trie_pos![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0],
        &mut page_set,
        ops,
    )
    .unwrap()
    .collect();

    // Make sure that elision bitfield was updated correctly.
    let reconstructed_page = reconstructed_pages
        .iter()
        .find(|(page_id, _, _, _, _)| page_id.encode() == &[24, 24])
        .map(|(_, page, _, _, _)| page)
        .unwrap();

    let elided_children = reconstructed_page.elided_children();
    let expected_elided = [0, 2, 10, 26];
    for i in 0..64 {
        if expected_elided.contains(&i) {
            assert!(elided_children.is_elided(ChildPageIndex::new(i).unwrap()));
        } else {
            assert!(!elided_children.is_elided(ChildPageIndex::new(i).unwrap()));
        }
    }

    // Ensure reconstructed pages are what we expect.
    for (page_id, page, _, _, _) in reconstructed_pages {
        let correct_page = correct_pages
            .iter()
            .position(|correct_page| correct_page.page_id == page_id)
            .map(|idx| correct_pages.remove(idx).page)
            .unwrap();

        let page = if page_id.encode() == &[24, 24] {
            // The correct pages are build without elision,
            // so the elided children bitfield is not present.
            let mut no_bitfield_page = page.deep_copy();
            no_bitfield_page.set_elided_children(&ElidedChildren::new());
            no_bitfield_page.freeze()
        } else {
            page
        };

        assert_eq!(
            correct_page.freeze().into_inner().deref().deref(),
            page.into_inner().deref().deref()
        );
    }
}

#[test]
fn reconstruct_from_jump_page() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    #[rustfmt::skip]
        let ops = vec![
            (key_path![0,1,1,0,0,0,  0,1,1,0,0,0,   0,1,1,0,0,0,  0,1,1,0,0,0,  0,0,0,0,0,0, 0], val(1),),
            (key_path![0,1,1,0,0,0,  0,1,1,0,0,0,   0,1,1,0,0,0,  0,1,1,0,0,0,  0,0,0,0,0,0, 1], val(2),),
            (key_path![0,1,1,0,0,0,  0,1,1,0,0,0,   0,1,1,0,0,0,  0,1,1,0,0,0,  0,0,0,0,1,0, 0], val(3),),
            (key_path![0,1,1,0,0,0,  0,1,1,0,0,0,   0,1,1,0,0,0,  0,1,1,0,0,0,  0,0,0,0,1,0, 1], val(4),),
        ];

    // Build all correct pages:
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();
    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());
    let Output::Root(_root, mut correct_pages) = walker.conclude(&page_set) else {
        unreachable!();
    };

    // Build pages in the first two layers.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());
    let Output::Root(_root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };
    assert_eq!(updates.len(), 2);
    updates.iter().find(|update| update.page_id == ROOT_PAGE_ID);
    updates
        .iter()
        .find(|update| update.page_id.encode() == &[24]);
    page_set.apply(updates);

    let mut page_id = ROOT_PAGE_ID;
    page_id = page_id
        .child_page_id(ChildPageIndex::new(24).unwrap())
        .unwrap();
    let page = page_set.get(&page_id).unwrap().0;

    // Reconstruct pages which are expected to be elided.
    let reconstructed_pages: Vec<_> = super::reconstruct_pages::<Blake3Hasher>(
        &page,
        page_id,
        trie_pos![0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0],
        &mut page_set,
        ops,
    )
    .unwrap()
    .collect();

    // Ensure reconstructed pages are what we expect.
    for (page_id, page, _, _, _) in reconstructed_pages {
        let correct_page = correct_pages
            .iter()
            .position(|correct_page| correct_page.page_id == page_id)
            .map(|idx| correct_pages.remove(idx).page)
            .unwrap();

        let page = if page_id.encode() == &[24, 24, 24, 24] {
            // The correct pages are build without elision,
            // so the elided children bitfield is not present.
            let mut no_bitfield_page = page.deep_copy();
            no_bitfield_page.set_elided_children(&ElidedChildren::new());
            no_bitfield_page.freeze()
        } else {
            page
        };

        assert_eq!(
            correct_page.freeze().into_inner().deref().deref(),
            page.into_inner().deref().deref()
        );
    }
}

#[test]
fn build_one_collision_subtree() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();

    // Build pages in the first two layers.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    #[rustfmt::skip]
        let ops = vec![
            (vec![0b00100000], val(1),),
            (vec![0b00110000], val(2),),
            (vec![0b00110000, 0], val(3),),
        ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(_, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    page_set.apply(updates);

    let (page, _) = page_set.get(&ROOT_PAGE_ID).unwrap();
    let position = trie_pos![0, 0, 1, 1];

    let is_collision = trie::is_collision_leaf::<Blake3Hasher>(&page.node(position.node_index()));
    assert!(is_collision);
}

#[test]
fn build_multiple_collision_subtree() {
    let root = trie::TERMINATOR;
    let page_set = MockPageSet::default();

    // Build pages in the first two layers.
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    #[rustfmt::skip]
        let ops = vec![
            // leaf -> 001
            (vec![0b00100000], val(1),),
            // collision leaf -> 00110
            (vec![0b00110000], val(2),),
            (vec![0b00110000, 0], val(3),),
            // leaf -> 00111
            (vec![0b00111000], val(4),),
            // collision leaf -> 100
            (vec![0b10000000], val(5),),
            (vec![0b10000000, 0], val(6),),
            (vec![0b10000000, 0, 0], val(7),),
            (vec![0b10000000, 0, 0, 0], val(8),),
            // collision leaf -> 101
            (vec![0b10100000], val(9),),
            (vec![0b10100000, 0, 0, 0, 0,0,0, 0, 0,0], val(10),),
            // leaf -> 110
            (vec![0b11000000], val(11),),
            // collision leaf -> 111
            (vec![0b11100000], val(11),),
            (vec![0b11100000, 0], val(12),),
            (vec![0b11100000, 0, 0, 0, 0, 0], val(13),),
        ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(_root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };
    let page = &updates[0].page;
    let n_leaves = super::count_leaves::<Blake3Hasher>(page);
    assert_eq!(n_leaves, 7);

    assert!(trie::is_collision_leaf::<Blake3Hasher>(
        &page.node(trie_pos![0, 0, 1, 1, 0].node_index())
    ));
    assert!(trie::is_collision_leaf::<Blake3Hasher>(
        &page.node(trie_pos![1, 0, 0].node_index())
    ));
    assert!(trie::is_collision_leaf::<Blake3Hasher>(
        &page.node(trie_pos![1, 0, 1].node_index())
    ));
    assert!(trie::is_collision_leaf::<Blake3Hasher>(
        &page.node(trie_pos![1, 1, 1].node_index())
    ));
}

#[test]
fn build_jump_page() {
    let root = trie::TERMINATOR;
    let page_set = MockPageSet::default();
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    #[rustfmt::skip]
        let ops = vec![
            (vec![0b00100000, 0b00100000, 0b00100000, 0b00100000], val(1),),
            (vec![0b00100000, 0b00100000, 0b00100000, 0b00100001], val(2),),
            (vec![0b00100000, 0b10100000], val(3),),
        ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(_, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    let expected_jump_page = updates
        .iter()
        .find(|update| update.page_id == PageId::decode(&[8, 2]).unwrap())
        .unwrap();
    assert!(expected_jump_page.page.jump_data().is_some());
}

#[test]
fn build_clear_jump_page() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    let leaf_a_key_path = vec![0b00100000, 0b00100000, 0b00100000, 0b00100000];
    let leaf_a_pos = TriePosition::from_bitslice(leaf_a_key_path.view_bits::<Msb0>());

    let leaf_b_key_path = vec![0b00100000, 0b00100000, 0b00100000, 0b00100001];
    let leaf_b_pos = TriePosition::from_bitslice(leaf_b_key_path.view_bits::<Msb0>());

    let leaf_c_key_path = vec![0b00110000, 0b00100000, 0b00100000, 0b00100000];
    let leaf_c_pos = TriePosition::from_bitslice(leaf_c_key_path.view_bits::<Msb0>());

    let leaf_d_key_path = vec![0b00110000, 0b00100000, 0b00100000, 0b00100001];

    #[rustfmt::skip]
        let ops = vec![
            (leaf_a_key_path.clone(), val(1),),
            (leaf_b_key_path.clone(), val(2),),
            (leaf_c_key_path.clone(), val(3),),
            (leaf_d_key_path.clone(), val(4),),
        ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    page_set.apply(updates);

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();
    walker.advance_and_replace(&page_set, leaf_a_pos, vec![]);
    walker.advance_and_replace(&page_set, leaf_b_pos, vec![]);
    walker.advance_and_replace(&page_set, leaf_c_pos, vec![]);

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    assert_eq!(updates.len(), 0);

    let leaf_data = LeafData {
        key_path: leaf_d_key_path,
        value_hash: val(4),
        collision: false,
    };
    assert_eq!(root, Blake3Hasher::hash_leaf(&leaf_data));
}

#[test]
fn making_jump_shorter() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    let leaf_a_key_path = vec![0b00000100, 0b00010000, 0b01000001, 0b00000100];
    let leaf_b_key_path = vec![0b00000100, 0b00010000, 0b01000001, 0b00000101];
    let leaf_b_pos = TriePosition::from_bitslice(leaf_b_key_path.view_bits::<Msb0>());
    let leaf_c_key_path = vec![0b00000100, 0b00010000, 0b01000001, 0b00100101];
    let mut leaf_c_pos = TriePosition::from_bitslice(leaf_c_key_path.view_bits::<Msb0>());
    leaf_c_pos.up(5);

    let ops = vec![
        (leaf_a_key_path.clone(), val(1)),
        (leaf_b_key_path.clone(), val(2)),
    ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(
        0,
        ops.into_iter()
            .map(|(key_path, val)| (key_path, val, false)),
        |_| {},
    );

    assert_eq!(expected_root, root);

    assert_eq!(updates.len(), 4);
    page_set.apply(updates);

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    walker.advance_and_replace(
        &page_set,
        leaf_b_pos,
        vec![(leaf_b_key_path.clone(), val(4))],
    );
    walker.advance_and_replace(
        &page_set,
        leaf_c_pos,
        vec![(leaf_c_key_path.clone(), val(3))],
    );

    let Output::Root(_root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    assert_eq!(updates.len(), 5);

    updates
        .iter()
        .find(|update| update.page_id == PageId::decode(&[1, 1, 1, 1, 1]).unwrap())
        .unwrap();
}

#[test]
fn making_jump_shorter_from_top() {
    let root = trie::TERMINATOR;
    let page_set = MockPageSet::default();
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    let leaf_a_key_path = vec![0b000001_00, 0b0001_0000, 0b01_000001, 0b00000000];
    let leaf_b_key_path = vec![0b000001_00, 0b0001_0000, 0b01_000001, 0b10000000];

    #[rustfmt::skip]
        let ops = vec![
            (leaf_a_key_path.clone(), val(1),),
            (leaf_b_key_path.clone(), val(2),),
        ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(
        0,
        ops.into_iter()
            .map(|(key_path, val)| (key_path, val, false)),
        |_| {},
    );

    assert_eq!(expected_root, root);

    assert_eq!(updates.len(), 4);

    let expected_pages = [
        PageId::decode(&[]).unwrap(),
        PageId::decode(&[1]).unwrap(),
        PageId::decode(&[1, 1]).unwrap(),
        PageId::decode(&[1, 1, 1, 1]).unwrap(),
    ];

    for expected_page in expected_pages {
        assert!(updates
            .iter()
            .find(|update| update.page_id == expected_page)
            .is_some())
    }
}

#[test]
fn making_jump_longer() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    let leaf_a_key_path = vec![1];
    let leaf_b_key_path = vec![1, 0, 0, 0, 128];
    let leaf_c_key_path = vec![1, 0, 64];
    let leaf_d_key_path = vec![1, 0, 128];
    let leaf_e_key_path = vec![1, 1];

    let mut leaf_b_pos = TriePosition::from_bitslice(leaf_b_key_path.view_bits::<Msb0>());
    leaf_b_pos.up(7);
    let mut leaf_c_pos = TriePosition::from_bitslice(leaf_c_key_path.view_bits::<Msb0>());
    leaf_c_pos.up(6);
    let mut leaf_d_pos = TriePosition::from_bitslice(leaf_d_key_path.view_bits::<Msb0>());
    leaf_d_pos.up(7);
    let leaf_e_pos = TriePosition::from_bitslice(leaf_e_key_path.view_bits::<Msb0>());

    #[rustfmt::skip]
        let ops = vec![
            (leaf_a_key_path.clone(), val(1),),
            (leaf_b_key_path.clone(), val(2),),
            //(leaf_c_key_path.clone(), val(3),),
            //(leaf_d_key_path.clone(), val(4),),
            (leaf_e_key_path.clone(), val(5),),
        ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(
        0,
        ops.into_iter()
            .map(|(key_path, val)| (key_path, val, false)),
        |_| {},
    );

    assert_eq!(expected_root, root);

    assert_eq!(updates.len(), 5);
    page_set.apply(updates);

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    walker.advance_and_replace(
        &page_set,
        leaf_b_pos,
        vec![(leaf_b_key_path.clone(), val(6))],
    );
    walker.advance_and_replace(&page_set, leaf_c_pos, vec![]);
    walker.advance_and_replace(&page_set, leaf_d_pos, vec![]);
    walker.advance_and_replace(&page_set, leaf_e_pos, vec![]);

    let Output::Root(_root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    assert_eq!(updates.len(), 4);

    let expected_pages = [
        PageId::decode(&[]).unwrap(),
        PageId::decode(&[0]).unwrap(),
        PageId::decode(&[0, 16]).unwrap(),
        PageId::decode(&[0, 16, 0, 0, 0]).unwrap(),
    ];

    for expected_page in expected_pages {
        assert!(updates
            .iter()
            .find(|update| update.page_id == expected_page)
            .is_some())
    }
}

#[test]
fn making_jump_longer_join_pending_jumps() {
    let root = trie::TERMINATOR;
    let mut page_set = MockPageSet::default();
    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    let leaf_a_key_path = vec![0];
    let leaf_b_key_path = vec![0, 0, 0, 64, 0, 0];
    let leaf_c_key_path = vec![0, 0, 0, 64, 0, 1];

    let leaf_a_pos = TriePosition::from_bitslice(bits![u8, Msb0;
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ]);
    let leaf_b_pos = TriePosition::from_bitslice(leaf_b_key_path.view_bits::<Msb0>());

    #[rustfmt::skip]
        let ops = vec![
            (leaf_a_key_path.clone(), val(1),),
            (leaf_b_key_path.clone(), val(2),),
            (leaf_c_key_path.clone(), val(3),),
        ];

    walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

    let Output::Root(root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(
        0,
        ops.into_iter()
            .map(|(key_path, val)| (key_path, val, false)),
        |_| {},
    );

    assert_eq!(expected_root, root);

    assert_eq!(updates.len(), 6);
    page_set.apply(updates);

    let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    walker.set_inhibit_elision();

    walker.advance_and_replace(&page_set, leaf_a_pos, vec![]);
    walker.advance_and_replace(
        &page_set,
        leaf_b_pos,
        vec![(leaf_b_key_path.clone(), val(4))],
    );

    let Output::Root(_root, updates) = walker.conclude(&page_set) else {
        unreachable!();
    };

    assert_eq!(updates.len(), 4);

    let expected_pages = [
        PageId::decode(&[]).unwrap(),
        PageId::decode(&[0]).unwrap(),
        PageId::decode(&[0, 0]).unwrap(),
        PageId::decode(&[0, 0, 0, 0, 16, 0, 0]).unwrap(),
    ];

    for expected_page in expected_pages {
        assert!(updates
            .iter()
            .find(|update| update.page_id == expected_page)
            .is_some())
    }
}

#[test]
fn traverse_transparent_hash_page() {
    let page_set = MockPageSet::default();

    let transparent_hash = |page: &mut PageMut, node, bit_path: &BitSlice<u8, Msb0>| {
        let mut pos = TriePosition::new();
        for bit in bit_path {
            pos.down(*bit);
            let node_index = pos.node_index();
            let sibling_index = pos.sibling_index();
            page.set_node(node_index, node);
            page.set_node(sibling_index, trie::TERMINATOR);
        }
    };

    let paths_to_test = [
        bits![u8, Msb0; 0, 0, 0, 0, 0, 0],
        bits![u8, Msb0; 0, 1, 0, 0, 0, 0],
        bits![u8, Msb0; 0, 0, 1, 0, 0, 0],
        bits![u8, Msb0; 0, 0, 0, 1, 0, 0],
        bits![u8, Msb0; 0, 0, 0, 0, 1, 0],
        bits![u8, Msb0; 0, 0, 0, 0, 0, 1],
        bits![u8, Msb0; 0, 1, 0, 1, 0, 1],
        bits![u8, Msb0; 0, 1, 1, 1, 1, 1],
        bits![u8, Msb0; 1, 1, 1, 1, 1, 1],
        bits![u8, Msb0; 1, 0, 1, 1, 1, 1],
        bits![u8, Msb0; 1, 1, 0, 1, 1, 1],
        bits![u8, Msb0; 1, 1, 1, 0, 1, 1],
        bits![u8, Msb0; 1, 1, 1, 1, 0, 1],
        bits![u8, Msb0; 1, 1, 1, 1, 1, 0],
    ];
    let node = [1; 32];

    for path in paths_to_test {
        let mut page = page_set.fresh();

        transparent_hash(&mut page, node, path);

        assert_eq!(
            super::traverse_transparent_hash_page(&page, node),
            Some(path.to_bitvec())
        );
    }
}
