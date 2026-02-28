mod common;

use std::collections::{BTreeMap, VecDeque};

use common::Test;
use quickcheck::{Arbitrary, Gen, QuickCheck, TestResult};

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct Key {
    inner: Vec<u8>,
}

impl Arbitrary for Key {
    fn arbitrary(g: &mut Gen) -> Key {
        let mut key = Vec::<u8>::arbitrary(g);
        key.truncate(1024);

        if key.is_empty() {
            key.push(u8::arbitrary(g));
        }

        Key { inner: key }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct Value {
    inner: Vec<u8>,
}

impl Arbitrary for Value {
    fn arbitrary(g: &mut Gen) -> Value {
        let mut key = Vec::<u8>::arbitrary(g);
        key.truncate(256);

        if key.is_empty() {
            key.push(u8::arbitrary(g));
        }

        Value { inner: key }
    }
}

#[derive(Clone, Debug)]
struct Inputs {
    // Insertions, modifications/deletions, re-insertions
    key_value_pairs: Vec<(
        BTreeMap<Key, Value>,
        BTreeMap<u16, Option<Value>>,
        BTreeMap<u16, Value>,
    )>,
    // Lentgh of the chain of overlays.
    n_overlays: u8,
    // Iteration ranges.
    iter_keys_info: Vec<(u16, u16)>,
}

impl Arbitrary for Inputs {
    fn arbitrary(g: &mut Gen) -> Inputs {
        Self {
            key_value_pairs: Vec::arbitrary(g),
            n_overlays: u8::arbitrary(g),
            iter_keys_info: Vec::arbitrary(g),
        }
    }
}

fn rescale(init: u16, lower_bound: usize, upper_bound: usize) -> usize {
    ((init as f64 / u16::MAX as f64) * ((upper_bound - 1 - lower_bound) as f64)).round() as usize
        + lower_bound
}

fn inner_nomt_iterator(
    Inputs {
        key_value_pairs,
        n_overlays,
        iter_keys_info,
    }: Inputs,
) -> TestResult {
    // Fill nomt
    let mut t = Test::new("nomt_iterator");

    let mut present_items: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut deleted_items: Vec<Vec<u8>> = Vec::new();
    let mut overlays = VecDeque::new();

    for (insertions, modifications, re_insertions) in key_value_pairs {
        for (Key { inner: key }, Value { inner: value }) in insertions {
            // Skip items that were already present or already deleted because could be re-inserted.
            if present_items.binary_search_by(|(k, _)| k.cmp(&key)).is_ok()
                || deleted_items.binary_search(&key).is_ok()
            {
                continue;
            }

            t.write(key.clone(), Some(value.clone()));
            present_items.push((key, value));
            present_items.sort_unstable_by(|(k1, _), (k2, _)| k1.cmp(k2));
        }

        let mut session_deletion = vec![];
        for (key, maybe_val) in modifications {
            if present_items.is_empty() {
                break;
            }

            let key_index = rescale(key, 0, present_items.len());

            if key_index >= present_items.len() {
                continue;
            }

            let key = if let Some(ref val) = maybe_val {
                present_items[key_index].1 = val.inner.clone();
                present_items[key_index].0.clone()
            } else {
                let (key, _) = present_items.remove(key_index);
                session_deletion.push(key.clone());
                key
            };

            t.write(key, maybe_val.map(|v| v.inner));
        }

        for (key, val) in re_insertions {
            if deleted_items.is_empty() {
                break;
            }
            let key_index = rescale(key, 0, deleted_items.len());
            let key = deleted_items.remove(key_index);
            t.write(key.clone(), Some(val.inner.clone()));
            present_items.push((key, val.inner.clone()));
            present_items.sort_unstable_by(|(k1, _), (k2, _)| k1.cmp(k2));
        }

        for deleted_key in session_deletion {
            deleted_items.push(deleted_key);
            deleted_items.sort_unstable();
        }

        overlays.push_front(t.update().0);

        if overlays.len() > n_overlays as usize {
            let overlay = overlays.pop_back().unwrap();
            t.commit_overlay(overlay);
        }

        t.start_overlay_session(overlays.iter());
    }

    if present_items.is_empty() {
        return TestResult::discard();
    }

    // Test beatree with overlay iteration.
    for key_range_info in iter_keys_info {
        let start_idx = rescale(key_range_info.0, 0, present_items.len());
        let end_idx = rescale(key_range_info.1, start_idx, present_items.len());
        let start_key = present_items[start_idx].0.clone();
        let end_key = present_items[end_idx].0.clone();

        let expected_iter = &present_items[start_idx..end_idx];

        let nomt_iter = t.iterator(start_key, Some(end_key));

        for (expected_pair, nomt_pair) in expected_iter.iter().zip(nomt_iter) {
            assert_eq!(expected_pair, &nomt_pair);
        }
    }

    TestResult::passed()
}

#[test]
fn nomt_iterator() {
    QuickCheck::new()
        .gen(quickcheck::Gen::new(100))
        .max_tests(5)
        .quickcheck(inner_nomt_iterator as fn(_) -> TestResult)
}
