mod common;

use codec::Encode;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
    // Reads, Writes, modifications/deletions, re-insertions
    key_value_pairs: Vec<(
        BTreeSet<(u16, bool)>,
        BTreeMap<Key, Value>,
        BTreeMap<u16, Option<Value>>,
        BTreeMap<u16, Value>,
    )>,
    // Length of the chain of overlays.
    n_overlays: u8,
}

impl Arbitrary for Inputs {
    fn arbitrary(g: &mut Gen) -> Inputs {
        Self {
            key_value_pairs: Vec::arbitrary(g),
            n_overlays: u8::arbitrary(g),
        }
    }
}

fn rescale(init: u16, lower_bound: usize, upper_bound: usize) -> usize {
    ((init as f64 / u16::MAX as f64) * ((upper_bound - 1 - lower_bound) as f64)).round() as usize
        + lower_bound
}

#[cfg(feature = "codec")]
fn inner_witness_size_estimation(
    Inputs {
        key_value_pairs,
        n_overlays,
    }: Inputs,
) -> TestResult {
    // Fill nomt

    let mut t = Test::new_with_params(
        "witness_size_estimation",
        nomt::WitnessMode::read_write_with_estimation(),
        1,      // commit concurrency
        10_000, // hashtable buckets
        None,   // panic on sync
        true,   // cleanup dir
    );

    let mut present_items: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut deleted_items: Vec<Vec<u8>> = Vec::new();
    let mut overlays = VecDeque::new();

    let tot_key_value_pairs = key_value_pairs.len();
    for (reads, writes, modifications, re_insertions) in key_value_pairs {
        for (key, is_present) in reads {
            if present_items.is_empty() {
                break;
            }

            let key_index = rescale(key, 0, present_items.len());

            let mut key = present_items[key_index].0.clone();
            if !is_present {
                key.push(1);
            };

            let _ = t.read(key);
        }

        for (Key { inner: key }, Value { inner: value }) in writes {
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

        let witness_size_estimation = t.estimate_witness_size().unwrap();

        let (overlay, witness) = t.update();

        let mut path_proofs: Vec<_> = witness
            .path_proofs
            .into_iter()
            .map(|nomt_core::witness::WitnessedPath { inner, .. }| inner)
            .collect();
        path_proofs.sort_by(|p1, p2| p1.terminal.path().cmp(p2.terminal.path()));

        let multi_proof = nomt_core::proof::MultiProof::from_path_proofs(path_proofs);

        let mut tot_sibling_counter = 0;
        let mut real_unique_siblings = 0;
        let mut real_terminators = 0;
        let mut real_terminator_sequences = 0;

        for chunk in multi_proof.sibling_chunks.iter() {
            match &chunk {
                nomt::proof::SiblingChunk::Sibling(_) => {
                    tot_sibling_counter += 1;
                    real_unique_siblings += 1;
                }
                nomt::proof::SiblingChunk::Terminators(t) => {
                    real_terminators += *t as usize;
                    tot_sibling_counter += t;
                    real_terminator_sequences += 1;
                }
            }
        }

        let nomt_core::witness::EstimationResult {
            byte_length,
            testing_data:
                nomt_core::witness::TestingEstimationResult {
                    paths,
                    paths_encoding,
                    siblings_encoding,
                    unique_siblings,
                    tot_siblings,
                    shared_bits,
                    pair_bits,
                    terminators,
                    terminator_sequences,
                    terminals,
                },
        } = witness_size_estimation;

        let mut multi_proof_paths = multi_proof.paths.clone();
        multi_proof_paths.sort_by(|a, b| a.terminal.path().cmp(&b.terminal.path()));
        for (multi_proof_path, terminal) in multi_proof_paths.iter().zip(terminals.iter().by_ref())
        {
            let d = multi_proof_path.depth as usize;
            use bitvec::prelude::*;
            use nomt::proof::shared_bits;
            if d != 0 && d != 1 {
                assert_eq!(d, terminal.depth);
                let multi_proof_terminal_path = {
                    let mut bits = multi_proof_path.terminal.path().to_bitvec();
                    if bits.len() < d {
                        bits.extend(core::iter::repeat(false).take(d - bits.len()));
                    } else {
                        bits.truncate(d);
                    }
                    bits
                };

                let multi_proof_estimated_path = {
                    let mut bits = terminal.key.view_bits::<Msb0>().to_bitvec();
                    if bits.len() < d {
                        bits.extend(core::iter::repeat(false).take(d - bits.len()));
                    } else {
                        bits.truncate(d);
                    }
                    bits
                };

                assert_eq!(multi_proof_terminal_path, multi_proof_estimated_path);
            }
        }

        assert!(paths >= multi_proof.paths.len());
        assert!(unique_siblings >= real_unique_siblings);
        assert!(terminators <= real_terminators);

        let real_sibling_encoding = multi_proof.sibling_chunks.encode().len();
        assert!(siblings_encoding >= real_sibling_encoding);

        let real_paths_encoding = multi_proof.paths.encode().len();
        assert!(paths_encoding >= real_paths_encoding);

        let witness_size = multi_proof.encode().len();
        assert!(witness_size <= byte_length);

        let diff = byte_length - witness_size;
        let percentage = (diff * 100) as f64 / witness_size as f64;
        println!("percentage diff: {}", percentage);

        overlays.push_front(overlay);

        if overlays.len() > n_overlays as usize {
            let overlay = overlays.pop_back().unwrap();
            t.commit_overlay(overlay);
        }

        t.start_overlay_session(
            overlays.iter(),
            nomt::WitnessMode::read_write_with_estimation(),
        );
    }

    if present_items.is_empty() {
        return TestResult::discard();
    }

    TestResult::passed()
}

#[cfg(feature = "codec")]
#[test]
fn witness_size_estimation() {
    QuickCheck::new()
        .gen(quickcheck::Gen::new(50))
        .max_tests(10)
        .quickcheck(inner_witness_size_estimation as fn(_) -> TestResult)
}
