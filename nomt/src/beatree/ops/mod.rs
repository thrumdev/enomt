//! BTree Operations.

use anyhow::Result;
use bitvec::prelude::*;

use std::{cmp::Ordering, sync::Arc};

use super::{
    allocator::{PageNumber, StoreReader},
    branch::{node::get_key, BranchNode},
    index::Index,
    leaf::node::LeafNode,
    leaf_cache::LeafCache,
    Key,
};

pub(crate) mod bit_ops;
pub mod overflow;
mod reconstruction;
mod update;

pub use reconstruction::reconstruct;
pub use update::update;

/// Do a partial lookup of the key in the beatree.
///
/// This determines the leaf store page number which might store the associated value, or `None`
/// if the value is definitely non-existent.
pub fn partial_lookup(key: &Key, bbn_index: &Index) -> Option<PageNumber> {
    let branch = match bbn_index.lookup(key) {
        None => return None,
        Some((_, branch)) => branch,
    };

    search_branch(&branch, key).map(|(_, leaf_pn)| leaf_pn)
}

/// Find the associated value associated with the key in the given leaf node, if any.
///
/// If the value is an overflow, this function will load it with blocking I/O.
pub fn finish_lookup_blocking(
    key: Key,
    leaf: &LeafNode,
    leaf_store: &StoreReader,
) -> Option<Vec<u8>> {
    search_leaf(&leaf, &key).map(|(v, is_overflow)| {
        if is_overflow {
            overflow::read_blocking(v, leaf_store)
        } else {
            v.to_vec()
        }
    })
}

/// Find the associated value associated with the key in the given leaf node, if any.
///
/// If the value is an overflow, this function will create an asynchronous reader.
pub fn finish_lookup_async(
    key: &Key,
    leaf: &LeafNode,
    leaf_store: &StoreReader,
) -> Result<Option<Vec<u8>>, overflow::AsyncReader> {
    search_leaf(&leaf, &key)
        .map(|(v, is_overflow)| {
            if is_overflow {
                Err(overflow::AsyncReader::new(v, leaf_store.clone()))
            } else {
                Ok(v.to_vec())
            }
        })
        .transpose()
}

/// Lookup a key in the btree using blocking I/O.
pub fn lookup_blocking(
    key: Key,
    bbn_index: &Index,
    leaf_cache: &LeafCache,
    leaf_store: &StoreReader,
) -> Result<Option<Vec<u8>>> {
    let leaf_pn = match partial_lookup(&key, bbn_index) {
        None => return Ok(None),
        Some(pn) => pn,
    };

    let leaf = match leaf_cache.get(leaf_pn) {
        Some(leaf) => leaf,
        None => {
            let leaf = Arc::new(LeafNode {
                inner: leaf_store.query(leaf_pn),
            });
            leaf_cache.insert(leaf_pn, leaf.clone());
            leaf
        }
    };

    Ok(finish_lookup_blocking(key, &leaf, leaf_store))
}

/// Binary search a branch node for the child node containing the key. This returns the last child
/// node pointer whose separator is less than or equal to the given key.
pub fn search_branch(branch: &BranchNode, key: &Key) -> Option<(usize, PageNumber)> {
    let (found, pos) = branch_find_key_pos(branch, key, None);

    if found {
        return Some((pos, branch.node_pointer(pos).into()));
    } else if pos == 0 {
        return None;
    } else {
        // first key greater than the one we are looking for has been returned,
        // thus the correct child is the previous one
        return Some((pos - 1, branch.node_pointer(pos - 1).into()));
    }
}

pub fn search_leaf<'a>(leaf: &'a LeafNode, key: &Key) -> Option<(&'a [u8], bool)> {
    let (found, index) = leaf_find_key_pos(leaf, key, None);
    if !found {
        return None;
    }
    Some(leaf.value(index))
}

// Binary search for a key within a branch node.
// Accept a field to override the starting point of the binary search.
// It returns true and the index of the specified key,
// or false and the index containing the first key greater than the specified one.
pub fn branch_find_key_pos(branch: &BranchNode, key: &Key, low: Option<usize>) -> (bool, usize) {
    let prefix = branch.prefix();
    let prefix_len = prefix.len();
    let n = branch.n() as usize;
    let prefix_compressed = branch.prefix_compressed() as usize;

    let key_shorter_than_prefix = (key.len() * 8) < prefix_len;
    let len = std::cmp::min(key.len() * 8, prefix_len);

    // The key is infinetly padded with zeros so if the key is equal to a portion
    // of the prefix it means that all other bits are zero ans thus smaller than
    // any other key in the leaf which shares the same bits or if not compressed is highher

    match key.view_bits::<Msb0>()[..len].cmp(&prefix[..len]) {
        Ordering::Less => return (false, 0),
        Ordering::Equal if key_shorter_than_prefix => return (false, 0),
        Ordering::Greater if n == prefix_compressed => return (false, n),
        Ordering::Equal | Ordering::Greater => {}
    }

    let start = low.unwrap_or(0);
    let end = branch.n() as usize;

    binary_search(start, end, |index| key.cmp(&get_key(branch, index)))
}

pub fn leaf_find_key_pos(leaf: &LeafNode, key: &Key, low: Option<usize>) -> (bool, usize) {
    let prefix_len = leaf.prefix_len();
    let prefix = leaf.prefix();
    let n = leaf.n() as usize;
    let prefix_compressed = leaf.prefix_compressed() as usize;
    let low = low.unwrap_or(0);

    let key_shorter_than_prefix = key.len() < prefix_len;
    let len = std::cmp::min(key.len(), prefix_len);

    // The key is infinetly padded with zeros so if the key is equal to a portion
    // of the prefix it means that all other bits are zero ans thus smaller than
    // any other key in the leaf which shares the same bits or if not compressed is highher

    // Key will be the entire key or without the prefix if we expect to compare
    // it with compressed or non compressed items.
    let (start, end, key) = match &key[..len].cmp(&prefix[..len]) {
        std::cmp::Ordering::Less => return (false, 0),
        std::cmp::Ordering::Equal if key_shorter_than_prefix => return (false, 0),
        std::cmp::Ordering::Greater if n == prefix_compressed => return (false, n),
        std::cmp::Ordering::Greater => {
            // Even if a key is shorter than the prefix, it could still be larger
            // than the compressed items in the prefix. Therefore, it must be compared
            // with non-compressed ones.
            let from = std::cmp::max(prefix_compressed, low);
            (from, n, &key[..])
        }
        std::cmp::Ordering::Equal => {
            let from = std::cmp::min(prefix_compressed, low);
            (from, prefix_compressed, &key[prefix_len..])
        }
    };

    let cell_pointers = leaf.cell_pointers();
    binary_search(start, end, |index| {
        key.cmp(leaf.raw_key(cell_pointers, index))
    })
}

// If there are available keys in the node, then it returns the index
// of the specified key with the boolean set to true or the index containing
// the first key bigger than the one specified and the boolean set to false.
pub fn binary_search(
    mut start: usize,
    mut end: usize,
    cmp: impl Fn(usize) -> Ordering,
) -> (bool, usize) {
    while start < end {
        let mid = start + (end - start) / 2;

        match cmp(mid) {
            Ordering::Equal => {
                return (true, mid);
            }
            Ordering::Less => end = mid,
            Ordering::Greater => start = mid + 1,
        }
    }

    (false, end)
}

#[cfg(feature = "benchmarks")]
pub mod benches {
    use crate::{
        beatree::{
            benches::get_keys,
            branch::{node::BranchNodeBuilder, BranchNode},
            ops::bit_ops::separator_len,
            Key,
        },
        io::{PagePool, PAGE_SIZE},
    };
    use criterion::{BenchmarkId, Criterion};
    use rand::Rng;

    pub fn search_branch_benchmark(c: &mut Criterion) {
        let mut group = c.benchmark_group("search_branch");
        let mut rand = rand::thread_rng();
        let page_pool = PagePool::new();

        for prefix_len_bytes in [1, 4, 8, 12, 16] {
            // fill the branch node with as many separators as possible
            //
            // body_size = (prefix_len_bits + (separator_len_bits * n) + 7)/8 + 4 * n
            // n = (8 * body_size - prefix_len_bits) / (separator_len_bits + 8*4)
            let body_size_target = PAGE_SIZE - 8;
            let prefix_len_bits = prefix_len_bytes * 8;
            let separator_len_bits = (32 - prefix_len_bytes) * 8;
            let n = (8 * body_size_target - prefix_len_bits) / (separator_len_bits + 8 * 4);

            let mut separators: Vec<(usize, Key)> = get_keys(prefix_len_bytes, n)
                .into_iter()
                .map(|s| (s.len(), s))
                .collect();
            separators.sort_by(|a, b| a.1.cmp(&b.1));

            let branch_node = BranchNode::new_in(&page_pool);
            let mut branch_node_builder =
                BranchNodeBuilder::new(branch_node, n, prefix_len_bits, 256);

            for (index, (separator_len, separator)) in separators.iter().enumerate() {
                branch_node_builder.push(separator.clone(), *separator_len, index as u32);
            }

            let branch = branch_node_builder.finish();

            group.bench_function(
                BenchmarkId::new("prefix_len_bytes", prefix_len_bytes),
                |b| {
                    b.iter_batched(
                        || {
                            let index = rand.gen_range(0..separators.len());
                            separators[index].1.clone()
                        },
                        |separator| super::search_branch(&branch, separator),
                        criterion::BatchSize::SmallInput,
                    )
                },
            );
        }

        group.finish();
    }
}
