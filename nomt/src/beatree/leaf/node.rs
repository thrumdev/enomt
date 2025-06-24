/// Here is the layout of a leaf node:
///
/// ```rust,ignore
/// n: u16
/// prefix_compressed: u16
/// prefix_len: u16
/// prefix: [u8; prefix_len]
/// cell_pointers: [(cell_offset ++ key_len); n]
/// padding: [u8] // empty space between cell_pointers and cells
/// cells: [key ++ value; n]
/// key: [u8]
/// value: [u8]
/// overflow value: (u64, u256, [NodePointer]) | semantically, (value_size, value_hash, [NodePointer]).
/// ```
///
/// | n | prefix | [(cell_offset ++ key_len); n] | ----  | [key ++ value; n] |
///
// TODO: update comment with max key size
/// Where key a byte array smaller than 2^N bits, and cell_offset is the byte offset in the node
/// to the beginning of the the cell.
///
/// Cell pointers are saved in order of the key, and consequently, so are the cells.
/// The key starts at the relative cell_offset within the node, and its length is key_len.
/// The length of the value is determined by the difference between the end of the key
/// and the beginning of the next cell.
///
/// A cell_pointer is made by 12 bits of cell_offset and 9 of key_length and they are arranged in 3
/// bytes in the following manner:
///
/// cell_pointer[0] = first 8 bits of the key len
/// cell_pointer[1..3] = little endian bytes of the cell_offset
/// cell_pointer[2] & 0x10 >> 4 = overflow bit
/// cell_pointer[2] & 0xe0 >> 5 = most significant key length bits
///
/// When a cell is an overflow cell, the overflow bit will be set to `1`. Only the low
/// 12 bits should count when considering the offset.
///
/// Cells are left-aligned and thus the last value is always attached to the end.
///
/// The offset of the first cell also serves to detect potential overlap
/// between the growth of cell_pointers and cells.
use std::ops::Range;

use crate::{
    beatree::Key,
    io::{page_pool::FatPage, PagePool, PAGE_SIZE},
};

/// The size of the leaf node body: everything excluding the mandatory header.
pub const LEAF_NODE_BODY_SIZE: usize = PAGE_SIZE - 6;

/// The maximum value size before overflow pages are used.
pub const MAX_LEAF_VALUE_SIZE: usize = (LEAF_NODE_BODY_SIZE / 3) - 32;

/// The maximum number of node pointers which may appear directly in an overflow cell.
///
/// Note that this gives an overflow value cell maximum size of 100 bytes.
pub const MAX_OVERFLOW_CELL_NODE_POINTERS: usize = 15;

/// The maximum value size supported by overflow pages, 512MiB.
pub const MAX_OVERFLOW_VALUE_SIZE: usize = 1 << 29;

/// We use the three high bit to encode the msb of the key len.
const MSBS_KEY_LEN_BIT: u8 = 0b11100000;

/// We use the fifth bit to encode whether a cell is an overflow cell.
const OVERFLOW_BIT: u8 = 0b00010000;

/// The maximum size of the key in byte supported by the leaf encoding.
pub const MAX_KEY_LEN: u16 = 1 << 10;

/// A reference to the compressed key stored in the leaf, excluding the shared prefix.
type RawKey<'a> = &'a [u8];

pub struct LeafNode {
    pub inner: FatPage,
}

impl LeafNode {
    pub fn n(&self) -> usize {
        u16::from_le_bytes(self.inner[0..2].try_into().unwrap()) as usize
    }

    pub fn set_n(&mut self, n: u16) {
        self.inner[0..2].copy_from_slice(&n.to_le_bytes());
    }

    pub fn prefix_compressed(&self) -> usize {
        u16::from_le_bytes(self.inner[2..4].try_into().unwrap()) as usize
    }

    pub fn set_prefix_compressed(&mut self, prefix_len: u16) {
        self.inner[2..4].copy_from_slice(&prefix_len.to_le_bytes());
    }

    pub fn prefix_len(&self) -> usize {
        u16::from_le_bytes(self.inner[4..6].try_into().unwrap()) as usize
    }

    pub fn set_prefix_len(&mut self, prefix_len: u16) {
        self.inner[4..6].copy_from_slice(&prefix_len.to_le_bytes());
    }

    pub fn prefix(&self) -> &[u8] {
        &self.inner[6..6 + self.prefix_len()]
    }

    pub fn set_prefix(&mut self, prefix: &[u8]) {
        self.inner[6..6 + prefix.len()].copy_from_slice(&prefix);
    }

    pub fn raw_key<'a>(&'a self, i: usize) -> RawKey<'a> {
        let cell_pointer = &self.cell_pointers()[i];
        let key_len = key_len(cell_pointer);
        let offset = offset(cell_pointer);
        &self.inner[offset..offset + key_len]
    }

    pub fn key(&self, i: usize) -> Key {
        let raw_key = self.raw_key(i);

        if i >= self.prefix_compressed() || self.prefix_len() == 0 {
            return raw_key.to_vec();
        }

        let prefix = self.prefix();
        let prefix_len = self.prefix_len();
        let mut key = vec![0; prefix_len + raw_key.len()];
        key[..prefix_len].copy_from_slice(prefix);
        key[prefix_len..].copy_from_slice(raw_key);
        key
    }

    pub fn key_len(&self, i: usize) -> usize {
        let cell_pointer = &self.cell_pointers()[i];
        let key_len = key_len(cell_pointer);
        if i < self.prefix_compressed() {
            self.prefix_len() + key_len
        } else {
            key_len
        }
    }

    pub fn value(&self, i: usize) -> (&[u8], bool) {
        let (range, overflow) = self.value_range(self.cell_pointers(), i);
        (&self.inner[range], overflow)
    }

    pub fn value_len(&self, i: usize) -> usize {
        self.value_range(self.cell_pointers(), i).0.len()
    }

    // returns the range at which the value of a cell is stored
    fn value_range(&self, cell_pointers: &[[u8; 3]], index: usize) -> (Range<usize>, bool) {
        let key_len = key_len(&cell_pointers[index]);
        let start = offset(&cell_pointers[index]) + key_len;

        let end = if index == cell_pointers.len() - 1 {
            PAGE_SIZE
        } else {
            offset(&cell_pointers[index + 1])
        };

        (start..end, overflow(&cell_pointers[index]))
    }

    pub fn values_len(&self, from: usize, to: usize) -> usize {
        let compressed_keys = self.compressed_keys_len(from, to);

        let cell_pointers = self.cell_pointers();
        let offset_start = offset(&cell_pointers[from]);

        let offset_end = if to == cell_pointers.len() {
            PAGE_SIZE
        } else {
            offset(&cell_pointers[to])
        };

        offset_end - offset_start - compressed_keys
    }

    pub fn compressed_keys_len(&self, from: usize, to: usize) -> usize {
        self.cell_pointers()[from..to]
            .iter()
            .map(|cell_pointer| key_len(cell_pointer))
            .sum()
    }

    pub fn uncompressed_keys_len(&self, from: usize, to: usize) -> usize {
        let end_compressed = std::cmp::max(std::cmp::min(self.prefix_compressed(), to), from);
        self.compressed_keys_len(from, to) + (end_compressed - from) * self.prefix_len()
    }

    pub fn cell_pointers(&self) -> &[[u8; 3]] {
        let cell_pointers_start = 2 + 2 + 2 + self.prefix_len();
        let cell_pointers_end = self.n() * 3;
        assert!(cell_pointers_start + cell_pointers_end < LEAF_NODE_BODY_SIZE);

        // SAFETY: This creates a slice of length 34 * N starting at index 2. This is ensured
        // to be within the bounds by the assertion above.
        unsafe {
            std::slice::from_raw_parts(
                self.inner[cell_pointers_start..cell_pointers_start + 3].as_ptr() as *const [u8; 3],
                self.n(),
            )
        }
    }

    fn cell_pointers_mut(&mut self) -> &mut [[u8; 3]] {
        let cell_pointers_start = 2 + 2 + 2 + self.prefix_len();
        let cell_pointers_end = self.n() * 3;
        assert!(cell_pointers_end < LEAF_NODE_BODY_SIZE);

        // SAFETY: This creates a slice of length 34 * N starting at index 2. This is ensured
        // to be within the bounds by the assertion above.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.inner[cell_pointers_start..cell_pointers_start + 3].as_mut_ptr()
                    as *mut [u8; 3],
                self.n(),
            )
        }
    }
}

pub struct LeafBuilder {
    leaf: LeafNode,
    index: usize,
    prefix_compressed: usize,
    prefix_len: usize,
    remaining_value_size: usize,
}

impl LeafBuilder {
    /// Construct a leaf builder.
    ///
    /// NOTE: keys_len must be reflect the compressed version of the keys.
    pub fn new(
        page_pool: &PagePool,
        n: usize,
        prefix_len: usize,
        prefix_compressed: usize,
        keys_len: usize,
        values_len: usize,
    ) -> Self {
        let mut leaf = LeafNode {
            inner: page_pool.alloc_fat_page(),
        };

        leaf.set_n(n as u16);
        leaf.set_prefix_len(prefix_len as u16);
        leaf.set_prefix_compressed(prefix_compressed as u16);
        LeafBuilder {
            leaf,
            index: 0,
            prefix_compressed,
            prefix_len,
            remaining_value_size: keys_len + values_len,
        }
    }

    pub fn push(&mut self, key: &Key, value: &[u8], overflow: bool) {
        assert!(self.index < self.leaf.n());

        if self.index == 0 {
            self.leaf.set_prefix(&key[..self.prefix_len]);
        }

        let key = if self.index < self.prefix_compressed {
            &key[self.prefix_len..]
        } else {
            &key[..]
        };

        let offset = PAGE_SIZE - self.remaining_value_size;
        let cell_pointer = &mut self.leaf.cell_pointers_mut()[self.index];

        encode_cell_pointer(cell_pointer, key.len(), offset, overflow);

        self.leaf.inner[offset..offset + key.len()].copy_from_slice(key);
        self.leaf.inner[offset + key.len()..offset + key.len() + value.len()]
            .copy_from_slice(value);

        self.index += 1;
        self.remaining_value_size -= value.len() + key.len();
    }

    pub fn push_chunk(&mut self, base: &LeafNode, from: usize, to: usize) {
        let n_items = to - from;
        assert!(self.index + n_items <= self.prefix_compressed);

        if self.index == 0 {
            // set the prefix if this is the first inserted item
            let key = base.key(from);
            self.leaf.set_prefix(&key);
        }

        let byte_prefix_len_difference = base.prefix_len() as isize - self.prefix_len as isize;

        let start_offset = PAGE_SIZE - self.remaining_value_size;

        // 1. copy and update cell pointers
        for base_index in from..to {
            let base_key_len = base.compressed_keys_len(base_index, base_index + 1);
            let (value_range, overflow) = base.value_range(base.cell_pointers(), base_index);
            let value_len = value_range.len();

            let key_len =
                (base_key_len as isize).saturating_add(byte_prefix_len_difference) as usize;

            let offset = PAGE_SIZE - self.remaining_value_size;
            let cell_index_offset = base_index - from;
            encode_cell_pointer(
                &mut self.leaf.cell_pointers_mut()[self.index + cell_index_offset],
                key_len,
                offset,
                overflow,
            );

            // TODO: Here we have two solutions: one that is cleaner but requires an allocation
            // (within the `key` method), and one that has more computation in both conditional branches.
            // This should be benchmarked to decide which one to use.

            // SOL1
            //let prefix_diff = byte_prefix_len_difference.abs() as usize;
            //if byte_prefix_len_difference > 0 {
            //// copy what is missing from the prefix
            //let mut range = offset..offset + prefix_diff;
            //self.leaf.inner[range.clone()]
            //.copy_from_slice(&base_prefix[base_prefix_len - prefix_diff..]);
            //
            //// copy the rest of the key
            //range.start += prefix_diff;
            //range.end += base_key_len;
            //self.leaf.inner[range.clone()].copy_from_slice(base.raw_key(base_index));
            //
            //// copy the value
            //range.start += base_key_len;
            //range.end += value_len;
            //self.leaf.inner[range].copy_from_slice(base.value(base_index).0);
            //} else if byte_prefix_len_difference < 0 {
            //// copy the rest of the key
            //let mut range = offset..offset + key_len;
            //self.leaf.inner[range.clone()]
            //.copy_from_slice(&base.raw_key(base_index)[base_key_len - key_len..]);
            //
            //// copy the value
            //range.start += key_len;
            //range.end += value_len;
            //self.leaf.inner[range].copy_from_slice(base.value(base_index).0);
            //}

            // SOL2
            if byte_prefix_len_difference != 0 {
                // slow path, each key needs to be copied one by one
                let new_key = &base.key(base_index)[self.prefix_len..];
                assert_eq!(new_key.len(), key_len);
                self.leaf.inner[offset..offset + key_len].copy_from_slice(new_key);
                self.leaf.inner[offset + key_len..offset + key_len + value_len]
                    .copy_from_slice(base.value(base_index).0);
            }

            self.remaining_value_size -= key_len + value_len;
        }

        let end_offset = PAGE_SIZE - self.remaining_value_size;

        if byte_prefix_len_difference == 0 {
            // fast path, copy all cells at once
            let base_start_offset = offset(&base.cell_pointers()[from]);
            let base_end_offset = if to == base.n() {
                PAGE_SIZE
            } else {
                offset(&base.cell_pointers()[to])
            };

            self.leaf.inner[start_offset..end_offset]
                .copy_from_slice(&base.inner[base_start_offset..base_end_offset]);
        }

        self.index += n_items;
    }

    pub fn finish(self) -> LeafNode {
        assert!(self.remaining_value_size == 0);
        self.leaf
    }
}

// Evaluate the body size given the prefix len, the number of items, the total size of all values
// and the compressed size of all keys
pub fn body_size(prefix_len: usize, n: usize, key_size_sum: usize, value_size_sum: usize) -> usize {
    prefix_len + n * 3 + key_size_sum + value_size_sum
}

/// Given inputs describing a set of keys for a leaf, output the compressed size if compressed
/// with the given prefix length.
///
/// `prefix_compressed_items` must be greater than zero.
/// `pre_compression_size_sum` is the sum of all key lengths, not including the first.
pub fn compressed_key_range_size(
    first_key_length: usize,
    prefix_compressed_items: usize,
    pre_compression_size_sum: usize,
    prefix_len: usize,
) -> usize {
    // first length can be less than the shared prefix due to trailing zero compression.
    // then add the total size.
    // then subtract the size difference due to compression of the remaining items.
    first_key_length.saturating_sub(prefix_len) + pre_compression_size_sum
        - (prefix_compressed_items - 1) * prefix_len
}

// get the key length from the cell_pointer.
fn key_len(cell_pointer: &[u8; 3]) -> usize {
    u16::from_le_bytes([cell_pointer[0], (cell_pointer[2] & MSBS_KEY_LEN_BIT) >> 5]) as usize
}

// get the cell offset and whether the cell is an overflow cell.
fn offset(cell_pointer: &[u8; 3]) -> usize {
    u16::from_le_bytes([
        cell_pointer[1],
        cell_pointer[2] & !MSBS_KEY_LEN_BIT & !OVERFLOW_BIT,
    ]) as usize
}

fn overflow(cell_pointer: &[u8; 3]) -> bool {
    cell_pointer[2] & OVERFLOW_BIT == OVERFLOW_BIT
}

// panics if offset is bigger than 2^15 - 1.
fn encode_cell_pointer(cell_pointer: &mut [u8; 3], key_len: usize, offset: usize, overflow: bool) {
    let key_len = u16::try_from(key_len).unwrap();
    assert!(key_len <= MAX_KEY_LEN);
    let key_len = key_len.to_le_bytes();

    let offset = u16::try_from(offset).unwrap();

    cell_pointer[0] = key_len[0];
    cell_pointer[1..3].copy_from_slice(&offset.to_le_bytes());
    if overflow {
        cell_pointer[2] |= OVERFLOW_BIT;
    }
    cell_pointer[2] |= (key_len[1] & (MSBS_KEY_LEN_BIT >> 5)) << 5;
}

#[cfg(test)]
mod tests {
    use crate::io::{PagePool, PAGE_SIZE};

    lazy_static::lazy_static! {
        static ref PAGE_POOL: PagePool = PagePool::new();
    }

    #[test]
    fn encode_cell_pointer() {
        // 10 bits are avaiables for the key
        for key_bit_index in 0..=10 {
            for offest_bit_index in 0..12 {
                for overflow in [false, true] {
                    let key_len = 1 << key_bit_index;
                    let offset = 1 << offest_bit_index;

                    let mut cell_pointer = [0; 3];
                    super::encode_cell_pointer(&mut cell_pointer, key_len, offset, overflow);

                    assert_eq!(key_len, super::key_len(&cell_pointer));
                    assert_eq!(offset, super::offset(&cell_pointer));
                    assert_eq!(overflow, super::overflow(&cell_pointer));
                }
            }
        }
    }

    #[test]
    fn leaf_encoding() {
        let mut leaf = super::LeafNode {
            inner: PAGE_POOL.alloc_fat_page(),
        };

        let n = 2;
        let non_prefix_compressed = 2;
        let prefix_len = 10;
        leaf.set_n(n);
        leaf.set_prefix_len(prefix_len as u16);
        leaf.set_prefix_compressed(n - non_prefix_compressed);

        let prefix = vec![7; prefix_len];
        leaf.set_prefix(&prefix);

        let range = 0..n as usize - 2;
        let mut key_value_pairs = range
            .into_iter()
            .map(|i| (i, vec![i as u8; 50 + i], vec![i as u8; 100 + i], i % 2 == 0))
            .collect::<Vec<_>>();

        key_value_pairs.push((0, vec![251u8; 96], vec![251u8; 4], true));
        key_value_pairs.push((1, vec![255u8; 72], vec![5u8; 4], false));

        let mut offset = PAGE_SIZE
            - key_value_pairs
                .iter()
                .by_ref()
                .map(|(_, k, v, _)| k.len() + v.len())
                .sum::<usize>();

        for (i, key, val, overflow) in key_value_pairs.iter().by_ref() {
            super::encode_cell_pointer(
                &mut leaf.cell_pointers_mut()[*i],
                key.len(),
                offset,
                *overflow,
            );

            leaf.inner[offset..offset + key.len()].copy_from_slice(&key[..]);
            leaf.inner[offset + key.len()..offset + key.len() + val.len()]
                .copy_from_slice(&val[..]);

            offset += key.len() + val.len();
        }

        assert_eq!(leaf.n(), n as usize);
        assert_eq!(leaf.prefix(), &prefix[..]);
        assert_eq!(leaf.prefix_len(), prefix.len());
        assert_eq!(
            leaf.prefix_compressed(),
            (n - non_prefix_compressed) as usize
        );

        for (i, key, val, overflow) in key_value_pairs {
            assert_eq!(leaf.raw_key(i), &key);

            let expected_key = if i < (n - non_prefix_compressed) as usize {
                [prefix.clone(), key].concat()
            } else {
                key
            };

            assert_eq!(leaf.key(i), expected_key);

            assert_eq!(leaf.value(i), (&val[..], overflow));
        }
    }

    #[test]
    fn push_chunk() {
        // 10 bits are avaiables for the key
        for key_bit_index in 0..=10 {
            for offest_bit_index in 0..12 {
                for overflow in [false, true] {
                    let key_len = 1 << key_bit_index;
                    let offset = 1 << offest_bit_index;

                    let mut cell_pointer = [0; 3];
                    super::encode_cell_pointer(&mut cell_pointer, key_len, offset, overflow);

                    assert_eq!(key_len, super::key_len(&cell_pointer));
                    assert_eq!(offset, super::offset(&cell_pointer));
                    assert_eq!(overflow, super::overflow(&cell_pointer));
                }
            }
        }
    }
}

#[cfg(feature = "benchmarks")]
pub mod benches {

    use crate::{
        beatree::{
            benches::get_keys,
            leaf::node::{LeafBuilder, LEAF_NODE_BODY_SIZE},
        },
        io::PagePool,
    };
    use criterion::{BatchSize, BenchmarkId, Criterion};
    use rand::Rng;

    pub fn leaf_search_benchmark(c: &mut Criterion) {
        let mut group = c.benchmark_group("search_leaf");
        let mut rand = rand::thread_rng();

        let page_pool = PagePool::new();

        // we fill the leaf with as much as possible 4B values
        // leaf_body_size = b = n * 34 + value_size_sum
        //                    = n * 34 + (n * 4)
        //                  n = b / 38

        let n = LEAF_NODE_BODY_SIZE / 38;
        let mut leaf_builder = LeafBuilder::new(&page_pool, n, n * 4);

        let mut keys = get_keys(0, n);
        keys.sort();
        for (index, k) in keys.iter().enumerate() {
            leaf_builder.push_cell(k.clone(), &(index as u32).to_le_bytes()[..], false);
        }
        let leaf = leaf_builder.finish();

        group.bench_function(BenchmarkId::new("full_leaf", format!("{}-keys", n)), |b| {
            b.iter_batched(
                || {
                    let index = rand.gen_range(0..keys.len());
                    keys[index].clone()
                },
                |key| leaf.get(&key),
                BatchSize::SmallInput,
            )
        });

        group.finish();
    }

    pub fn leaf_builder_benchmark(c: &mut Criterion) {
        let mut group = c.benchmark_group("leaf_builder");

        // benchmark the leaf builder creating an almost full leaf node
        // given different value sizes

        let page_pool = PagePool::new();

        for value_size in [4, 8, 16, 32, 64, 128] {
            // leaf_body_size = b = n * 34 + value_size_sum
            //                  b = n * 34 + (n * value_size)
            //                  n = b / (34 + value_size)

            let n = (LEAF_NODE_BODY_SIZE as f64 / (34 + value_size) as f64).floor() as usize;
            let mut keys = get_keys(0, n);
            keys.sort();

            group.bench_function(BenchmarkId::new("value_len_bytes", value_size), |b| {
                b.iter_batched(
                    || {
                        (
                            keys.clone(),
                            std::iter::repeat(12).take(value_size).collect::<Vec<u8>>(),
                        )
                    },
                    |(keys, value)| {
                        let mut leaf_builder = LeafBuilder::new(&page_pool, n, n * value_size);
                        for k in keys.into_iter() {
                            leaf_builder.push_cell(k, &value[..], false);
                        }
                        leaf_builder.finish();
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }

        group.finish();
    }
}
