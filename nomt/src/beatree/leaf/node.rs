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
/// cell_pointer[2] & 0x40 >> 14 = overflow bit
/// cell_pointer[2] & 0x80 >> = msb key len
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
pub const LEAF_NODE_BODY_SIZE: usize = PAGE_SIZE - 2;

/// The maximum value size before overflow pages are used.
pub const MAX_LEAF_VALUE_SIZE: usize = (LEAF_NODE_BODY_SIZE / 3) - 32;

/// The maximum number of node pointers which may appear directly in an overflow cell.
///
/// Note that this gives an overflow value cell maximum size of 100 bytes.
pub const MAX_OVERFLOW_CELL_NODE_POINTERS: usize = 15;

/// The maximum value size supported by overflow pages, 512MiB.
pub const MAX_OVERFLOW_VALUE_SIZE: usize = 1 << 29;

/// We use the high bit to encode the msb of the key len.
const MSB_KEY_LEN_BIT: u8 = 1 << 7;

/// We use the second high bit to encode whether a cell is an overflow cell.
const OVERFLOW_BIT: u8 = 1 << 6;

/// TODO
const MAX_CELL_POINTER_OFFSET: u16 = 1 << 12;
/// TODO
const MAX_KEY_LEN: u16 = 1 << 9;

pub struct KeyRef<'a> {
    prefix: &'a [u8],
    remaining_key: &'a [u8],
}

impl<'a> KeyRef<'a> {
    pub fn into_key(self) -> Key {
        let mut key = Vec::with_capacity(self.prefix.len() + self.remaining_key.len());
        key[..self.prefix.len()].copy_from_slice(self.prefix);
        key[self.prefix.len()..].copy_from_slice(self.remaining_key);
        key
    }
}

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

    pub fn key_ref<'a>(&'a self, i: usize) -> KeyRef<'a> {
        let cell_pointer = &self.cell_pointers()[i];
        let key_len = key_len(cell_pointer);
        let (cell_offset, _) = cell_offset(cell_pointer);

        KeyRef {
            prefix: self.prefix(),
            remaining_key: &self.inner[cell_offset..cell_offset + key_len],
        }
    }

    pub fn key(&self, i: usize) -> Key {
        self.key_ref(i).into_key()
    }

    pub fn value(&self, i: usize) -> (&[u8], bool) {
        let (range, overflow) = self.value_range(self.cell_pointers(), i);
        (&self.inner[range], overflow)
    }

    pub fn get(&self, key: &Key) -> Option<(&[u8], bool)> {
        let prefix = self.prefix();

        match key[..prefix.len()].cmp(prefix) {
            std::cmp::Ordering::Less => return None,
            std::cmp::Ordering::Greater => return None,
            std::cmp::Ordering::Equal => (),
        }

        let cell_pointers = self.cell_pointers();

        cell_pointers
            .binary_search_by(|cell_pointer| {
                let (cell_offset, _) = cell_offset(cell_pointer);
                let key_len = key_len(cell_pointer);
                let remaining_key = &self.inner[cell_offset..cell_offset + key_len];
                remaining_key.cmp(key)
            })
            .ok()
            .map(|index| self.value_range(cell_pointers, index))
            .map(|(range, overflow)| (&self.inner[range], overflow))
    }

    pub fn values_size(&self, from: usize, to: usize) -> usize {
        let cell_pointers = self.cell_pointers();
        let value_range_start = self.value_range(cell_pointers, from).0.start;
        let value_range_end = self.value_range(cell_pointers, to - 1).0.end;
        value_range_end - value_range_start
    }

    // returns the range at which the value of a cell is stored
    fn value_range(&self, cell_pointers: &[[u8; 3]], index: usize) -> (Range<usize>, bool) {
        let cell_pointer = &cell_pointers[index];
        let key_len = key_len(cell_pointer);
        let (offset, overflow) = cell_offset(cell_pointer);
        let start = offset + key_len;

        let end = if index == cell_pointers.len() - 1 {
            PAGE_SIZE
        } else {
            cell_offset(&cell_pointers[index + 1]).0
        };

        (start..end, overflow)
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
    remaining_value_size: usize,
}

impl LeafBuilder {
    // TODO: Update builder to support new encoding
    pub fn new(page_pool: &PagePool, n: usize, total_value_size: usize) -> Self {
        let mut leaf = LeafNode {
            inner: page_pool.alloc_fat_page(),
        };
        leaf.set_n(n as u16);
        LeafBuilder {
            leaf,
            index: 0,
            remaining_value_size: total_value_size,
        }
    }

    pub fn push_cell(&mut self, key: Key, value: &[u8], overflow: bool) {
        assert!(self.index < self.leaf.n());

        let offset = PAGE_SIZE - self.remaining_value_size;
        let cell_pointer = &mut self.leaf.cell_pointers_mut()[self.index];

        todo!();
        //encode_cell_pointer(
        //&mut cell_pointer[..],
        //key_len.try_into().unwrap(),
        //offset,
        //overflow,
        //);
        self.leaf.inner[offset..][..value.len()].copy_from_slice(value);

        self.index += 1;
        self.remaining_value_size -= value.len();
    }

    pub fn push_chunk(&mut self, base_node: &LeafNode, from: usize, to: usize) {
        assert!(self.index < self.leaf.n());

        // copy cells, update offsets
        let n_items = to - from;
        let base_node_cell_pointers = base_node.cell_pointers();
        self.leaf.cell_pointers_mut()[self.index..self.index + n_items]
            .copy_from_slice(&base_node_cell_pointers[from..to]);

        let offset = PAGE_SIZE - self.remaining_value_size;

        let value_range_start = base_node.value_range(base_node_cell_pointers, from).0.start;
        let value_range_end = base_node.value_range(base_node_cell_pointers, to - 1).0.end;

        // if difference is positive it needs to be added otherwise subtracted
        let difference = offset as isize - value_range_start as isize;

        if difference != 0 {
            let positive_difference = difference.is_positive();
            let difference = u16::try_from(difference.abs()).unwrap();

            for cell in &mut self.leaf.cell_pointers_mut()[self.index..self.index + n_items] {
                let mut buf = [0; 2];
                buf.copy_from_slice(&cell[32..34]);
                let mut cell_pointer_offset = u16::from_le_bytes(buf);

                if positive_difference {
                    cell_pointer_offset += difference;
                } else {
                    cell_pointer_offset -= difference;
                }

                cell[32..34].copy_from_slice(&cell_pointer_offset.to_le_bytes());
            }
        }

        // copy values
        let values = &base_node.inner[value_range_start..value_range_end];
        self.leaf.inner[offset..][..values.len()].copy_from_slice(values);

        self.index += n_items;
        self.remaining_value_size -= values.len();
    }

    pub fn finish(self) -> LeafNode {
        assert!(self.remaining_value_size == 0);
        self.leaf
    }
}

pub fn body_size(n: usize, value_size_sum: usize) -> usize {
    n * 34 + value_size_sum
}

// get the key length from the cell_pointer.
fn key_len(cell_pointer: &[u8; 3]) -> usize {
    u16::from_le_bytes([cell_pointer[0], cell_pointer[2] & MSB_KEY_LEN_BIT >> 15]) as usize
}

// get the cell offset and whether the cell is an overflow cell.
fn cell_offset(cell_pointer: &[u8; 3]) -> (usize, bool) {
    (
        u16::from_le_bytes([
            cell_pointer[1],
            cell_pointer[2] & !MSB_KEY_LEN_BIT & !OVERFLOW_BIT,
        ]) as usize,
        cell_pointer[2] & OVERFLOW_BIT == OVERFLOW_BIT,
    )
}

// panics if offset is bigger than 2^15 - 1.
fn encode_cell_pointer(cell_pointer: &mut [u8; 3], key_len: usize, offset: usize, overflow: bool) {
    let key_len = u16::try_from(key_len).unwrap();
    assert!(key_len < MAX_KEY_LEN);
    let key_len = key_len.to_le_bytes();

    let offset = u16::try_from(offset).unwrap();
    assert!(offset < MAX_CELL_POINTER_OFFSET);

    cell_pointer[0] = key_len[0];
    cell_pointer[1..3].copy_from_slice(&offset.to_le_bytes());
    if overflow {
        cell_pointer[3] |= OVERFLOW_BIT;
    }
    if key_len[1] == 1 {
        cell_pointer[3] |= MSB_KEY_LEN_BIT;
    }
}

// look for key in the node. the return value has the same semantics as std binary_search*.
fn search(cell_pointers: &[[u8; 3]], key: &Key) -> Result<usize, usize> {
    // TODO: Update to support prefix compression
    cell_pointers.binary_search_by(|cell| cell[0..32].cmp(key))
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
