//! This module contains all the relevant methods to work with PageIds.
//!
//! A PageId is an unique identifier for a Page in a tree of pages with branching factor 2^6 and
//! a maximum depth of [`MAX_PAGE_DEPTH`], with the root page counted as depth 0.
//!
//! Each PageId consists of a list of numbers between 0 and 2^6 - 1, which encodes a path through
//! the tree. The list may have between 0 and [`MAX_PAGE_DEPTH`] (inclusive) items.

use crate::{
    page::DEPTH,
    trie::{KeyPath, MAX_KEY_PATH_LEN},
};
use bitvec::prelude::*;
use ruint::Uint;

pub const MAX_PAGE_DEPTH: usize = (MAX_KEY_PATH_LEN * 8) / 6;

/// A unique ID for a page.
///
/// # Ordering
///
/// Page IDs are ordered "depth-first" such that:
///  - An ID is always less than its child IDs.
///  - An ID's child IDs are ordered ascending by child index.
///  - An ID's child IDs are always less than any sibling IDs to the right of the ID.
///
/// This property lets us refer to sub-trees cleanly with simple ordering statements.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageId {
    path: Vec<u8>,
}

/// The root page is the one containing the sub-trie directly descending from the root node.
pub const ROOT_PAGE_ID: PageId = PageId { path: vec![] };

pub const MAX_CHILD_INDEX: u8 = (1 << DEPTH) - 1;

/// The number of children each Page ID has.
pub const NUM_CHILDREN: usize = MAX_CHILD_INDEX as usize + 1;

/// The index of a children of a page.
///
/// Each page can be thought of a root-less binary tree. The leaves of that tree are roots of
/// subtrees stored in subsequent pages. There are 64 (2^[`DEPTH`]) children in each page.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ChildPageIndex(u8);

impl ChildPageIndex {
    pub fn new(index: u8) -> Option<Self> {
        if index > MAX_CHILD_INDEX {
            return None;
        }
        Some(Self(index))
    }

    pub fn to_u8(self) -> u8 {
        self.0
    }
}

impl PageId {
    /// Decode a page ID from its disambiguated representation.
    ///
    /// This can fall out of bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidPageIdBytes> {
        if bytes.len() > MAX_PAGE_DEPTH {
            return Err(InvalidPageIdBytes);
        }

        for byte in bytes {
            ChildPageIndex::new(*byte).ok_or(InvalidPageIdBytes)?;
        }

        Ok(PageId {
            path: bytes.to_vec(),
        })
    }

    /// Get the child index of the page at the given depth.
    ///
    /// This panics if the depth of the page is not at least `depth + 1`.
    pub fn child_index_at_level(&self, depth: usize) -> ChildPageIndex {
        ChildPageIndex(self.path[depth])
    }

    /// Encode this page ID to its disambiguated representation.
    pub fn encode(&self) -> &[u8] {
        // NOTE: here we can trade off some computation for a more space-efficient representation
        // of the page_id, which, insteaf of wasting 2 bits per byte, could be encoded
        // one sextet after the other. This would also require the number of sextets to be
        // encoded at the end to maintain a non-ambiguous representation.
        &self.path
    }

    /// Get the depth of the page ID. The depth of the [`ROOT_PAGE_ID`] is 0.
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Construct the Child PageId given the previous PageId and the child index.
    ///
    /// Child index must be a 6 bit integer, two most significant bits must be zero.
    /// Passed PageId must be a valid PageId and be located in a layer below 42 otherwise
    /// `PageIdOverflow` will be returned.
    pub fn child_page_id(&self, child_index: ChildPageIndex) -> Result<Self, ChildPageIdError> {
        if self.path.len() >= MAX_PAGE_DEPTH {
            return Err(ChildPageIdError::PageIdOverflow);
        }

        let mut path = self.path.clone();
        path.push(child_index.0);
        Ok(PageId { path })
    }

    /// Extract the Parent PageId given a PageId.
    ///
    /// If the provided PageId is the one pointing to the root,
    /// then itself is returned.
    pub fn parent_page_id(&self) -> Self {
        if *self == ROOT_PAGE_ID {
            return ROOT_PAGE_ID;
        }

        let mut path = self.path.clone();
        let _ = path.pop();
        PageId { path }
    }

    /// Whether this page is a descendant of the other.
    pub fn is_descendant_of(&self, other: &PageId) -> bool {
        self.path.starts_with(&other.path)
    }

    /// Get the maximum descendant of this page.
    pub fn max_descendant(&self) -> PageId {
        let mut page_id = self.clone();
        while page_id.path.len() < MAX_PAGE_DEPTH {
            page_id.path.push(MAX_CHILD_INDEX);
        }

        page_id
    }

    /// Get the minimum key-path which could land in this page.
    pub fn min_key_path(&self) -> KeyPath {
        let path_len = ((self.path.len() * 6) + 7) / 8;

        // Force the minimum key_path of the root page to be [0]
        if path_len == 0 {
            return vec![0];
        }

        let mut path = vec![0; path_len];
        let path_bits = path.view_bits_mut::<Msb0>();
        for (i, child_index) in self.path.iter().enumerate() {
            let bit_start = i * 6;
            let bit_end = bit_start + 6;
            let child_bits = &child_index.view_bits::<Msb0>()[2..8];
            path_bits[bit_start..bit_end].copy_from_bitslice(child_bits);
        }

        path
    }

    /// Get the maximum key-path which could land in this page.
    pub fn max_key_path(&self) -> KeyPath {
        let mut path = self.min_key_path();
        path.view_bits_mut::<Msb0>()[6 * self.path.len()..].fill(true);
        path.extend(std::iter::repeat(255).take(MAX_KEY_PATH_LEN - path.len()));
        path
    }
}

/// The bytes cannot form a valid PageId because they use invalid child indices,
/// or the PageId would be larger than the largest valid one.
#[derive(Debug, PartialEq)]
pub struct InvalidPageIdBytes;

/// Errors related to the construction of a Child PageId
#[derive(Debug, PartialEq)]
pub enum ChildPageIdError {
    /// PageId was at the last layer of the page tree
    /// or it was too big to represent a valid page
    PageIdOverflow,
}

/// Iterator of PageIds over a KeyPath,
/// PageIds will be lazily constructed as needed
pub struct PageIdsIterator {
    last_byte: usize,
    remaining_sextets: usize,
    key_path: Uint<8192, 128>,
    page_id: Option<PageId>,
}

impl PageIdsIterator {
    /// Create a PageIds Iterator over a KeyPath
    pub fn new(key_path: KeyPath) -> Self {
        Self {
            last_byte: key_path.len() - 1,
            remaining_sextets: ((key_path.len() * 8) / 6),
            key_path: Uint::from_be_slice(&key_path[..]),
            page_id: Some(ROOT_PAGE_ID),
        }
    }
}

impl Iterator for PageIdsIterator {
    type Item = PageId;

    fn next(&mut self) -> Option<Self::Item> {
        let prev = self.page_id.take()?;

        // If sextets are finished early, return without resetting `prev`
        if self.remaining_sextets == 0 {
            return Some(prev);
        }
        self.remaining_sextets -= 1;

        let child_index = ChildPageIndex::new(self.key_path.byte(self.last_byte) >> 2).unwrap();
        self.key_path <<= 6;
        self.page_id = prev.child_page_id(child_index).ok();
        Some(prev)
    }
}

#[cfg(test)]
mod tests {
    use crate::{page_id::MAX_PAGE_DEPTH, trie::MAX_KEY_PATH_LEN};

    use super::{
        ChildPageIdError, ChildPageIndex, InvalidPageIdBytes, Msb0, PageId, PageIdsIterator, Uint,
        MAX_CHILD_INDEX, ROOT_PAGE_ID,
    };
    use arrayvec::ArrayVec;
    use bitvec::prelude::*;

    fn child_page_id(page_id: &PageId, child_index: u8) -> Result<PageId, ChildPageIdError> {
        page_id.child_page_id(ChildPageIndex::new(child_index).unwrap())
    }

    #[test]
    fn test_encoding_and_decoding_page_id() {
        let mut page_id = PageId { path: Vec::new() };
        let mut child_index = 0;

        for _ in 0..super::MAX_PAGE_DEPTH {
            page_id.path.push(child_index);
            let encoding = page_id.encode();
            let decoded_page_id = PageId::decode(&encoding).unwrap();
            assert_eq!(page_id, decoded_page_id);

            child_index = (child_index + 1) % 64;
        }
    }

    #[test]
    fn test_child_and_parent_page_id() {
        let page_id_1 = vec![6]; // child index 6
        let page_id_1 = PageId::decode(&page_id_1).unwrap();

        assert_eq!(Ok(page_id_1.clone()), child_page_id(&ROOT_PAGE_ID, 6));
        assert_eq!(ROOT_PAGE_ID, page_id_1.parent_page_id());

        let page_id_2 = vec![6, 4]; // child index 4
        let page_id_2 = PageId::decode(&page_id_2).unwrap();

        assert_eq!(Ok(page_id_2.clone()), child_page_id(&page_id_1, 4));
        assert_eq!(page_id_1, page_id_2.parent_page_id());

        let page_id_3 = [6, 4, 63]; // child index 63
        let page_id_3 = PageId::decode(&page_id_3).unwrap();

        assert_eq!(
            Ok(page_id_3.clone()),
            child_page_id(&page_id_2, MAX_CHILD_INDEX),
        );
        assert_eq!(page_id_2, page_id_3.parent_page_id());
    }

    #[test]
    fn test_page_ids_iterator() {
        // key_path = 0b000001|000010|0...
        let mut key_path = vec![0b00000100, 0b00100000];

        let page_id_1 = vec![0b000001];
        let page_id_1 = PageId::decode(&page_id_1).unwrap();

        let page_id_2 = vec![0b000001, 0b000010];
        let page_id_2 = PageId::decode(&page_id_2).unwrap();

        let mut page_ids = PageIdsIterator::new(key_path.to_vec());
        assert_eq!(page_ids.next(), Some(ROOT_PAGE_ID));
        assert_eq!(page_ids.next(), Some(page_id_1));
        assert_eq!(page_ids.next(), Some(page_id_2));

        // key_path = 0b000010|111111|0...
        let key_path = vec![0b00001011, 0b11110000];

        let page_id_1 = vec![0b000010];
        let page_id_1 = PageId::decode(&page_id_1).unwrap();
        let page_id_2 = vec![0b000010, 0b111111];
        let page_id_2 = PageId::decode(&page_id_2).unwrap();

        let mut page_ids = PageIdsIterator::new(key_path.to_vec());
        assert_eq!(page_ids.next(), Some(ROOT_PAGE_ID));
        assert_eq!(page_ids.next(), Some(page_id_1));
        assert_eq!(page_ids.next(), Some(page_id_2));
    }

    #[test]
    fn invalid_child_index() {
        assert_eq!(None, ChildPageIndex::new(0b01010000));
        assert_eq!(None, ChildPageIndex::new(0b10000100));
        assert_eq!(None, ChildPageIndex::new(0b11000101));
    }

    #[test]
    fn test_invalid_page_id() {
        assert_eq!(Err(InvalidPageIdBytes), PageId::decode(&[0, 4, 63, 68]));

        assert_eq!(
            Err(InvalidPageIdBytes),
            PageId::decode(&vec![0; MAX_PAGE_DEPTH + 1])
        );
    }

    #[test]
    fn test_page_id_overflow() {
        let first_page_last_layer = PageIdsIterator::new([0u8; MAX_KEY_PATH_LEN].to_vec())
            .last()
            .unwrap();
        let last_page_last_layer = PageIdsIterator::new([255; MAX_KEY_PATH_LEN].to_vec())
            .last()
            .unwrap();
        assert_eq!(
            Err(ChildPageIdError::PageIdOverflow),
            child_page_id(&first_page_last_layer, 0),
        );
        assert_eq!(
            Err(ChildPageIdError::PageIdOverflow),
            child_page_id(&last_page_last_layer, 0),
        );

        let page_id = vec![0u8; MAX_PAGE_DEPTH - 1];
        let page_id = PageId::decode(&page_id).unwrap();
        assert!(child_page_id(&page_id, 0).is_ok());

        // neither of those two have to panic if called at most 41 times
        let mut low = ROOT_PAGE_ID;
        let mut high = ROOT_PAGE_ID;
        for _ in 0..42 {
            low = child_page_id(&low, 0).unwrap();
            high = child_page_id(&high, MAX_CHILD_INDEX).unwrap();
        }
    }

    #[test]
    fn page_id_sibling_order() {
        let root_page = ROOT_PAGE_ID;
        let mut last_child = None;
        for i in 0..=MAX_CHILD_INDEX {
            let child = root_page.child_page_id(ChildPageIndex(i)).unwrap();
            assert!(child > root_page);

            if let Some(last) = last_child.take() {
                assert!(child > last);
            }
            last_child = Some(child);
        }
    }

    #[test]
    fn page_max_descendants_all_less_than_right_sibling() {
        let sibling_left = ROOT_PAGE_ID.child_page_id(ChildPageIndex(0)).unwrap();
        let sibling_right = ROOT_PAGE_ID.child_page_id(ChildPageIndex(1)).unwrap();

        let mut left_descendant = sibling_left.clone();
        loop {
            left_descendant = match left_descendant.child_page_id(ChildPageIndex(MAX_CHILD_INDEX)) {
                Err(_) => break,
                Ok(d) => d,
            };

            assert!(left_descendant < sibling_right);
        }
    }

    #[test]
    fn page_min_descendants_all_greater_than_left_sibling() {
        let sibling_left = ROOT_PAGE_ID.child_page_id(ChildPageIndex(0)).unwrap();
        let sibling_right = ROOT_PAGE_ID.child_page_id(ChildPageIndex(1)).unwrap();

        let mut right_descendant = sibling_right.clone();
        loop {
            right_descendant = match right_descendant.child_page_id(ChildPageIndex(0)) {
                Err(_) => break,
                Ok(d) => d,
            };

            assert!(right_descendant > sibling_left);
        }
    }

    #[test]
    fn root_min_key_path() {
        assert_eq!(ROOT_PAGE_ID.min_key_path(), [0]);
    }

    #[test]
    fn root_max_key_path() {
        assert_eq!(ROOT_PAGE_ID.max_key_path(), [255; MAX_KEY_PATH_LEN]);
    }

    #[test]
    fn page_min_key_path() {
        let min_page = ROOT_PAGE_ID.child_page_id(ChildPageIndex(0)).unwrap();
        let max_page = ROOT_PAGE_ID
            .child_page_id(ChildPageIndex(MAX_CHILD_INDEX))
            .unwrap();

        assert_eq!(min_page.min_key_path(), [0]);
        assert_eq!(max_page.min_key_path(), vec![0b11111100]);
    }

    #[test]
    fn page_max_key_path() {
        let min_page = ROOT_PAGE_ID.child_page_id(ChildPageIndex(0)).unwrap();
        let max_page = ROOT_PAGE_ID
            .child_page_id(ChildPageIndex(MAX_CHILD_INDEX))
            .unwrap();

        assert_eq!(max_page.max_key_path(), [255; MAX_KEY_PATH_LEN]);

        let mut key_path = [255; MAX_KEY_PATH_LEN];
        for i in 0..6 {
            key_path.view_bits_mut::<Msb0>().set(i, false);
        }
        assert_eq!(min_page.max_key_path(), key_path);
    }
}
