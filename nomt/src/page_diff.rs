use crate::page_cache::NODES_PER_PAGE;

const CLEAR_BIT: u64 = 1 << 63;
const JUMP_BIT: u64 = 1 << 62;

/// A bitfield tracking which nodes have changed within a page.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PageDiff {
    /// Each bit indicates whether the node at the corresponding index has changed.
    ///
    /// There are only effectively [`NODES_PER_PAGE`] (126) nodes per page. The last two bits are
    /// reserved.
    ///
    /// See [`CLEAR_BIT`] and [`JUMP_BIT`].
    changed_nodes: [u64; 2],
}

impl PageDiff {
    /// Create a new page diff from bytes.
    ///
    /// Returns `None` if any of reserved bits are set to 1.
    pub fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        let mut changed_nodes = [0u64; 2];
        changed_nodes[0] = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        changed_nodes[1] = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

        let diff = PageDiff { changed_nodes };
        // Check if the two last bits are set to 1
        if diff.changed(126) || diff.changed(127) {
            return None;
        }
        Some(diff)
    }

    /// Create a new jump page diff from the partial path bit len.
    pub fn from_jump_page(partial_path_bit_len: usize) -> Self {
        let mut changed_nodes = [0u64; 2];

        let init_partial_path = crate::page_cache::JUMP_PARTIAL_PATH_LEN_RANGE.end;
        changed_nodes[0] = (1 << init_partial_path) - 1;
        changed_nodes[1] = JUMP_BIT;

        let mut diff = PageDiff { changed_nodes };

        let partial_path_byte_len = (partial_path_bit_len + 7) / 8;
        let occupied_nodes = (partial_path_byte_len + 31) / 32;
        // Within the first byte there are 64 slots, thus 64 * 32 = 2048 bytes.
        // Keys are at most 1KiB thus they are expected to fit there.
        for idx in 0..occupied_nodes {
            diff.set_changed(init_partial_path + idx);
        }

        diff
    }

    /// Whether the page is a jump page.
    pub fn jump(&self) -> bool {
        self.changed_nodes[1] & JUMP_BIT == JUMP_BIT
    }

    /// Note that some 32-byte slot in the page data has changed.
    ///
    /// The acceptable range is 0..NODES_PER_PAGE. Erases the clear bit.
    pub fn set_changed(&mut self, slot_index: usize) {
        assert!(slot_index < NODES_PER_PAGE);
        let word = slot_index / 64;
        let index = slot_index % 64;
        let mask = 1 << index;
        self.changed_nodes[word] |= mask;
        self.changed_nodes[1] &= !CLEAR_BIT;
    }

    /// Whether a bit is set within the page data.
    pub fn changed(&self, slot_index: usize) -> bool {
        let word = slot_index / 64;
        let index = slot_index % 64;
        let mask = 1 << index;
        self.changed_nodes[word] & mask == mask
    }

    /// Mark the page as having been cleared.
    pub fn set_cleared(&mut self) {
        self.changed_nodes[1] |= CLEAR_BIT;
    }

    /// Whether the page was completely cleared.
    pub fn cleared(&self) -> bool {
        self.changed_nodes[1] & CLEAR_BIT == CLEAR_BIT
    }

    /// Given the page data, collect the nodes that have changed according to this diff.
    /// Panics if this is a cleared page-diff.
    pub fn pack_changed_nodes<'a, 'b: 'a>(
        &'b self,
        page: &'a [u8],
    ) -> impl Iterator<Item = [u8; 32]> + 'a {
        self.assert_not_cleared();
        self.iter_ones().map(|node_index| {
            let start = node_index * 32;
            let end = start + 32;
            page[start..end].try_into().unwrap()
        })
    }

    /// Given the changed nodes, apply them to the given page according to the diff.
    ///
    /// Panics if the number of changed nodes doesn't equal to the number of nodes
    /// this diff recorded.
    pub fn unpack_changed_nodes(&self, nodes: &[[u8; 32]], page: &mut [u8]) {
        assert_eq!(self.count(), nodes.len());
        for (node_index, node) in self.iter_ones().zip(nodes) {
            let start = node_index * 32;
            let end = start + 32;
            page[start..end].copy_from_slice(&node[..]);
        }
    }

    /// Returns the number of changed nodes. Capped at [NODES_PER_PAGE].
    pub fn count(&self) -> usize {
        (self.changed_nodes[0].count_ones() + self.changed_nodes[1].count_ones()) as usize
    }

    /// Get raw bytes representing the PageDiff.
    ///
    /// Panics if this is a cleared page-diff.
    pub fn as_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&self.changed_nodes[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&self.changed_nodes[1].to_le_bytes());
        bytes
    }

    fn assert_not_cleared(&self) {
        assert_eq!(self.changed_nodes[1] & (1 << 63), 0);
    }

    fn iter_ones(&self) -> impl Iterator<Item = usize> {
        self.assert_not_cleared();
        FastIterOnes(self.changed_nodes[0])
            .chain(FastIterOnes(self.changed_nodes[1]).map(|i| i + 64))
    }

    /// Join two `PageDiff` together into one, it results in a `PageDiff` that contains
    /// all the changed nodes present in the two operand `PageDiff`s.
    pub fn join(&self, diff: &PageDiff) -> PageDiff {
        PageDiff {
            changed_nodes: [
                self.changed_nodes[0] | diff.changed_nodes[0],
                self.changed_nodes[1] | diff.changed_nodes[1],
            ],
        }
    }
}

struct FastIterOnes(u64);

impl Iterator for FastIterOnes {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        match self.0.trailing_zeros() {
            64 => None,
            x => {
                self.0 &= !(1 << x);
                Some(x as usize)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PageDiff;
    use crate::page_cache::NODES_PER_PAGE;

    #[test]
    fn ensure_cap() {
        assert_eq!(NODES_PER_PAGE, 126);
    }

    #[test]
    fn iter_ones() {
        let mut diff = PageDiff::default();

        let set_bits = (0..63).map(|i| i * 2).collect::<Vec<_>>();
        for bit in set_bits.iter().cloned() {
            diff.set_changed(bit);
        }

        for bit in set_bits.iter().cloned() {
            assert!(diff.changed(bit));
        }

        let mut iterated_set_bits = diff.iter_ones().collect::<Vec<_>>();
        iterated_set_bits.sort();

        assert_eq!(iterated_set_bits, set_bits);
    }

    #[test]
    fn clear_bit() {
        let mut diff = PageDiff::default();

        diff.set_cleared();
        assert!(diff.cleared());

        // Make sure that setting a node as changed zeros out the clear bit
        diff.set_changed(0);
        assert!(!diff.cleared());
    }

    #[test]
    fn jump_bit() {
        let diff = PageDiff::default();
        assert!(!diff.jump());

        let check_jump_page_diff = |diff: PageDiff, expected_occupied_nodes: usize| {
            assert!(diff.jump());
            for idx in crate::page_cache::JUMP_NODE_RANGE {
                assert!(diff.changed(idx));
            }
            for idx in crate::page_cache::JUMP_PARTIAL_PATH_LEN_RANGE {
                assert!(diff.changed(idx));
            }

            for idx in 0..expected_occupied_nodes {
                assert!(diff.changed(crate::page_cache::JUMP_PARTIAL_PATH_LEN_RANGE.end + idx));
            }
        };

        // 1 bit long paritial path
        let jump_diff = PageDiff::from_jump_page(1);
        check_jump_page_diff(jump_diff, 1);

        // 8 bit long paritial path
        let jump_diff = PageDiff::from_jump_page(8);
        check_jump_page_diff(jump_diff, 1);

        // 32 * 8 bit long paritial path
        let jump_diff = PageDiff::from_jump_page(32 * 8);
        check_jump_page_diff(jump_diff, 1);

        // 32 * 8 + 1 bit long paritial path
        let jump_diff = PageDiff::from_jump_page(32 * 8 + 1);
        check_jump_page_diff(jump_diff, 2);

        // 31 changes by 32 byte each by 8 bits each + some other bits
        // should result in the maximum amount of changes given a key
        // big as most 1KiB
        let jump_diff = PageDiff::from_jump_page(31 * 32 * 8 + 9);
        check_jump_page_diff(jump_diff, 32);
    }
}
