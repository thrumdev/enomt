//! Left-to-right walking and updating the page tree.
//!
//! The core usage is to create a [`PageWalker`] and make repeated called to `advance`,
//! `advance_and_replace`, and `advance_and_place_node`, followed by a single call to `conclude`.
//!
//! The [`PageWalker`], upon concluding, causes the same effect to the trie as a series of
//! standalone put and delete operations, but with a minimal amount of hashing and revisiting of
//! nodes.
//!
//! ## Multi-Update
//!
//! `advance_and_replace` is based off of the observation that a set of put and delete operations
//! can be partitioned into groups based on which terminal node their keys currently look up to.
//! Each terminal node is then replaced with the sub-trie resulting from the set of given updates,
//! and the trie is compacted into its smallest possible form, and hashed.
//!
//! For example,
//!   - Replacing a single leaf node with another leaf node in the case of the previous leaf
//!     being deleted and a new one with the same key or at least key prefix being put.
//!   - Replacing a single leaf node with a terminator, in the case of deleting the leaf which was
//!     there prior.
//!   - Replacing a terminator with a leaf, in the case of a single put operation with that prefix
//!   - Replacing a leaf node or terminator with a larger sub-trie in the case of multiple puts for
//!     keys beginning with that prefix, possibly preserving the initial leaf.
//!
//! We refer to this as sub-trie replacement.
//!
//! Any newly created terminator nodes must be "compacted" upwards as long as their sibling is a
//! terminator or a leaf node to create the most tractable representation. We combine this operation
//! with hashing up towards the root, described in the following paragraph.
//!
//! Any changes in the trie must be reflected in the hashes of the nodes above them, all the way
//! up to the root. When we replace a terminal node with a new sub-trie, we apply the compaction
//! and hashing operations up to the point where no subsequently altered terminal will affect its
//! result. The last terminal finishes hashing to the root. We refer to this as partial compaction.
//!
//! ## Partial Update
//!
//! The PageWalker can also perform a partial update of the trie. By providing a parent page in
//! [`PageWalker::new`], you can restrict the operation only to trie positions which land in pages
//! below the parent. In this mode, the changes which _would_ have been made to the parent page
//! are recorded as part of the output. This is useful for splitting the work of updating pages
//! across multiple threads.

#[cfg(test)]
mod tests;

use bitvec::prelude::*;
use nomt_core::{
    hasher::NodeHasher,
    page::DEPTH,
    page_id::{ChildPageIndex, PageId, ROOT_PAGE_ID},
    trie::{self, KeyPath, Node, NodeKind, ValueHash, TERMINATOR},
    trie_pos::TriePosition,
    update::WriteNode,
};

use crate::{
    merkle::{
        divergence_bit, jump_page_destination, page_set::PageOrigin, BucketInfo, ElidedChildren,
        PAGE_ELISION_THRESHOLD,
    },
    page_cache::{Page, PageMut},
    page_diff::PageDiff,
};

/// The output of the page walker.
pub enum Output {
    /// A new root node.
    ///
    /// This is always the output when no parent page is supplied to the walker.
    Root(Node, Vec<UpdatedPage>),
    /// Nodes to set in the bottom layer of the parent page, indexed by the position of the node
    /// to set.
    ///
    /// This is always the output when a parent page is supplied to the walker.
    ChildPageRoots(Vec<(TriePosition, Node)>, Vec<UpdatedPage>),
}

/// Pages created as output of the page walker, they could be updated or reconstructed pages.
enum PageWalkerPageOutput {
    Updated(UpdatedPage),
    Reconstructed(ReconstructedPage),
}

/// A page which was updated during the course of modifying the trie.
pub struct UpdatedPage {
    /// The ID of the page.
    pub page_id: PageId,
    /// An owned copy of the page, including the modified nodes.
    pub page: PageMut,
    /// A compact diff indicating all modified slots in the page.
    pub diff: PageDiff,
    /// The bucket info associated with the page.
    pub bucket_info: BucketInfo,
}

/// A page which was reconstructed by the page walker.
struct ReconstructedPage {
    /// The ID of the page.
    pub page_id: PageId,
    /// An owned copy of the page, including the modified nodes.
    pub page: PageMut,
    /// Number of leaves present in the child pages of the page.
    pub children_leaves_counter: u64,
    /// A compact diff indicating all reconstructed slots in the page.
    pub diff: PageDiff,
}

/// Represents a jump from the end of one page to another.
/// This will be used within the stack to handle cases where jumps become
/// shorter or longer. Upon compaction, they will either be finalized into
/// standard pages or into a jump page that covers a number of pages.
struct PendingJump {
    /// The source of the pending jump could be an already existing jump page,
    /// therefore, the following data are required to possibly modify
    /// or clear that page
    source: Option<(PageId, PageMut, PageOrigin)>,
    /// Where the jump starts from.
    start_page_id: PageId,
    /// Where the jump arrives at.
    destination_page_id: PageId,
    /// The bit path covered within the trie between the start and
    /// the destination pages.
    bit_path: BitVec<u8, Msb0>,
    /// Used to propagate elision data up the stack.
    elision_data: ElisionData,
    /// The new node associated with the jump.
    node: Option<Node>,
    /// The pages that are jumped and thus need to be cleared.
    jumped_pages: Vec<(PageId, PageMut, Option<BucketInfo>)>,
}

impl PendingJump {
    /// Make the PendingJump shorter from the top, thus making
    /// the second jumped page the new jump start page.
    ///
    /// `is elided`, whether the PendingJump is being elided or not,
    /// because it imply the elision or not of the newly created page.
    ///
    /// Returns all the data required to store the new page and the
    /// shorter pending jump.
    fn shorten_top(
        mut self,
        page_set: &impl PageSet,
        is_elided: bool,
    ) -> (
        PageId,
        PageMut,
        PageDiff,
        Option<BucketInfo>,
        ElisionData,
        PendingJump,
    ) {
        let page_bit_path = &self.bit_path[0..DEPTH];
        // UNWRAP: 6 bits never overflows child page index
        let child_index = ChildPageIndex::new(page_bit_path.load_be::<u8>()).unwrap();

        let page_id = self.start_page_id.clone();
        let mut elision_data = self.elision_data.clone();
        elision_data.elided_children = ElidedChildren::new();
        if is_elided {
            elision_data
                .elided_children
                .set_elide(child_index.clone(), true);
        }

        let (mut page, mut page_diff, bucket_info) = match self.source.take() {
            Some((_page_id, page, page_origin)) => (
                page,
                page_origin
                    .page_diff()
                    .cloned()
                    .unwrap_or(PageDiff::default()),
                page_origin.bucket_info(),
            ),
            None => (page_set.fresh(), PageDiff::default(), None),
        };

        // UNWRAP: If made shorter, the jump is expected to be already filled with the new jump node.
        let node = self.node.unwrap();

        fill_transparent_hash_page(
            &mut page,
            &mut page_diff,
            node,
            0,
            true, /* jump */
            &self.bit_path[..DEPTH],
        );

        page.set_elided_children(&elision_data.elided_children);

        self.bit_path.drain(0..DEPTH);
        // UNWRAP: trie position never overflows page tree.
        self.start_page_id = self.start_page_id.child_page_id(child_index).unwrap();

        (page_id, page, page_diff, bucket_info, elision_data, self)
    }

    /// Make the pending jump longer by the specified bit path.
    fn lengthen(&mut self, mut bit_path: BitVec<u8, Msb0>) {
        self.start_page_id = self.start_page_id.parent_page_id();
        bit_path.extend(self.bit_path.clone());
        self.bit_path = bit_path;
    }
}

/// Specify how to look for a `PendingJump` within `PendingJumps`,
/// by the start or destination page.
enum FindBy {
    Start,
    Destination,
}

/// Container of `PendingJump` that shares the same parent page.
struct PendingJumps {
    jumps: Vec<PendingJump>,
}

impl PendingJumps {
    /// Get the only the jump if there is only one PendingJump,
    /// None otherwise.
    fn get_jump_node(&self) -> Option<Node> {
        if self.jumps.len() == 1 {
            self.jumps[0].node
        } else {
            None
        }
    }

    // Given a PageId and how the PendingJump should be looked for return its index.
    fn find_pending_jump_mut(&mut self, page_id: &PageId, find_by: FindBy) -> Option<usize> {
        self.jumps.iter().position(
            |PendingJump {
                 destination_page_id,
                 start_page_id,
                 ..
             }| {
                match find_by {
                    FindBy::Start => start_page_id == page_id,
                    FindBy::Destination => destination_page_id == page_id,
                }
            },
        )
    }

    /// Extract a mutable `PendingJump`.
    fn get_jump_mut(&mut self, page_id: &PageId, find_by: FindBy) -> Option<&mut PendingJump> {
        self.find_pending_jump_mut(page_id, find_by)
            .map(|idx| &mut self.jumps[idx])
    }

    /// Remove the PendingJump specified by its index and possibly
    /// propagate the elision data to the parent, if specified.
    fn remove_pending_jump(&mut self, idx: usize, parent_elision_data: Option<&mut ElisionData>) {
        let PendingJump {
            elision_data: removed_elision_data,
            ..
        } = self.jumps.remove(idx);

        // Removing a pending jump needs to propagate the already counted number of children leaves
        // if the parent is not already non-elided.
        match parent_elision_data {
            Some(parent_data) if parent_data.prev_children_leaves_counter.is_some() => {
                // UNWRAP: prev_children_leaves_counter has just been checked to be Some.
                let children_leaves_counter = parent_data
                    .children_leaves_counter
                    .get_or_insert(parent_data.prev_children_leaves_counter.unwrap());

                *children_leaves_counter +=
                    removed_elision_data.children_leaves_counter.unwrap_or(0);
            }
            _ => (),
        }
    }

    /// Split a PendingJump exactly `up` positions from the destination.
    ///
    /// This takes into account that `up` starts from the first layer of the
    /// destination page; thus, if `up` is the same as the jump length,
    /// a split will occur in the first layer of the start page.
    /// To skip the jump, `up` must be at least jump_len + 1.
    ///
    /// Panics if the specified jump is not present among the current pending jumps.
    fn split_pending_jump<H: NodeHasher>(
        &mut self,
        page_set: &impl PageSet,
        page_id: &PageId,
        find_by: FindBy,
        up: usize,
        parent_elision_data: Option<&mut ElisionData>,
    ) -> SplitJumpResult {
        // UNWRAP: The specified jump is expected to be present.
        let jump_idx = self.find_pending_jump_mut(page_id, find_by).unwrap();
        let jump = &mut self.jumps[jump_idx];
        let jump_bit_path_len = jump.bit_path.len();

        if up > jump_bit_path_len {
            return SplitJumpResult::Skip(jump_bit_path_len);
        }

        let split_point_idx = jump_bit_path_len - up;

        let first_half_exceeding_bits = split_point_idx % DEPTH;
        let first_half_bit_path =
            jump.bit_path[..split_point_idx - first_half_exceeding_bits].to_bitvec();
        let first_half_bit_path_len = first_half_bit_path.len();

        let split_page_id = jump_page_destination(jump.start_page_id.clone(), &first_half_bit_path)
            .unwrap_or(jump.start_page_id.clone());

        let init_second_half_bit_path = first_half_bit_path.len() + DEPTH;
        let split_page_jump_bit_path =
            &jump.bit_path[first_half_bit_path_len..init_second_half_bit_path];

        // UNWRAP: 6 bits never overflows child page index
        let child_index = ChildPageIndex::new(split_page_jump_bit_path.load_be::<u8>()).unwrap();
        // UNWRAP: trie position never overflows page tree.
        let second_half_start_page_id = split_page_id.child_page_id(child_index).unwrap();
        let second_half_bit_path = jump.bit_path[init_second_half_bit_path..].to_bitvec();
        let second_half_destination_page_id = jump.destination_page_id.clone();

        let mut split_page = page_set.fresh();
        let mut split_page_diff = PageDiff::default();

        let maybe_jump_node = jump.node;
        match maybe_jump_node {
            // Fill the split page up to the jump_node_layers with the jump node,
            // if it is a valid internal node.
            Some(node) => {
                // The split page needs to be filled differently depending on whether the node is internal.
                // Both share a portion of the fill logic, there is a destination at which the node should be written.
                // Between the start of the page and the destination, terminators should be placed.
                // If the node is a jump node, it will be used as the node, otherwise, terminators will be placed
                // in between the destination and the end of the page.
                //
                // The first part, between the beginning of the page and the destination, requires terminators
                // because the page walker needs to traverse the path, and terminators are expected to be found
                // for non-existent reads.
                let jump_node_layers = up - second_half_bit_path.len();
                let destination_depth = DEPTH + 1 - jump_node_layers;
                fill_transparent_hash_page(
                    &mut split_page,
                    &mut split_page_diff,
                    node,
                    destination_depth,
                    trie::is_internal::<H>(&node),
                    &split_page_jump_bit_path[..DEPTH],
                );
            }
            _ => (),
        }

        // A chain of transparent hashes does not add any leaves, but given the fact that
        // the split always occurs after propagating the elision data to the pending jump,
        // it means that the split page will not contain any new leaves in its children.
        // The only information that will be added is the page delta, thus the leaves that will
        // be added within the split page.
        //
        // This means that the current pending jump will keep the same leaves_counter,
        // only extracting the elided_children field that will be moved to the split page.
        // Meanwhile, the split page will store the pending jump's children_leaves_counter value
        // in the children_leaves_counter and prev_children_leaves_counter.
        let mut split_page_elision_data = jump.elision_data.clone();
        jump.elision_data.elided_children = ElidedChildren::new();
        match &split_page_elision_data.children_leaves_counter {
            Some(leaves) if *leaves > 0 => {
                split_page_elision_data.prev_children_leaves_counter =
                    split_page_elision_data.children_leaves_counter;
            }
            Some(leaves) if *leaves == 0 => {
                split_page_elision_data.children_leaves_counter = None;
                split_page_elision_data.prev_children_leaves_counter = Some(0);
            }
            _ => (),
        };

        // If there is a second pending jump after the split page, then
        // the elided_children is not inherited and remains only associated
        // with the second half pending jump.
        if !second_half_bit_path.is_empty() {
            split_page_elision_data.elided_children = ElidedChildren::new();
        }

        // Clear the current PendingJump if the split occurred within the
        // staring page. Otherwise update destination and bit_path.
        if first_half_bit_path.is_empty() {
            self.remove_pending_jump(jump_idx, parent_elision_data);
        } else {
            jump.destination_page_id = split_page_id.clone();
            jump.bit_path = first_half_bit_path;
        }

        let second_half_bit_path_len = second_half_bit_path.len();
        let pending_jump = if second_half_bit_path_len > 0 {
            // The second half is not expected to change the jump node,
            // it is becoming shorter, but it is possible that
            // no terminal will be touched at the bottom of the jump.
            Some(PendingJump {
                start_page_id: second_half_start_page_id,
                destination_page_id: second_half_destination_page_id,
                bit_path: second_half_bit_path,
                jumped_pages: vec![],
                elision_data: ElisionData {
                    page_leaves_counter: None,
                    children_leaves_counter: split_page_elision_data.children_leaves_counter,
                    prev_children_leaves_counter: split_page_elision_data
                        .prev_children_leaves_counter,
                    elided_children: std::mem::replace(
                        &mut split_page_elision_data.elided_children,
                        ElidedChildren::new(),
                    ),
                    reconstruction_diff: None,
                },
                node: maybe_jump_node,
                source: None,
            })
        } else {
            None
        };

        SplitJumpResult::Split {
            split_page_id,
            split_page,
            split_page_diff,
            split_page_elision_data,
            jumped_bits: second_half_bit_path_len,
            pending_jump,
        }
    }
}

/// Result of a PendingJump split.
enum SplitJumpResult {
    /// The PendingJump has been skipped, the amount of up positions
    /// was higher than the length of the jump.
    Skip(usize),
    /// The PendingJump has been split, resulting in a split page.
    Split {
        /// PageId of the page where the split occurred.
        split_page_id: PageId,
        /// Page containing a portion of the previous jump,
        /// up to the split point.
        split_page: PageMut,
        /// Page diff associated with the the fill of the split page.
        split_page_diff: PageDiff,
        /// Elision data associated to the split page.
        split_page_elision_data: ElisionData,
        /// Amounts of effectively jumped bits before reaching the split page.
        jumped_bits: usize,
        /// The resulting second half of the split, if something
        /// needs to be covered between the jump page and the previous destination.
        pending_jump: Option<PendingJump>,
    },
}

/// An item that currently stays in the stack of the page walker.
struct StackPageItem {
    /// The ID of the page.
    page_id: PageId,
    /// An owned copy of the page, including the modified nodes.
    page: PageMut,
    /// A compact diff indicating all modified slots in the page.
    diff: PageDiff,
    /// The bucket info associated with the page.
    /// It can be None if the page was reconstructed or just consolidated.
    bucket_info: Option<BucketInfo>,
    /// Data required to handle page elision.
    elision_data: ElisionData,
    /// Container of all pending jumps which start just below this page.
    pending_jumps: PendingJumps,
}

impl StackPageItem {
    fn new_page(page_id: PageId, page: PageMut, page_origin: PageOrigin) -> Self {
        StackPageItem {
            elision_data: ElisionData {
                elided_children: page.elided_children(),
                page_leaves_counter: page_origin.page_leaves_counter(),
                prev_children_leaves_counter: page_origin.children_leaves_counter(),
                children_leaves_counter: None,
                reconstruction_diff: page_origin.page_diff().cloned(),
            },
            page_id,
            page,
            diff: PageDiff::default(),
            bucket_info: page_origin.bucket_info(),
            pending_jumps: PendingJumps { jumps: vec![] },
        }
    }

    fn parent_elision_data_mut(
        &mut self,
        child_page_id: &PageId,
        find_by: FindBy,
        dbg_text: &mut Vec<String>,
    ) -> &mut ElisionData {
        match self
            .pending_jumps
            .find_pending_jump_mut(child_page_id, find_by)
        {
            Some(idx) => {
                dbg_text.push("found pending jump".to_string());
                //if self.pending_jumps.jumps[idx].start_page_id
                //== PageId::decode(&[
                //51, 44, 20, 7, 3, 22, 2, 29, 52, 52, 37, 63, 28, 43, 55, 32, 31, 60, 37,
                //43, 40, 7,
                //])
                //.unwrap()
                //{
                //dbg_text.push(format!(
                //"THIS shoule have 0 children leaves counter: {:?}",
                //self.pending_jumps.jumps[idx]
                //.elision_data
                //.children_leaves_counter
                //));
                //}
                &mut self.pending_jumps.jumps[idx].elision_data
            }
            None => {
                // NOTE: Once PendingJumps are battle-tested, this could be removed.
                let expected = if let Some((_, partial_path)) = self.page.jump_data() {
                    // UNWRAP: jump partial path is at least 6 bits long.
                    let jump_destination =
                        jump_page_destination(self.page_id.clone(), &partial_path).unwrap();
                    jump_destination.parent_page_id()
                } else {
                    self.page_id.clone()
                };
                assert_eq!(child_page_id.parent_page_id(), expected);
                dbg_text.push("not found pending jump, using stack top elision data".to_string());
                &mut self.elision_data
            }
        }
    }
}

/// It contains all the data required to respect the [`PAGE_ELISION_THRESHOLD`].
#[derive(Clone, Debug)]
struct ElisionData {
    /// Store the number of leaves contained within the page.
    /// This is not needed for non-reconstructed pages.
    page_leaves_counter: Option<u64>,
    /// It contains a counter of all the leaves present in all child pages
    /// at the time of reconstruction. If this counter is above [`PAGE_ELISION_THRESHOLD`],
    /// then there is no need to keep track of it because all parent pages also exceed the threshold.
    prev_children_leaves_counter: Option<u64>,
    /// It contains an updated counter of all the leaves present in all child pages.
    /// This is initially None and is updated by the pages below this one in the stack.
    children_leaves_counter: Option<u64>,
    /// Bitfield used to keep track of which child pages have been elided.
    elided_children: ElidedChildren,
    /// A compact diff indicating all reconstructed slots in the page if the
    /// page was reconstructed.
    reconstruction_diff: Option<PageDiff>,
}

/// A set of pages that the page walker draws upon.
pub trait PageSet {
    /// Get a page from the set. `None` if it isn't exist.
    fn get(&self, page_id: &PageId) -> Option<(Page, PageOrigin)>;
    /// Checks if a `page_id` is already present.
    fn contains(&self, page_id: &PageId) -> bool;
    /// Create a new fresh page.
    fn fresh(&self) -> PageMut;
    /// Insert a page into the set along with its origin.
    fn insert(&mut self, page_id: PageId, page: Page, page_origin: PageOrigin);
}

/// Result of a compaction from the last layer of the page.
enum CompactDestination {
    /// The next position could be the root
    Root,
    /// The next positoin could be within the parent page.
    ChildRoots,
    /// The next position could be in a standard page.
    Page,
    /// The next position could be in .
    SplitJump,
}

/// Left-to-right updating walker over the page tree.
pub struct PageWalker<H> {
    // last position `advance` was invoked with.
    last_position: Option<TriePosition>,
    // actual position
    position: TriePosition,
    parent_data: Option<(PageId, PendingJumps)>,
    child_page_roots: Vec<(TriePosition, Node)>,
    root: Node,
    output_pages: Vec<PageWalkerPageOutput>,

    // the stack contains pages (ascending) which are descendants of the parent page, if any.
    stack: Vec<StackPageItem>,

    // the sibling stack contains the previous node values of siblings on the path to the current
    // position, annotated with their depths.
    sibling_stack: Vec<(Node, usize)>,
    prev_node: Option<Node>, // the node at `self.position` which was replaced in a previous call

    // Whether the page walker is used to reconstruct elided pages.
    // If so, the elision does not occur, if a page is not found in the page set, it is freshly created.
    reconstruction: bool,
    dbg_text: Vec<String>,

    _marker: std::marker::PhantomData<H>,

    #[cfg(test)]
    inhibit_elision: bool,
}

impl<H: NodeHasher> PageWalker<H> {
    /// Create a new [`PageWalker`], with an optional parent page for constraining operations
    /// to a subsection of the page tree.
    pub fn new(root: Node, parent_page: Option<PageId>) -> Self {
        Self::new_inner(root, parent_page, false /* reconstruction */)
    }

    /// Create a new [`PageWalker`] made to reconstruct all elided pages below the specified `parent_page`.
    ///
    /// A [`PageWalker`] created to reconstruct pages can only call [`PageWalker::reconstruct`].
    fn new_reconstructor(root: Node, parent_page: PageId) -> Self {
        Self::new_inner(root, Some(parent_page), true /* reconstruction */)
    }

    fn new_inner(root: Node, parent_page: Option<PageId>, reconstruction: bool) -> Self {
        PageWalker {
            last_position: None,
            position: TriePosition::new(),
            parent_data: parent_page.map(|parent| (parent, PendingJumps { jumps: vec![] })),
            child_page_roots: Vec::new(),
            root,
            output_pages: Vec::new(),
            stack: Vec::new(),
            sibling_stack: Vec::new(),
            prev_node: None,
            _marker: std::marker::PhantomData,
            reconstruction,
            dbg_text: vec![],
            #[cfg(test)]
            inhibit_elision: false,
        }
    }

    #[cfg(test)]
    fn set_inhibit_elision(&mut self) {
        self.inhibit_elision = true;
    }

    /// Advance to a given trie position and replace the terminal node there with a trie
    /// based on the provided key-value pairs.
    ///
    /// The key-value pairs should be sorted and should all be suffixes of the given position.
    ///
    /// An empty vector deletes any existing terminal node.
    ///
    /// # Panics
    ///
    /// Panics if the current trie position is not a terminal node.
    ///
    /// Panics if this falls in a page which is not a descendant of the parent page, if any.
    /// Panics if this is not greater than the previous trie position.
    pub fn advance_and_replace(
        &mut self,
        page_set: &impl PageSet,
        new_pos: TriePosition,
        ops: impl IntoIterator<Item = (KeyPath, ValueHash)>,
    ) {
        let ops: Vec<_> = ops.into_iter().collect();

        if let Some(ref pos) = self.last_position {
            assert!(new_pos.path() > pos.path());
            self.compact_up(Some(new_pos.clone()), page_set);
        }
        self.last_position = Some(new_pos.clone());
        self.build_stack(page_set, new_pos);
        self.replace_terminal(page_set, ops);
    }

    /// Advance to a given trie position and place the given node at that position.
    ///
    /// It is the responsibility of the user to ensure that:
    ///   - if this is an internal node, the two child positions hashed together create this node.
    ///   - if this is a terminal node, then nothing exists in the two child positions.
    ///
    /// The expected usage of this function is to be called with the values of
    /// `Output::ChildPageRoots`.
    ///
    /// # Panics
    ///
    /// Panics if the current trie position is not a terminal node.
    ///
    /// Panics if this falls in a page which is not a descendant of the parent page, if any.
    /// Panics if this is not greater than the previous trie position.
    pub fn advance_and_place_node(
        &mut self,
        page_set: &impl PageSet,
        new_pos: TriePosition,
        node: Node,
    ) {
        if let Some(ref pos) = self.last_position {
            assert!(new_pos.path() > pos.path());
            self.compact_up(Some(new_pos.clone()), page_set);
        }
        self.last_position = Some(new_pos.clone());
        self.build_stack(page_set, new_pos);
        self.place_node(node);
    }

    /// Advance to a given trie position without updating.
    ///
    /// # Panics
    ///
    /// Panics if this falls in a page which is not a descendant of the parent page, if any.
    /// Panics if this is not greater than the previous trie position.
    pub fn advance(&mut self, new_pos: TriePosition, page_set: &impl PageSet) {
        if let Some(ref pos) = self.last_position {
            assert!(new_pos.path() > pos.path());
            self.compact_up(Some(new_pos.clone()), page_set);
        }

        let page_id = new_pos.page_id();
        self.assert_page_in_scope(page_id.as_ref());
        self.last_position = Some(new_pos);
    }

    fn place_node(&mut self, node: Node) {
        if self.position.is_root() {
            self.prev_node = Some(self.root);
            self.root = node;
        } else {
            self.prev_node = Some(self.node());
            self.set_node(node);
        }
    }

    fn replace_terminal(
        &mut self,
        page_set: &impl PageSet,
        ops: impl IntoIterator<Item = (KeyPath, ValueHash)>,
    ) {
        let node = if self.position.is_root() {
            self.root
        } else {
            if self.reconstruction {
                trie::TERMINATOR
            } else {
                self.node()
            }
        };

        self.prev_node = Some(node);

        // During reconstruction, it is accepted to starts from internal nodes.
        if !self.reconstruction {
            assert!(!trie::is_internal::<H>(&node));
        }

        let start_position = self.position.clone();

        // Given the ops, build the required collision subtries and modify the ops
        // by inserting the collision subtries root as collision leaves.
        let ops = nomt_core::collisions::build_collision_subtries::<H>(ops.into_iter());

        // replace sub-trie at the given position
        nomt_core::update::build_trie::<H>(self.position.depth() as usize, ops, |control| {
            let node = control.node();
            let up = control.up();
            let mut down = control.down();
            let jump = control.jump();

            self.dbg_text.push(format!(
                "node: {:?}",
                nomt_core::hasher::node_kind_by_msbs(&node)
            ));
            self.dbg_text.push(format!("up: {:?}", up));
            self.dbg_text.push(format!("down: {:?}", down));
            self.dbg_text.push(format!("jump: {:?}", jump));

            if let WriteNode::Internal {
                ref internal_data, ..
            } = control
            {
                // we assume pages are not necessarily zeroed. therefore, there might be
                // some garbage in the sibling slot we need to clear out.

                let zero_sibling = if self.position.peek_last_bit() {
                    trie::is_terminator::<H>(&internal_data.left)
                } else {
                    trie::is_terminator::<H>(&internal_data.right)
                };

                if zero_sibling {
                    self.set_sibling(trie::TERMINATOR);
                }
            }

            let mut up_within_pending_jump = false;
            // avoid popping pages off the stack if we are jumping to a sibling.
            if up && !down.is_empty() {
                if down[0] == !self.position.peek_last_bit() {
                    // UNWRAP: checked above
                    self.position.sibling();
                    down = &down[1..];
                } else {
                    up_within_pending_jump = self.up(page_set);
                }
            } else if up {
                up_within_pending_jump = self.up(page_set);
            }

            // Up just says to go up by one position, and it is short-circuited
            // in the case of moving to the sibling subtree (up true and then down).
            // This implies that if we end up within a pending jump, there is no
            // expectation to go down from there.
            if up_within_pending_jump {
                assert!(down.is_empty());
            }

            self.down(page_set, &down, true);

            if self.position.is_root() {
                self.root = node;
            } else if self
                .parent_data
                .as_ref()
                .map_or(false, |(parent_page_id, _)| {
                    // UNWRAP: Position has just been checked to not be the root.
                    *parent_page_id == self.position.page_id().unwrap()
                })
            {
                self.child_page_roots.push((self.position.clone(), node));
            } else {
                if up_within_pending_jump {
                    // Moving within a pending jump implies not having a page
                    // under which the node can be placed, which means it remains un-applied
                    // until the jump uses it or writes it to the page.
                    self.jump(jump, page_set, Some(node));
                } else {
                    self.set_node(node);
                    self.jump(jump, page_set, None);
                }
            }
        });

        assert_eq!(self.position, start_position);

        // build_trie should always return us to the original position.
        if !self.position.is_root() {
            // UNWRAP: Either a page in the stack or the parent must be present.
            let expected_page_id = self
                .stack
                .last()
                .map(|item| item.page_id.clone())
                .or(self.parent_data.as_ref().map(|(id, _)| id.clone()))
                .unwrap();
            assert_eq!(expected_page_id, self.position.page_id().unwrap());
        } else {
            self.stack.len();
            self.stack.last().map(|item| &item.page_id);
            assert!(self.stack.is_empty());
        }
    }

    // Move the current position up.
    //
    // Return true if the position moved up not within the parent
    // page of the stack top, but instead moved within a pending
    // jump of the parent's page.
    fn up(&mut self, page_set: &impl PageSet) -> bool {
        let was_first_layer_in_page = self.position.is_first_layer_in_page();
        self.position.up(1);

        // If the position were at first layer of the page, possibly pop and handle it.
        if was_first_layer_in_page {
            // UNWRAPs: there is always a page to go up from.
            let child_page_id = self.stack.last().unwrap().page_id.clone();
            let expected_parent_page_id = child_page_id.parent_page_id();

            self.handle_traversed_page(page_set);

            let Some(stack_top) = self.stack.last_mut() else {
                // If there are no other elements in the stack, we could either
                // be at the root position or have reached the parent page.

                match &self.parent_data {
                    // There is no stack item, but the parent page has not been reached yet,
                    // thus, there must be a pending jump from the parent
                    // pointing to the previous position.
                    Some((parent_page_id, _)) if *parent_page_id != expected_parent_page_id => {
                        return true
                    }
                    // The parent page has been reached.
                    Some(..) => return false,
                    // If there are no other elements in the stack and there is
                    // no parent page, then the root must have been reached.
                    None => {
                        assert_eq!(self.position.depth(), 0);
                        return false;
                    }
                }
            };

            // The last page in the stack has been handled, now a pending jump
            // could have been reached.
            if !stack_top.page.jump() && expected_parent_page_id != stack_top.page_id {
                return true;
            }
        }

        false
    }

    // Starting from the current position, jump up by the specified amount,
    // regardless of the size of the jump, if pages are skipped, create PendingJumps,
    // which will be consolidated or not into pages lazily during finalization.
    fn jump(&mut self, mut up: usize, page_set: &impl PageSet, maybe_jump_data: Option<Node>) {
        // The jump can be divided into the following steps:
        // 1. Perform the hash up within the current page up to the first layer.
        // 2. Handle the traversed page and move to the parent page.
        // 3. Check if the parent page in the stack has the same expected parent page_id.
        // 4. If yes, go back to step one, utilizing the parent page as the new base page.
        // 5. If no, then there must be a pending jump with the expected destination page_id.
        //    Considering the bit_path of the pending jump it can be skip or be split.
        // 6. Complete the transparent hash on the newly created page.

        // 1
        //
        // Step 1 depends also on `maybe_jump_node`, if specified it the position right now points
        // to the last layer of a page which is covered by a pending jump. In this case step 1 is
        // skip and go directly to step 5.
        let (node, child_page_id) = match maybe_jump_data {
            Some(node) => {
                // UNWRAP: There must be a page containg the PendingJump.
                let cur_page_id = self.position.page_id().unwrap();
                let child_page_id = cur_page_id
                    .child_page_id(self.position.child_page_index())
                    .unwrap();

                // This is a trick to reuse the 5th step without modifying it.
                // The position goes down by one, to later be compensated by the jump.
                self.position.down(false);
                up += 1;

                (node, child_page_id)
            }
            None => {
                if up == 0 {
                    // Early return if jump is not required.
                    return;
                }

                let node = self.node();
                let layer_in_page = self.position.depth_in_page() - 1;

                // The sibling of the current position needs to be set before
                // performing the first step of transparent hash up.
                self.set_sibling(trie::TERMINATOR);

                // Subtract 1 because the last step will not require a terminator sibling,
                // it only sets the branch node at the destination position.
                let hash_up_layers = std::cmp::min(up - 1, layer_in_page);
                self.transparent_hash_up(node, hash_up_layers);
                up -= hash_up_layers;

                if up == 1 && self.position.depth_in_page() != 1 {
                    // The transparent hash up ends within the same page.
                    self.position.up(1);
                    self.set_node(node);
                    return;
                }

                // 2
                // UNWRAPs: There is always a page while goung up.
                let child_page_id = self.stack.last().unwrap().page_id.clone();
                let expected_parent_page_id = child_page_id.parent_page_id();
                // NOTE: this is the only place were the call to handle_traversed_page happens
                self.handle_traversed_page(page_set);

                // 3
                let maybe_parent_page_id =
                    self.stack.last().map(|item| item.page_id.clone()).or(self
                        .parent_data
                        .as_ref()
                        .map(|(page_id, _)| page_id.clone()));

                let Some(parent_page_id) = maybe_parent_page_id else {
                    assert_eq!(up, 1);
                    assert_eq!(self.position.depth(), 1);
                    self.position.up(1);
                    self.root = node;
                    return;
                };

                if expected_parent_page_id == parent_page_id {
                    // 4. Re-start jumping up from the first layer of the next page.
                    self.position.up(1);
                    if !self.stack.is_empty() {
                        // If the stack is not empty than set the node within the last
                        // page in the stack and continue jump from there
                        self.set_node(node);
                        self.jump(up - 1, page_set, None);
                    } else {
                        // If the stack is empty it means that the parent page was reached
                        // and thus we save the value in the child page roots
                        self.child_page_roots.push((self.position.clone(), node));
                    }
                    return;
                }
                (node, child_page_id)
            }
        };

        let (parent_pending_jumps, parent_elision_data) = match self.stack.last_mut() {
            Some(stack_top) => (
                &mut stack_top.pending_jumps,
                Some(&mut stack_top.elision_data),
            ),
            None => {
                // UNWRAP: if there are not stack items the parent page
                // and its pending jumps are expected to be used.
                self.parent_data
                    .as_mut()
                    .map(|(_, pending_jump)| (pending_jump, None))
                    .unwrap()
            }
        };

        // 5
        // Between the last page that has been popped and
        // the current stack top, a PendingJump is expected.
        match parent_pending_jumps.split_pending_jump::<H>(
            page_set,
            &child_page_id,
            FindBy::Destination,
            up,
            parent_elision_data,
        ) {
            SplitJumpResult::Skip(jump_len) => {
                let jump_idx = parent_pending_jumps
                    .find_pending_jump_mut(&child_page_id, FindBy::Destination)
                    .unwrap();
                parent_pending_jumps.jumps[jump_idx].node.replace(node);

                // Not only does the jump need to be skipped, but moving up to the
                // last layer of the jump's starting page needs to be done.

                up -= jump_len;
                self.position.up(jump_len as u16);

                if up > 1 {
                    up -= 1;
                    self.position.up(1);

                    if !self.stack.is_empty() {
                        // If the stack is not empty than set the node within the last
                        // page in the stack and continue jump from there
                        self.set_node(node);
                        self.jump(up, page_set, None);
                    } else {
                        // If the stack is empty it means that the parent page was reached
                        // and thus we save the value in the child page roots
                        self.child_page_roots.push((self.position.clone(), node));
                    }

                    return;
                }
            }
            SplitJumpResult::Split {
                split_page_id,
                split_page,
                jumped_bits,
                pending_jump,
                split_page_diff,
                split_page_elision_data,
            } => {
                self.dbg_text
                    .push(format!("split happened at: {:?}", split_page_id));
                self.dbg_text.push(format!(
                    "split_page_elision_data: {:?}",
                    split_page_elision_data
                ));
                let mut stack_page_item = StackPageItem {
                    elision_data: split_page_elision_data,
                    page_id: split_page_id,
                    page: split_page,
                    diff: split_page_diff,
                    bucket_info: None,
                    pending_jumps: PendingJumps { jumps: vec![] },
                };

                if let Some(mut pending_jump) = pending_jump {
                    pending_jump.node = Some(node);
                    stack_page_item.pending_jumps.jumps.push(pending_jump);
                }

                self.stack.push(stack_page_item);
                up -= jumped_bits;
                self.position.up(jumped_bits as u16);

                // 6
                assert!(up <= DEPTH);
                self.transparent_hash_up(node, up - 1);
            }
        };

        self.position.up(1);
        if self.position.is_root() {
            self.root = node;
        } else {
            if !self.stack.is_empty() {
                // If the stack is not empty than set the node within the last
                // page in the stack and continue jump from there
                self.set_node(node);
            } else {
                // If the stack is empty it means that the parent page was reached
                // and thus we save the value in the child page roots
                self.child_page_roots.push((self.position.clone(), node));
            }
        }
    }

    // Perform transparent hash_up for the specified amount of layers on the current page
    // form the current position.
    fn transparent_hash_up(&mut self, node: Node, layers: usize) {
        for _ in 0..layers {
            self.position.up(1);
            self.set_node(node);
            self.set_sibling(trie::TERMINATOR);
        }
    }

    // move the current position down, hinting whether the location is guaranteed to be fresh.
    fn down(&mut self, page_set: &impl PageSet, bit_path: &BitSlice<u8, Msb0>, fresh: bool) {
        if self.stack.last().map_or(false, |item| item.page.jump()) {
            // PANIC: down should never be called on jump pages or traverse them.
            unreachable!()
        }

        let push_page = |page_id, stack: &mut Vec<_>| {
            let (page, page_origin) = if fresh {
                (
                    page_set.fresh(),
                    PageOrigin::Reconstructed {
                        page_leaves_counter: 0,
                        children_leaves_counter: 0,
                        diff: PageDiff::default(),
                    },
                )
            } else {
                // UNWRAP: all pages on the path to the node should be in the cache.
                page_set
                    .get(&page_id)
                    .map(|(p, b)| (p.deep_copy(), b))
                    .unwrap()
            };

            stack.push(StackPageItem::new_page(page_id, page, page_origin));
        };

        let mut bit_path_idx = 0;
        while bit_path_idx < bit_path.len() {
            if self.position.is_root() {
                // If we currently are at the root position let's create the root page,
                // it cannot be a jump page.
                push_page(ROOT_PAGE_ID, &mut self.stack);
                self.position.down(bit_path[bit_path_idx]);
                bit_path_idx += 1;
            } else if self.position.depth_in_page() == DEPTH {
                self.down_new_page(bit_path, &mut bit_path_idx, push_page);
            } else {
                // Simply go down within the current page.
                self.position.down(bit_path[bit_path_idx]);
                bit_path_idx += 1;
            }
        }
    }

    // Move the current position down to a new page,
    // possibly creating a new PendingJump if more than one page is skipped.
    fn down_new_page(
        &mut self,
        bit_path: &BitSlice<u8, Msb0>,
        bit_path_idx: &mut usize,
        push_page: impl Fn(PageId, &mut Vec<StackPageItem>),
    ) {
        let (parent_page_id, parent_pending_jumps) = match self.stack.last_mut() {
            Some(stack_top) => (stack_top.page_id.clone(), &mut stack_top.pending_jumps),
            None => {
                // UNWRAP: if there are not stack items the parent page and its pending jumps
                // are expected to be used.
                self.parent_data
                    .as_mut()
                    .map(|(page_id, pending_jump)| (page_id.clone(), pending_jump))
                    .unwrap()
            }
        };
        let child_page_index = self.position.child_page_index();

        // UNWRAP: we never overflow the page stack.
        let child_page_id = parent_page_id
            .child_page_id(child_page_index.clone())
            .unwrap();

        assert!(parent_pending_jumps
            .find_pending_jump_mut(&child_page_id, FindBy::Start)
            .is_none());

        // Given the remaining bit_path, get an iterator over all the jumped pages.
        // If at least one page is jumped, then let's save a pending jump in the current
        // page and go directly to the destination page.
        let relevant_bit_path = &bit_path[*bit_path_idx..bit_path.len() - 1];
        let maybe_destination_page_id =
            jump_page_destination(child_page_id.clone(), relevant_bit_path);

        let destination_page_id = match maybe_destination_page_id {
            Some(destination_page_id) => {
                let covered_pages = relevant_bit_path.len() / 6;
                let used_bits = covered_pages * DEPTH;
                let jump_bit_path = relevant_bit_path[..used_bits].to_bitvec();

                //if child_page_id
                //== PageId::decode(&[
                //51, 44, 20, 7, 3, 22, 2, 29, 52, 52, 37, 63, 28, 43, 55, 32, 31, 60, 37,
                //43, 40, 7,
                //])
                //.unwrap()
                //{
                //self.dbg_text
                //.push("..., 40, 7 pending jump being pushed".to_string());
                //}

                parent_pending_jumps.jumps.push(PendingJump {
                    start_page_id: child_page_id,
                    destination_page_id: destination_page_id.clone(),
                    bit_path: jump_bit_path,
                    elision_data: ElisionData {
                        page_leaves_counter: Some(0),
                        prev_children_leaves_counter: Some(0),
                        children_leaves_counter: None,
                        elided_children: ElidedChildren::new(),
                        reconstruction_diff: None,
                    },
                    jumped_pages: vec![],
                    node: None,
                    source: None,
                });
                destination_page_id
            }
            None => child_page_id,
        };

        // pushing the destination page after the jump page.
        push_page(destination_page_id, &mut self.stack);
        for bit in &bit_path[*bit_path_idx..] {
            self.position.down(*bit);
        }
        *bit_path_idx += bit_path[*bit_path_idx..].len();
    }

    /// Get the previous values of any siblings on the path to the current node, along with their depth.
    pub fn siblings(&self) -> &[(Node, usize)] {
        &self.sibling_stack
    }

    /// Conclude walking and updating and return an output - either a new root, or a list
    /// of node changes to apply to the parent page.
    pub fn conclude(mut self, page_set: &impl PageSet) -> Output {
        assert!(!self.reconstruction);
        self.compact_up(None, page_set);

        self.handle_last_pending_jumps(page_set);

        // SAFETY: PageWlaker was initialized to not reconstruct pages.
        let updated_pages = self
            .output_pages
            .into_iter()
            .map(|output_page| match output_page {
                PageWalkerPageOutput::Updated(updated_page) => updated_page,
                _ => unreachable!(),
            })
            .collect();

        if self.parent_data.is_none() {
            Output::Root(self.root, updated_pages)
        } else {
            Output::ChildPageRoots(self.child_page_roots, updated_pages)
        }
    }

    // Handle the pending jobs that are just before the parent page.
    fn handle_last_pending_jumps(&mut self, page_set: &impl PageSet) {
        if let Some(pending_jumps) = self
            .parent_data
            .as_mut()
            .map(|(_, pending_jumps)| std::mem::replace(&mut pending_jumps.jumps, vec![]))
        {
            for pending_jump in pending_jumps {
                self.handle_pending_jump(pending_jump, page_set, false /* parent_elided */);
            }
        }
    }

    /// Reconstruct all pages under the parent page and the specified position using the provided ops.
    ///
    /// Returns None if the pages that should be reconstructed are already in the `PageSet`.
    ///
    /// Panics if the page walker was not constructed using `new_reconstructor`.
    fn reconstruct(
        mut self,
        page_set: &mut impl PageSet,
        position: TriePosition,
        ops: impl IntoIterator<Item = (KeyPath, ValueHash)>,
    ) -> Option<(Node, Vec<ReconstructedPage>)> {
        assert!(self.reconstruction);

        // UNWRAPs: parent_data must be present.
        let parent_page_id = self
            .parent_data
            .as_ref()
            .map(|(page_id, _)| page_id.clone())
            .unwrap();
        let first_elided_page_id = parent_page_id
            .child_page_id(position.child_page_index())
            .unwrap();

        if page_set.contains(&first_elided_page_id) {
            // Reconstruction already happened, avoid doing it twice.
            return None;
        }

        self.last_position = Some(position.clone());
        self.dbg_text
            .push(format!("from pos: {:?}", self.last_position));
        self.position = position.clone();
        self.replace_terminal(page_set, ops);
        self.compact_up(None, page_set);
        self.handle_last_pending_jumps(page_set);

        // SAFETY: PageWlaker was initialized to only reconstruct pages.
        let reconstructed_pages = self
            .output_pages
            .into_iter()
            .map(|output_page| match output_page {
                PageWalkerPageOutput::Reconstructed(reconstructed_page) => reconstructed_page,
                _ => unreachable!(),
            })
            .collect();

        Some((self.child_page_roots[0].1, reconstructed_pages))
    }

    // From the current position, compact upwards towards `target_pos` if specified,
    // otherwise, compact up to the root or the parent page.
    fn compact_up(&mut self, target_pos: Option<TriePosition>, page_set: &impl PageSet) {
        // This serves as a check to see if we have anything to compact.
        if self.stack.is_empty() {
            return;
        }

        let mut compact_layers = if let Some(target_pos) = target_pos {
            let current_depth = self.position.depth() as usize;
            let shared_depth = self.position.shared_depth(&target_pos);

            // prune all siblings after shared depth. this function will push one more pending
            // sibling at `shared_depth + 1`.
            let keep_sibling_depth = shared_depth;
            let keep_sibling_len = self
                .sibling_stack
                .iter()
                .take_while(|s| s.1 <= keep_sibling_depth)
                .count();
            self.sibling_stack.truncate(keep_sibling_len);

            // shared_depth is guaranteed less than current_depth because the full prefix isn't
            // shared.
            // we want to compact up (inclusive) to the depth `shared_depth + 1`
            let compact_layers = current_depth - (shared_depth + 1);

            if compact_layers == 0 {
                if let Some(prev_node) = self.prev_node.take() {
                    self.sibling_stack.push((prev_node, current_depth));
                }
            } else {
                self.prev_node = None;
            }
            compact_layers
        } else {
            self.sibling_stack.clear();
            self.position.depth() as usize
        };

        while compact_layers != 0 {
            // 1. Compute next node.
            let next_node = self.compact_step();

            // 2. Move up, possibly handling jumps.
            let compact_dest = if self.position.is_first_layer_in_page() {
                let compact_dest = match self.maybe_lenghten_pending_jump(
                    page_set,
                    next_node,
                    &mut compact_layers,
                ) {
                    Some(compact_dest) => compact_dest,
                    None => self.compact_up_page(page_set, next_node, &mut compact_layers),
                };
                compact_dest
            } else {
                self.position.up(1);
                compact_layers -= 1;
                CompactDestination::Page
            };

            // 3. Place node
            match compact_dest {
                CompactDestination::Root => {
                    assert_eq!(compact_layers, 0);
                    self.root = next_node;
                    return;
                }
                CompactDestination::ChildRoots => {
                    assert_eq!(
                        self.position.page_id().unwrap(),
                        self.parent_data.as_ref().unwrap().0
                    );
                    self.child_page_roots
                        .push((self.position.clone(), next_node));
                    return;
                }
                CompactDestination::SplitJump => {
                    return;
                }
                CompactDestination::Page => {
                    if compact_layers == 0 {
                        self.sibling_stack
                            .push((self.node(), self.position.depth() as usize));
                    }
                    self.set_node(next_node);
                }
            }
        }
    }

    fn compact_step(&mut self) -> Node {
        let stack_top = self.stack.last();
        assert!(!stack_top.map_or(false, |item| item.page.jump()));

        let node = self.node();
        let sibling = self.sibling_node();
        let bit = self.position.peek_last_bit();

        match (NodeKind::of::<H>(&node), NodeKind::of::<H>(&sibling)) {
            (NodeKind::Terminator, NodeKind::Terminator) => {
                // compact terminators.
                trie::TERMINATOR
            }
            (NodeKind::Leaf, NodeKind::Terminator)
            | (NodeKind::CollisionLeaf, NodeKind::Terminator) => {
                // compact: clear this node, move leaf up.
                self.set_node(trie::TERMINATOR);
                node
            }
            (NodeKind::Terminator, NodeKind::Leaf)
            | (NodeKind::Terminator, NodeKind::CollisionLeaf) => {
                // compact: clear sibling node, move leaf up.
                self.position.sibling();
                self.set_node(trie::TERMINATOR);
                sibling
            }
            _ => {
                // otherwise, internal
                let node_data = if bit {
                    trie::InternalData {
                        left: sibling,
                        right: node,
                    }
                } else {
                    trie::InternalData {
                        left: node,
                        right: sibling,
                    }
                };

                let depth = self.position.depth() as usize - 1;
                H::hash_internal(&node_data, &self.position.path()[..depth])
            }
        }
    }

    // Once the first layer of a page is reached, while compacting upwards, it may happen
    // that the entire page is filled with the same node. If that node is also associated
    // with the only pending jump of the page, the page will be extended, and the just
    // traversed page will join the previous pending jump.
    fn maybe_lenghten_pending_jump(
        &mut self,
        page_set: &impl PageSet,
        node: Node,
        compact_layers: &mut usize,
    ) -> Option<CompactDestination> {
        // UNWRAPs: There must be a page if we are trying to make a jump longer.
        let stack_top = self.stack.last_mut().unwrap();

        // If we reach the first layer of a page, then 'node' contains the
        // node that will be placed within the last layer of the parent.
        //
        // If 'node' is an internal node and  is the same as the only pending jump
        // of the current stack item, it is proven that only a transparent hash has
        // occurred on this page, and this means that the current unique pending jump
        // can be made longer.
        //
        // This only happens if the page we are going to cover with the jump is
        // not within the first two layers of the trie.
        match stack_top.pending_jumps.get_jump_node() {
            Some(jump_node)
                if stack_top.page_id.depth() > 1
                    && jump_node == node
                    && trie::is_internal::<H>(&jump_node) =>
            {
                ()
            }
            _ => return None,
        };

        // No work on elision_data is required because a jump page does not add any info.
        //
        // UNWRAP: The stack top has already been checked to exist.
        let mut cleared_top = self.stack.pop().unwrap();
        let prev_stack_top_page_id = cleared_top.page_id.clone();

        // The bit path followed by the transparent hash can become part of the pending jump,
        // and the page must be cleared.
        let bit_path = traverse_transparent_hash_page(&cleared_top.page, node).unwrap();

        let mut pending_jump = cleared_top.pending_jumps.jumps.remove(0);
        pending_jump.lengthen(bit_path);

        // The covered page and the source page need to be pushed within
        // the jumped pages that will be cleared during the finalization of the PendingJump.
        match pending_jump.source.take() {
            Some((source_page_id, source_page, source_page_origin)) => {
                assert_eq!(cleared_top.page_id.clone(), source_page_id.parent_page_id());
                pending_jump.jumped_pages.push((
                    cleared_top.page_id,
                    cleared_top.page,
                    cleared_top.bucket_info,
                ));
                pending_jump.jumped_pages.push((
                    source_page_id,
                    source_page,
                    source_page_origin.bucket_info(),
                ));
            }
            None => {
                pending_jump.jumped_pages.push((
                    cleared_top.page_id,
                    cleared_top.page,
                    cleared_top.bucket_info,
                ));
            }
        };

        let compact_dest_result = self.compact_up_from_pending_jump(
            page_set,
            node,
            compact_layers,
            prev_stack_top_page_id,
        );

        let (pending_jumps, is_parent) = if let Some(stack_top) = self.stack.last_mut() {
            (&mut stack_top.pending_jumps, false)
        } else {
            // UNWRAP: parent pending jumps must be present if the stack is empty.
            self.parent_data
                .as_mut()
                .map(|(_, pending_jumps)| (pending_jumps, true))
                .unwrap()
        };

        match compact_dest_result {
            // The longer pending jump can now be stored, and compaction continue from there.
            None => {
                pending_jumps.jumps.push(pending_jump);
                self.position.up(1);
                *compact_layers -= 1;

                return if is_parent {
                    Some(CompactDestination::ChildRoots)
                } else {
                    Some(CompactDestination::Page)
                };
            }
            // If another pending jump is met while going up, they need to be joined or
            // pushed as new if it has been split and the second half deleted.
            Some(compact_dest) => {
                match pending_jumps.get_jump_mut(&pending_jump.start_page_id, FindBy::Destination) {
                    Some(parent_jump) => {
                        // Destination of the child becomes the destination
                        // of the parent pending jump.
                        parent_jump.destination_page_id = pending_jump.destination_page_id;

                        // Bit path are concatenated.
                        parent_jump.bit_path.append(&mut pending_jump.bit_path);

                        // Jumped pages are joined.
                        parent_jump.jumped_pages.extend(pending_jump.jumped_pages);

                        // ElisionData remains the one of the child pending jump.
                        parent_jump.elision_data = pending_jump.elision_data;

                        // New node is also taken from the child pending jump..
                        parent_jump.node = pending_jump.node;
                    }
                    None => {
                        pending_jumps.jumps.push(pending_jump);
                    }
                }
                return Some(compact_dest);
            }
        }
    }

    // Once the first layer of a page is reached, the next step is to move up,
    // handling any possibilities: encountering a pending jump, reaching the root
    // or parent page, or simply moving on to the next page.
    fn compact_up_page(
        &mut self,
        page_set: &impl PageSet,
        node: Node,
        compact_layers: &mut usize,
    ) -> CompactDestination {
        // UNWRAPs: The page where the compaction is expected to happen needs to exist.
        let prev_stack_top_page_id = self.stack.last().unwrap().page_id.clone();
        let expected_parent_page_id = prev_stack_top_page_id.parent_page_id();

        self.handle_traversed_page(page_set);

        if let Some(stack_top) = self.stack.last_mut() {
            // If the stack top page_id matches the expectation just continue compacting up.
            if expected_parent_page_id == stack_top.page_id {
                self.position.up(1);
                *compact_layers -= 1;
                return CompactDestination::Page;
            }
            // Otherwise handle the reached PendingJump.
            (
                &mut stack_top.pending_jumps,
                Some(&mut stack_top.elision_data),
            )
        } else {
            // Return and handle the next node being the root if both the stack
            // is empty and there is no parent page.
            let Some((parent_page_id, pending_jumps)) = self.parent_data.as_mut() else {
                self.position.up(1);
                *compact_layers -= 1;
                return CompactDestination::Root;
            };

            // If parent page reached than store the new child page root.
            if expected_parent_page_id == *parent_page_id {
                self.position.up(1);
                *compact_layers -= 1;
                return CompactDestination::ChildRoots;
            }

            // Otherwise handle the last layer PendingJumps.
            (pending_jumps, None)
        };

        // UNWRAP: The compaction continues from a pending jump.
        self.compact_up_from_pending_jump(page_set, node, compact_layers, prev_stack_top_page_id)
            .unwrap()
    }

    // Handle the compaction up through a pending jump, it can either be split or skipped completely.
    fn compact_up_from_pending_jump(
        &mut self,
        page_set: &impl PageSet,
        node: Node,
        compact_layers: &mut usize,
        prev_stack_top_page_id: PageId,
    ) -> Option<CompactDestination> {
        let (pending_jumps, parent_elision_data) = if let Some(stack_top) = self.stack.last_mut() {
            (
                &mut stack_top.pending_jumps,
                Some(&mut stack_top.elision_data),
            )
        } else {
            // UNWRAP: parent pending jumps must be present if the stack is empty.
            self.parent_data
                .as_mut()
                .map(|(_, pending_jumps)| (pending_jumps, None))
                .unwrap()
        };

        let Some(jump) = pending_jumps.get_jump_mut(&prev_stack_top_page_id, FindBy::Destination)
        else {
            return None;
        };

        // UNWRAP: A previous node is expected because this pending jump is either
        // built during reconstruction or comes from a jump page, in either case
        // a previous jump node must be present.
        let prev_node = jump.node.replace(node).unwrap();

        let jumped_layers = match pending_jumps.split_pending_jump::<H>(
            page_set,
            &prev_stack_top_page_id,
            FindBy::Destination,
            *compact_layers,
            parent_elision_data,
        ) {
            SplitJumpResult::Split {
                split_page_id,
                split_page,
                split_page_diff,
                split_page_elision_data,
                pending_jump,
                ..
            } => {
                let mut stack_page_item = StackPageItem {
                    elision_data: split_page_elision_data,
                    page_id: split_page_id,
                    page: split_page,
                    diff: split_page_diff,
                    bucket_info: None,
                    pending_jumps: PendingJumps { jumps: vec![] },
                };
                if let Some(pending_jump) = pending_jump {
                    stack_page_item.pending_jumps.jumps.push(pending_jump);
                }
                self.stack.push(stack_page_item);
                *compact_layers
            }
            SplitJumpResult::Skip(jump_len) => jump_len,
        };

        *compact_layers -= jumped_layers;
        self.position.up(jumped_layers as u16);

        if *compact_layers == 0 {
            self.sibling_stack
                .push((prev_node, self.position.depth() as usize));
            return Some(CompactDestination::SplitJump);
        }

        // Move higher than the jump start.
        self.position.up(1);
        *compact_layers -= 1;

        // If the position reached the parent page, child_page_roots needs to be updated.
        if self.position.page_id().map_or(false, |page_id| {
            self.parent_data
                .as_ref()
                .map_or(false, |(parent_page_id, _)| page_id == *parent_page_id)
        }) {
            Some(CompactDestination::ChildRoots)
        } else {
            Some(CompactDestination::Page)
        }
    }

    // read the node at the current position. panics if no current page.
    fn node(&self) -> Node {
        let node_index = self.position.node_index();
        // UNWRAP: if a node is being read, then a page in the stack must be present.
        let stack_top = self.stack.last().unwrap();
        stack_top.page.node(node_index)
    }

    // read the sibling node at the current position. panics if no current page.
    fn sibling_node(&self) -> Node {
        let node_index = self.position.sibling_index();
        // UNWRAP: if a sibling node is being read, then a page in the stack must be present.
        let stack_top = self.stack.last().unwrap();
        stack_top.page.node(node_index)
    }

    // set a node in the current page at the given index. panics if no current page.
    fn set_node(&mut self, node: Node) {
        self.dbg_text
            .push(format!("placing not at: {:?}", self.position));
        let node_index = self.position.node_index();
        let sibling_node = self.sibling_node();

        // UNWRAP: if a node is being set, then a page in the stack must be present.
        let stack_top = self.stack.last_mut().unwrap();
        stack_top.page.set_node(node_index, node);

        if self.position.is_first_layer_in_page()
            && node == TERMINATOR
            && sibling_node == TERMINATOR
        {
            stack_top.diff.set_cleared();
        } else {
            stack_top.diff.set_changed(node_index);
        }
    }

    // set the sibling node in the current page at the given index. panics if no current page.
    fn set_sibling(&mut self, node: Node) {
        let node_index = self.position.sibling_index();
        // UNWRAP: if a sibling node is being set, then a page in the stack must be present.
        let stack_top = self.stack.last_mut().unwrap();

        stack_top.page.set_node(node_index, node);
        stack_top.diff.set_changed(node_index);
    }

    fn assert_page_in_scope(&self, page_id: Option<&PageId>) {
        match page_id {
            Some(page_id) => {
                if let Some((ref parent_page, _)) = self.parent_data {
                    // If reconstructing it is ok to start reconstructing
                    // from the last layer of the parent page.
                    if !self.reconstruction {
                        assert!(&page_id != &parent_page);
                    }
                    assert!(page_id.is_descendant_of(&parent_page));
                }
            }
            None => assert!(self.parent_data.is_none()),
        }
    }

    // Build the stack to target a particular position.
    //
    // Precondition: the stack is either empty or contains an ancestor of the page ID the position
    // lands in.
    fn build_stack(&mut self, page_set: &impl PageSet, new_position: TriePosition) {
        let old_position = self.position.clone();
        self.position = new_position.clone();
        let new_page_id = self.position.page_id();
        self.assert_page_in_scope(new_page_id.as_ref());

        let Some(new_page_id) = new_page_id else {
            while !self.stack.is_empty() {
                self.handle_traversed_page(page_set);
            }
            return;
        };

        // Starting from the current old_position page id, the parent page or the root page
        // collect all pages down to the target.
        let mut page_id = match old_position.page_id() {
            Some(page_id) => page_id,
            None if self.parent_data.is_some() => {
                // UNWRAP: parent has just been checked to be Some.
                self.parent_data
                    .as_ref()
                    .map(|(parent_page, _)| parent_page.clone())
                    .unwrap()
            }
            None => {
                let (page, page_origin) = page_set.get(&ROOT_PAGE_ID).unwrap();
                let stack_item =
                    StackPageItem::new_page(ROOT_PAGE_ID.clone(), page.deep_copy(), page_origin);
                self.stack.push(stack_item);
                ROOT_PAGE_ID
            }
        };

        // The last bit of the path will be used to traverse to the last page,
        // but traversing the page tree may lead to going past the target page.
        let new_position_path = new_position.path();
        let relevant_path = &new_position_path[..new_position_path.len() - 1];

        let mut chunks_iter = relevant_path
            .chunks_exact(DEPTH)
            .skip(page_id.depth())
            .into_iter();

        while let Some(chunk) = chunks_iter.next() {
            // UNWRAP: 6 bits never overflows child page index
            let child_index = ChildPageIndex::new(chunk.load_be::<u8>()).unwrap();

            // UNWRAP: Trie position never overflows page tree.
            page_id = page_id.child_page_id(child_index).unwrap();

            // Before fetching the new page, check if the current stack top
            // has a pending jump matching the page we are looking for
            if let Some(jump_idx) = self
                .stack
                .last_mut()
                .map(|stack_top| {
                    stack_top
                        .pending_jumps
                        .find_pending_jump_mut(&page_id, FindBy::Start)
                })
                .flatten()
            {
                let curr_bit_depth = page_id.depth() * DEPTH;
                let missing_bit_path = &new_position_path[curr_bit_depth..];

                let new_page_id = self.build_stack_split_pending_jump(
                    page_set,
                    &page_id,
                    jump_idx,
                    missing_bit_path,
                );

                let n_jump_chunks = new_page_id.depth() - page_id.depth();
                for _ in 0..n_jump_chunks {
                    let _ = chunks_iter.next();
                }
                page_id = new_page_id;

                let last_item_in_stack = self.stack.last().map(|item| &item.page_id);
                assert_eq!(last_item_in_stack, Some(&page_id));

                continue;
            }

            // UNWRAP: All pages are expected to be found in cache.
            let (page, page_origin) = page_set.get(&page_id).unwrap();

            if page.jump() {
                let curr_bit_depth = page_id.depth() * DEPTH;
                let missing_bit_path = &new_position_path[curr_bit_depth..];

                page_id = self.build_stack_traverse_jump_page(
                    page_set,
                    &page,
                    &page_id,
                    page_origin,
                    missing_bit_path,
                    &mut chunks_iter,
                );
            } else {
                self.stack.push(StackPageItem::new_page(
                    page_id.clone(),
                    page.deep_copy(),
                    page_origin,
                ));
            }
        }

        // now the stack top must contains a page with the expected page_id
        let page_id = self.stack.last().map(|item| &item.page_id);
        assert_eq!(page_id, Some(&new_page_id));
    }

    // Continue building the stack by traversing the jump page, which may
    // split the jump or keep it if completely traversed. Return the reached PageId
    // and advance `chunks_iter` based on how many pages have been advanced.
    fn build_stack_traverse_jump_page<'a>(
        &mut self,
        page_set: &impl PageSet,
        jump_page: &Page,
        jump_page_id: &PageId,
        jump_page_origin: PageOrigin,
        bit_path: &BitSlice<u8, Msb0>,
        chunks_iter: &mut impl Iterator<Item = &'a BitSlice<u8, Msb0>>,
    ) -> PageId {
        let Some((_jump_node, jump_partial_path)) = jump_page.jump_data() else {
            unreachable!()
        };

        assert_eq!(jump_partial_path.len() % DEPTH, 0);

        // UNWRAP: jump_partial_path is expected to be at least 6 bits.
        let jump_destination_page_id =
            jump_page_destination(jump_page_id.clone(), &jump_partial_path).unwrap();

        let jump_idx = self.jump_page_to_pending_jump(
            jump_page,
            jump_page_id,
            &jump_destination_page_id,
            jump_page_origin,
        );

        let new_page_id =
            self.build_stack_split_pending_jump(page_set, &jump_page_id, jump_idx, bit_path);

        let n_jump_chunks = new_page_id.depth() - jump_page_id.depth();
        for _ in 0..n_jump_chunks {
            let _ = chunks_iter.next();
        }

        new_page_id
    }

    // Given a jump page and relative information, transform it into a PendingJump
    // and save it within the jump's parent page.
    //
    // Returns the index at which the jump was inserted within `PendingJumps.jumps`
    fn jump_page_to_pending_jump(
        &mut self,
        jump_page: &Page,
        jump_page_id: &PageId,
        jump_destination_page_id: &PageId,
        jump_page_origin: PageOrigin,
    ) -> usize {
        let Some((jump_node, jump_partial_path)) = jump_page.jump_data() else {
            unreachable!()
        };

        assert!(jump_page_origin
            .page_leaves_counter()
            .map_or(true, |counter| counter == 0));

        let pending_jump = PendingJump {
            start_page_id: jump_page_id.clone(),
            destination_page_id: jump_destination_page_id.clone(),
            bit_path: jump_partial_path,
            elision_data: ElisionData {
                elided_children: ElidedChildren::new(),
                page_leaves_counter: jump_page_origin.page_leaves_counter(),
                prev_children_leaves_counter: jump_page_origin.children_leaves_counter(),
                children_leaves_counter: None,
                reconstruction_diff: jump_page_origin.page_diff().cloned(),
            },
            node: Some(jump_node),
            jumped_pages: vec![],
            source: Some((
                jump_page_id.clone(),
                jump_page.deep_copy(),
                jump_page_origin.clone(),
            )),
        };

        let (parent_pending_jumps, _parent_elision_data) = match self.stack.last_mut() {
            Some(stack_top) => (
                &mut stack_top.pending_jumps,
                Some(&mut stack_top.elision_data),
            ),
            None => {
                // UNWRAP: If there are no elements within the stack,
                // parent data is expected to be present.
                (
                    self.parent_data.as_mut().map(|(_, jumps)| jumps).unwrap(),
                    None,
                )
            }
        };

        parent_pending_jumps.jumps.push(pending_jump);
        parent_pending_jumps.jumps.len() - 1
    }

    // Given a jump, specified by its index, within the pending jumps of the stack top,
    // split it at the divergence point with `bit_path`.
    //
    // Push onto the stack the new page, which could be the result of the split
    // or the destination page of the jump if there is no divergence.
    fn build_stack_split_pending_jump(
        &mut self,
        page_set: &impl PageSet,
        next_page_id: &PageId,
        jump_idx: usize,
        bit_path: &BitSlice<u8, Msb0>,
    ) -> PageId {
        // UNWRAP: The stack top has just been checked to exists.
        let stack_top = self.stack.last_mut().unwrap();
        let jump = &stack_top.pending_jumps.jumps[jump_idx];

        if let Some(divergence_bit) = divergence_bit(&jump.bit_path, bit_path) {
            let up = jump.bit_path.len() - divergence_bit;

            let SplitJumpResult::Split {
                split_page_id,
                split_page,
                split_page_diff,
                split_page_elision_data,
                pending_jump,
                ..
            } = stack_top.pending_jumps.split_pending_jump::<H>(
                page_set,
                next_page_id,
                FindBy::Start,
                up,
                Some(&mut stack_top.elision_data),
            )
            else {
                // PANIC: A jump split is expected to happen.
                unreachable!()
            };

            let mut stack_page_item = StackPageItem {
                elision_data: split_page_elision_data,
                page_id: split_page_id.clone(),
                page: split_page,
                diff: split_page_diff,
                bucket_info: None,
                pending_jumps: PendingJumps { jumps: vec![] },
            };

            if let Some(pending_jump) = pending_jump {
                stack_page_item.pending_jumps.jumps.push(pending_jump);
            }

            self.stack.push(stack_page_item);

            // UNWRAP: Split is expected to have succeeded and pushed at least one page onto the stack.
            split_page_id
        } else {
            let new_page_id = jump.destination_page_id.clone();
            let (page, page_origin) = page_set.get(&new_page_id).unwrap();
            self.stack.push(StackPageItem::new_page(
                new_page_id.clone(),
                page.deep_copy(),
                page_origin,
            ));
            new_page_id
        }
    }

    fn handle_traversed_page(&mut self, page_set: &impl PageSet) {
        // UNWRAP: Handling traversed page can only occur on top of valid pages.
        let StackPageItem {
            page_id,
            mut page,
            mut diff,
            bucket_info,
            mut elision_data,
            pending_jumps,
        } = self.stack.pop().unwrap();

        self.dbg_text
            .push(format!("handling page_id: {:?}", page_id));

        // Propagate elision data for each pending jump.
        let pending_jumps: Vec<_> = pending_jumps
            .jumps
            .into_iter()
            .map(|pending_jump| {
                self.dbg_text.push(
                    "propagating penging jump elision data, overriding parent data".to_string(),
                );
                let elided = self.propagate_elision_data(
                    Some(&mut elision_data),
                    &pending_jump.start_page_id,
                    0,
                    &pending_jump.elision_data,
                    Some(&pending_jump.destination_page_id),
                );

                (pending_jump, elided)
            })
            .collect();

        // If the stack is empty or the page is a child of the root or the parent page,
        // elision and the carrying of elided children do not occur.
        let parent_page_id = self
            .parent_data
            .as_ref()
            .map(|(page_id, _)| page_id.clone())
            .unwrap_or(ROOT_PAGE_ID);

        self.dbg_text
            .push(format!("parent_page_id {:?}", parent_page_id));

        if page_id == ROOT_PAGE_ID || page_id.parent_page_id() == parent_page_id {
            for (pending_jump, elided_pending_jump) in pending_jumps {
                self.handle_pending_jump(pending_jump, page_set, elided_pending_jump);
            }

            if page_id != ROOT_PAGE_ID {
                // Store the updated elided_children field into the page.
                page.set_elided_children(&elision_data.elided_children);
            }

            if self.reconstruction {
                self.push_reconstructed(diff, page_id, page, &elision_data);
            } else {
                self.push_updated(diff, page_id, page, bucket_info, &elision_data);
            }
            return;
        }

        let page_leaves_counter = count_leaves::<H>(&page);

        self.dbg_text
            .push("propagating elision data, not overriding anything ".to_string());
        let elided =
            self.propagate_elision_data(None, &page_id, page_leaves_counter, &elision_data, None);

        for (pending_jump, elided_pending_jump) in pending_jumps {
            self.handle_pending_jump(pending_jump, page_set, elided_pending_jump);
        }

        // Store the updated elided_children field into the page.
        page.set_elided_children(&elision_data.elided_children);

        // If `reconstruction` is true, pages do not get elided,
        // they are simply pushed as reconstructed.
        // The bitfield needs to be present so that if, during the update phase,
        // this page gets promoted to be stored on disk,
        // we don't want to recompute which child is elided.
        if self.reconstruction {
            self.push_reconstructed(diff, page_id, page, &elision_data);
            return;
        }

        // If the page was previously resident in memory we need to clear it.
        let elide_existing = elided && bucket_info.is_some();
        if elide_existing {
            diff.set_cleared();
        }

        // A page is written either if it is not elided
        // or if a previously existing page is elided.
        if elide_existing || !elided {
            self.push_updated(diff, page_id, page, bucket_info, &elision_data);
        }
    }

    // Propagate the elision data to the higher parent page,
    // returning a bool that indicates whether the page needs to be elided.
    fn propagate_elision_data(
        &mut self,
        override_parent_elision_data: Option<&mut ElisionData>,
        page_id: &PageId,
        page_leaves_counter: u64,
        elision_data: &ElisionData,
        pending_jump: Option<&PageId>,
    ) -> bool {
        // If the parent is overwritten, use it, otherwise, try to use the last
        // item in the stack, and if none is found, expect to find the parent data.
        let parent_elision_data = override_parent_elision_data.unwrap_or_else(|| {
            // UNWRAP: Either an element in the stack or the parent page must be present.
            self.stack
                .last_mut()
                .map(|stack_top| {
                    Some(stack_top.parent_elision_data_mut(
                        &page_id,
                        FindBy::Destination,
                        &mut self.dbg_text,
                    ))
                })
                .or_else(|| {
                    self.parent_data.as_mut().map(|(_, pending_jumps)| {
                        pending_jumps
                            .get_jump_mut(&page_id, FindBy::Destination)
                            .map(|p_jump| &mut p_jump.elision_data)
                    })
                })
                .flatten()
                .unwrap()
        });

        self.dbg_text
            .push(format!("propagating elision data from a {:?}", page_id));

        self.dbg_text.push(format!(
            " elision_data
            .children_leaves_counter
            .or(elision_data.prev_children_leaves_counter): {:?}",
            elision_data
                .children_leaves_counter
                .or(elision_data.prev_children_leaves_counter)
        ));

        if let Some(children_leaves_counter) = elision_data
            .children_leaves_counter
            .or(elision_data.prev_children_leaves_counter)
        {
            #[cfg(not(test))]
            let elide = page_leaves_counter + children_leaves_counter < PAGE_ELISION_THRESHOLD;
            #[cfg(test)]
            let elide = page_leaves_counter + children_leaves_counter < PAGE_ELISION_THRESHOLD
                && !self.inhibit_elision;

            if elide {
                // The total number of leaves in the subtree of this pages is lower than the threshold.

                self.dbg_text.push(format!(
                    "parent_elision_data.children_leaves_counter: {:?} ",
                    parent_elision_data.children_leaves_counter
                ));
                self.dbg_text.push(format!(
                    "parent_elision_data.prev_children_leaves_counter: {:?} ",
                    parent_elision_data.prev_children_leaves_counter
                ));
                if let Some(ref mut parent_children_leaves_counter) = parent_elision_data
                    .children_leaves_counter
                    .or(parent_elision_data.prev_children_leaves_counter)
                {
                    let prev_page_leaves_counter = elision_data.page_leaves_counter.unwrap_or(0);
                    let page_delta = page_leaves_counter as i64 - prev_page_leaves_counter as i64;

                    let prev_children_leaves_counter =
                        elision_data.prev_children_leaves_counter.unwrap();
                    let children_delta =
                        children_leaves_counter as i64 - prev_children_leaves_counter as i64;

                    let new_parent_children_leaves_counter =
                        *parent_children_leaves_counter as i64 + page_delta + children_delta;

                    self.dbg_text
                        .push("upated parent children leaves".to_string());
                    self.dbg_text.push(format!(
                        "parent_children_leaves_counter: {}",
                        parent_children_leaves_counter
                    ));
                    self.dbg_text.push(format!("page_delta: {}", page_delta));
                    self.dbg_text
                        .push(format!("children_delta: {}", children_delta));
                    self.dbg_text.push(format!(
                        "new_parent_children_leaves_counter: {}",
                        new_parent_children_leaves_counter
                    ));

                    // UNWRAP: page_delta and children_delta, if negative, will always be smaller than
                    // parent_children_leaves_counter. More leaves that what was previously present
                    // cannot be removed.
                    parent_elision_data
                        .children_leaves_counter
                        .replace(new_parent_children_leaves_counter.try_into().unwrap());
                }

                // Elide current page from parent.
                // This will never underflow because page_id.depth() would be 0
                // only if page_id is the root and it cannot happen because the stack
                // would have been empty if the last stack item pop was the root.
                let child_index = page_id.child_index_at_level(page_id.depth() - 1);
                parent_elision_data
                    .elided_children
                    .set_elide(child_index.clone(), true);
                self.dbg_text.push(format!(
                    "setting parent elided children index: {:?}",
                    child_index.to_u8()
                ));
                return true;
            }
        }

        // If either `children_leaves_counter` and its previous value were already `None`
        // or the total number of leaves exceeded the threshold, this needs to be propagated.
        // UNWRAP: The stack has beed checked to not being empty.
        parent_elision_data.children_leaves_counter = None;
        parent_elision_data.prev_children_leaves_counter = None;
        self.dbg_text
            .push("ereased parent children counter data".to_string());

        // Special case of pending jump handling: if `pending_jump` is specified,
        // it contains the jump destination, which indicates whether the current page
        // should be elided or not. Jump pages only have one possible child and do not
        // introduce any leaves, thus, if pending jump elision data is being propagated
        // and the only child is being elided, then the parent jump page will also be elided.
        if let Some(pending_jump_destination) = pending_jump {
            let child_page_index =
                pending_jump_destination.child_index_at_level(pending_jump_destination.depth() - 1);

            if elision_data.elided_children.is_elided(child_page_index) {
                let child_index = page_id.child_index_at_level(page_id.depth() - 1);
                parent_elision_data
                    .elided_children
                    .set_elide(child_index.clone(), true);
                return true;
            }
        }

        // Toggle as not elide the current page from the parent page.
        // It does not overflow for the same reason as above.
        let child_index = page_id.child_index_at_level(page_id.depth() - 1);
        parent_elision_data
            .elided_children
            .set_elide(child_index.clone(), false);

        false
    }

    fn push_reconstructed(
        &mut self,
        diff: PageDiff,
        page_id: PageId,
        page: PageMut,
        elision_data: &ElisionData,
    ) {
        self.output_pages
            .push(PageWalkerPageOutput::Reconstructed(ReconstructedPage {
                diff: elision_data
                    .reconstruction_diff
                    .as_ref()
                    .map(|reconstruction_diff| reconstruction_diff.join(&diff))
                    .unwrap_or(diff),
                page_id,
                page,
                // UNWRAPs: If the page is being reconstructed, it must have its
                // children_leaves_counter updated by a child page or from a previous
                // children_leaves_counter state.
                children_leaves_counter: elision_data
                    .children_leaves_counter
                    .unwrap_or(elision_data.prev_children_leaves_counter.unwrap()),
            }));
    }

    fn push_updated(
        &mut self,
        diff: PageDiff,
        page_id: PageId,
        page: PageMut,
        bucket_info: Option<BucketInfo>,
        elision_data: &ElisionData,
    ) {
        let diff = elision_data
            .reconstruction_diff
            .as_ref()
            .map(|reconstruction_diff| reconstruction_diff.join(&diff))
            .unwrap_or(diff);

        // If the page is either fresh or has been reconstructed and cleared,
        // it doesn't need to be pushed as a page to be cleared.
        if diff.cleared() && bucket_info.is_none() {
            return;
        }

        self.output_pages
            .push(PageWalkerPageOutput::Updated(UpdatedPage {
                diff,
                page_id,
                page,
                bucket_info: bucket_info.unwrap_or(BucketInfo::Fresh),
            }));
    }

    // Handle the pending jump, either unfolding it into standard pages
    // or using a jump page.
    //
    // Returns whether the first unfolded page or the jump page has been elided.
    fn handle_pending_jump(
        &mut self,
        mut pending_jump: PendingJump,
        page_set: &impl PageSet,
        elided_pending_jump: bool,
    ) {
        let push_cleared_page = |page_walker: &mut PageWalker<H>, page, page_id, bucket_info| {
            let mut diff = PageDiff::default();
            diff.set_cleared();

            page_walker.push_updated(
                diff,
                page_id,
                page,
                bucket_info,
                &ElisionData {
                    page_leaves_counter: None,
                    prev_children_leaves_counter: None,
                    children_leaves_counter: None,
                    elided_children: ElidedChildren::new(),
                    reconstruction_diff: None,
                },
            );
        };

        // UNWRAP: if a jump is being handled, it means that it was stepped over
        // and thus consolidated with an associated node.
        let node = pending_jump.node.unwrap();

        // If the node within a pending node is not an internal node than the
        // jump can be considered as cleared.
        if !trie::is_internal::<H>(&node) {
            if let Some((page_id, page, page_origin)) = pending_jump.source {
                push_cleared_page(self, page, page_id, page_origin.bucket_info());
            }
            return;
        }

        // Pages in the first two layers are neither elided
        // nor accepted to be jump pages.
        if pending_jump.start_page_id.depth() == 1 {
            let (page_id, page, page_diff, bucket_info, elision_data, shorter_pending_jump) =
                pending_jump.shorten_top(page_set, elided_pending_jump);

            pending_jump = shorter_pending_jump;

            if self.reconstruction {
                self.push_reconstructed(page_diff, page_id, page, &elision_data);
            } else {
                self.push_updated(page_diff, page_id, page, bucket_info, &elision_data);
            }
        }

        assert!(pending_jump.bit_path.len() % DEPTH == 0);

        let source_data = if let Some((
            prev_jump_page_id,
            jump_page_origin,
            Some((prev_jump_node, prev_partial_path)),
            prev_jump_page,
        )) = pending_jump
            .source
            .map(|(page_id, page, page_origin)| (page_id, page_origin, page.jump_data(), page))
        {
            assert_eq!(pending_jump.start_page_id, prev_jump_page_id);

            if elided_pending_jump && !self.reconstruction {
                let maybe_bucket_info = jump_page_origin.clone().bucket_info();
                if maybe_bucket_info.is_some() {
                    push_cleared_page(
                        self,
                        prev_jump_page,
                        prev_jump_page_id,
                        jump_page_origin.bucket_info(),
                    );
                }
                return;
            }

            let changed_node = prev_jump_node != node;
            let changed_bit_path = prev_partial_path != pending_jump.bit_path;

            // If nothing has changed, the jump page remains as is.
            if !changed_node && !changed_bit_path {
                return;
            } else {
                Some((prev_jump_node, prev_partial_path, jump_page_origin))
            }
        } else {
            // If there is no source, the jump is being elided and it is not being reconstructed
            // there is nothing to handle.
            if elided_pending_jump && !self.reconstruction {
                return;
            }
            None
        };

        // Push as cleared each jumped page.
        for (page_id, page, bucket_info) in pending_jump.jumped_pages {
            assert!(!self.reconstruction);
            push_cleared_page(self, page, page_id, bucket_info);
        }

        // There are two main scenarios: when a pending jump becomes a proper
        // jump page, or when it becomes a collection of pages made only of transparent hashes.
        const JUMP_PAGE_THRESHOLD: usize = 12;
        if pending_jump.bit_path.len() < JUMP_PAGE_THRESHOLD {
            let mut page_id = pending_jump.start_page_id.clone();
            let last_unpacked_page_id = pending_jump.destination_page_id.parent_page_id();

            for chunk in pending_jump.bit_path.chunks_exact(DEPTH) {
                let mut page = page_set.fresh();
                let mut diff = match &source_data {
                    Some((_, jump_partial_path, _)) if page_id == pending_jump.start_page_id => {
                        // If the previous jump page is being consolidated, its page diff should
                        // also contain every clearance of the jump data. But wihout the jump bit.
                        PageDiff::from_jump_page(jump_partial_path.len())
                    }
                    _ => PageDiff::default(),
                };

                fill_transparent_hash_page(
                    &mut page, &mut diff, node, 0, true, /*jump*/
                    chunk,
                );

                // UNWRAP: 6 bits never overflows child page index
                let child_index = ChildPageIndex::new(chunk.load_be::<u8>()).unwrap();

                // All pages from the first to the second-to-last one will elide the child
                // if the pending jump itself is being elided. The last unpacked page
                // will store the elided children data of the pending jump.
                let mut elided_children = ElidedChildren::new();
                if page_id == last_unpacked_page_id {
                    elided_children = pending_jump.elision_data.elided_children.clone();
                } else if elided_pending_jump {
                    elided_children.set_elide(child_index.clone(), true);
                };
                page.set_elided_children(&elided_children);

                let elision_data = ElisionData {
                    page_leaves_counter: Some(0),
                    prev_children_leaves_counter: Some(0),
                    children_leaves_counter: pending_jump.elision_data.children_leaves_counter,
                    elided_children,
                    reconstruction_diff: None,
                };

                if self.reconstruction {
                    self.push_reconstructed(diff, page_id.clone(), page, &elision_data);
                } else {
                    let bucket_info = source_data
                        .as_ref()
                        .map(|(_, _, page_origin)| page_origin.clone().bucket_info())
                        .flatten();
                    self.push_updated(diff, page_id.clone(), page, bucket_info, &elision_data);
                }

                // UNWRAP: trie position never overflows page tree.
                page_id = page_id.child_page_id(child_index).unwrap();
            }

            return;
        }

        // Create the jump page
        let mut page = page_set.fresh();

        let mut diff = PageDiff::from_jump_page(pending_jump.bit_path.len());
        diff.set_jump();
        page.tag_jump_page(node, pending_jump.bit_path);

        if self.reconstruction {
            self.push_reconstructed(
                diff,
                pending_jump.start_page_id,
                page,
                &pending_jump.elision_data,
            );
        } else {
            let bucket_info = source_data
                .map(|(_, _, page_origin)| page_origin.bucket_info())
                .flatten();
            self.push_updated(
                diff,
                pending_jump.start_page_id,
                page,
                bucket_info,
                &pending_jump.elision_data,
            );
        }
    }
}

/// Count the number of leaves present *only* in the provided page,
/// without jumping into child pages.
fn count_leaves<H: NodeHasher>(page: &PageMut) -> u64 {
    // A simpler linear scan cannot be done because the page could contain some garbage.
    let mut counter = 0;

    // We just need the node indexes within a page,
    // so we treat this as the root page starting from the root position.
    let mut pos = TriePosition::new();
    let initial_depth = pos.depth();
    pos.down(false);

    loop {
        let node = page.node(pos.node_index());
        // Continue to traverse the left child if the current node is internal,
        // stop if we reach the end of the page.
        if trie::is_internal::<H>(&node) && pos.depth_in_page() != DEPTH {
            pos.down(false);
            continue;
        }

        if trie::is_leaf::<H>(&node) || trie::is_collision_leaf::<H>(&node) {
            counter += 1;
        }

        // Going up until I reach a leaf sibling or the node I started from.
        while pos.depth() != initial_depth && pos.peek_last_bit() {
            pos.up(1);
        }

        if pos.depth() == initial_depth {
            break;
        }

        pos.sibling();
    }
    counter
}

// Starting from the bottom follow the path placing:
// + `node` or `terminator` in each position up to destination
//   `node` if jump is true, otherwise `terminator`
// + place `node` at the destination position
// + continue to follow the path placing terminators
//
// All siblings of each placed node will be terminators.
fn fill_transparent_hash_page(
    page: &mut PageMut,
    page_diff: &mut PageDiff,
    node: Node,
    destination: usize,
    jump: bool,
    bit_path: &BitSlice<u8, Msb0>,
) {
    assert_eq!(bit_path.len(), 6);
    let mut pos = TriePosition::from_bitslice(bit_path);
    for depth_in_page in (1..=DEPTH).rev() {
        let node_index = pos.node_index();
        let sibling_index = pos.sibling_index();

        let node_to_write = if depth_in_page > destination {
            if jump {
                node
            } else {
                trie::TERMINATOR
            }
        } else if depth_in_page == destination {
            node
        } else {
            trie::TERMINATOR
        };

        page.set_node(node_index, node_to_write);
        page.set_node(sibling_index, trie::TERMINATOR);
        page_diff.set_changed(node_index);
        page_diff.set_changed(sibling_index);

        pos.up(1);
    }
}

fn traverse_transparent_hash_page(page: &PageMut, expected_node: Node) -> Option<BitVec<u8, Msb0>> {
    // Starting from the beginning of the page traverse it collecting the bitpath
    // expecting only terminators and one type of node.

    // We just need the node indexes within a page,
    // so we treat this as the root page starting from the root position.
    let mut pos = TriePosition::new();
    pos.down(false);

    let mut bit_path = BitVec::new();
    while pos.depth() <= DEPTH as u16 {
        let node = page.node(pos.node_index());
        let sibling_node = page.node(pos.sibling_index());

        if node == expected_node {
            // The left sibling is the expected node, the right must be a terminator;
            if sibling_node != trie::TERMINATOR {
                return None;
            }
        } else if sibling_node == expected_node {
            // The right sibling is the expected node, the left must be a terminator;
            if node != trie::TERMINATOR {
                return None;
            }

            pos.up(1);
            pos.down(true);
        } else {
            return None;
        }

        bit_path.push(pos.peek_last_bit());
        pos.down(false);
    }
    assert_eq!(bit_path.len(), DEPTH as usize);
    Some(bit_path)
}

/// Reconstruct the elided pages using all the key-value pairs present in the elided subtree.
/// Reconstruction requires the page and its page_id, where the elided child page was found,
/// as well as the `TriePosition` within that page.
///
///
/// Returns None if the pages that should be reconstructed are already in the `PageSet`,
/// otherwise an iterator over the following items: the reconstructed page, its page_id,
/// the PageDiff indicating all nodes effectively reconstructed within the page
/// and a counter of leaves in the page and its subtrees.
pub fn reconstruct_pages<H: nomt_core::hasher::NodeHasher>(
    page: &Page,
    page_id: PageId,
    position: TriePosition,
    page_set: &mut impl PageSet,
    ops: impl IntoIterator<Item = (KeyPath, ValueHash)>,
) -> Option<impl Iterator<Item = (PageId, Page, PageDiff, u64, u64)>> {
    let subtree_root = if let Some((jump_node, _)) = page.jump_data() {
        jump_node
    } else {
        page.node(position.node_index())
    };

    let mut page_walker = PageWalker::<H>::new_reconstructor(subtree_root, page_id.clone());

    page_walker
        .dbg_text
        .push(format!("reconstructing from: {:?}", page_id));

    let (root, reconstructed_pages) = page_walker.reconstruct(page_set, position, ops)?;

    assert_eq!(root, subtree_root);

    Some(reconstructed_pages.into_iter().map(|reconstructed_page| {
        let page_leaves_counter = if reconstructed_page.page.jump() {
            0
        } else {
            count_leaves::<H>(&reconstructed_page.page)
        };

        (
            reconstructed_page.page_id,
            reconstructed_page.page.freeze(),
            reconstructed_page.diff,
            page_leaves_counter,
            reconstructed_page.children_leaves_counter,
        )
    }))
}
