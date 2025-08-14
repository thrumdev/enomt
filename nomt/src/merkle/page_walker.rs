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

use bitvec::prelude::*;
use libc::getpriority;
use nomt_core::{
    hasher::NodeHasher,
    page::DEPTH,
    page_id::{ChildPageIndex, PageId, ROOT_PAGE_ID},
    trie::{self, InternalData, KeyPath, Node, NodeKind, ValueHash, TERMINATOR},
    trie_pos::{sibling_index, TriePosition},
    update::WriteNode,
};

use crate::{
    merkle::{page_set::PageOrigin, BucketInfo, ElidedChildren, PAGE_ELISION_THRESHOLD},
    page_cache::{Page, PageMut, JUMP_NODE_RANGE},
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
pub struct ReconstructedPage {
    /// The ID of the page.
    pub page_id: PageId,
    /// An owned copy of the page, including the modified nodes.
    pub page: PageMut,
    /// Number of leaves present in the child pages of the page.
    pub children_leaves_counter: u64,
    /// A compact diff indicating all reconstructed slots in the page.
    pub diff: PageDiff,
}

// TODO: This will be used by:
// 1. While handling a traversed page, it could have an associated
//   pending jump, implying the creation of a jump page
// 2. While compacting up a pending jump could be made longer if the
//    sibling of where the pending jump starts from is eliminated
struct PendingJump {
    /// Where the jump starts within the trie.
    start: TriePosition,
    /// Where the jump arrives within the trie.
    destination: TriePosition,
    /// The branch node.
    node: Node,
    /// The PageId of the jump page.
    page_id: PageId,
    /// A carry of the elision data brought
    /// from the first proper page after the jumped one.
    elision_data: ElisionData,
    /// The pages that are jumped and thus cleared.
    jumped_pages: Vec<(PageId, PageMut, BucketInfo)>,
}

/// An item that currently stays in the stack of the page walker.
enum StackPageItem {
    /// A page which has being created by the page walker or which was
    /// fetched from disk.
    Page {
        /// Data required to handle the page on disk.
        data: StackPageData,
        /// Data required to handle page elision.
        elision_data: ElisionData,
        /// Flag used to specify if a jump ended within this page and
        /// it could continue from here
        maybe_jump: Option<PendingJump>,
    },
    /// A pending page which is waiting to be consolidate and become
    /// a proper page or to be part of a jump page. They can be created by
    /// unpacking a jump page or while seeking down the trie to build new
    /// subtrees.
    Pending {
        /// The ID of the pending page.
        page_id: PageId,
        /// Data required to handle page elision.
        elision_data: ElisionData,
        /// Pending node and its node index, they could be stored within
        /// the page upon consolidation or used as jump node.
        pending_node: Option<(Node, usize)>,
    },
}

struct StackPageData {
    /// The ID of the page.
    page_id: PageId,
    /// An owned copy of the page, including the modified nodes.
    page: PageMut,
    /// A compact diff indicating all modified slots in the page.
    diff: PageDiff,
    /// The bucket info associated with the page.
    /// It can be None if the page was reconstructed or just consolidated.
    bucket_info: Option<BucketInfo>,
}

impl StackPageItem {
    fn new_page(page_id: PageId, page: PageMut, page_origin: PageOrigin) -> Self {
        StackPageItem::Page {
            elision_data: ElisionData {
                elided_children: page.elided_children(),
                page_leaves_counter: page_origin.page_leaves_counter(),
                prev_children_leaves_counter: page_origin.children_leaves_counter(),
                children_leaves_counter: None,
                reconstruction_diff: page_origin.page_diff().cloned(),
            },
            data: StackPageData {
                page_id,
                page,
                diff: PageDiff::default(),
                bucket_info: page_origin.bucket_info(),
            },
            maybe_jump: None,
        }
    }

    fn new_pending(page_id: PageId) -> Self {
        StackPageItem::Pending {
            page_id,
            elision_data: ElisionData {
                elided_children: ElidedChildren::new(),
                page_leaves_counter: Some(0),
                prev_children_leaves_counter: Some(0),
                children_leaves_counter: Some(0),
                reconstruction_diff: None,
            },
            pending_node: None,
        }
    }

    fn page_id(&self) -> &PageId {
        match self {
            StackPageItem::Page {
                data: StackPageData { page_id, .. },
                ..
            } => page_id,
            StackPageItem::Pending { page_id, .. } => page_id,
        }
    }

    fn elision_data_mut(&mut self) -> &mut ElisionData {
        match self {
            StackPageItem::Page { elision_data, .. } => elision_data,
            StackPageItem::Pending { elision_data, .. } => elision_data,
        }
    }

    fn page_data(self) -> Option<(StackPageData, ElisionData, Option<PendingJump>)> {
        match self {
            StackPageItem::Page {
                data,
                elision_data,
                maybe_jump,
            } => Some((data, elision_data, maybe_jump)),
            _ => None,
        }
    }

    fn pending_data(self) -> Option<(PageId, ElisionData)> {
        match self {
            StackPageItem::Pending {
                page_id,
                elision_data,
                ..
            } => Some((page_id, elision_data)),
            _ => None,
        }
    }

    fn page_data_ref(&self) -> Option<(&StackPageData, &ElisionData, Option<&PendingJump>)> {
        match self {
            StackPageItem::Page {
                data,
                elision_data,
                maybe_jump,
            } => Some((data, elision_data, maybe_jump.as_ref())),
            _ => None,
        }
    }

    fn page_data_mut(
        &mut self,
    ) -> Option<(
        &mut StackPageData,
        &mut ElisionData,
        &mut Option<PendingJump>,
    )> {
        match self {
            StackPageItem::Page {
                data,
                elision_data,
                maybe_jump,
            } => Some((data, elision_data, maybe_jump)),
            _ => None,
        }
    }

    fn consolidate(&mut self, page_set: &impl PageSet) {
        match self {
            StackPageItem::Pending {
                page_id,
                elision_data,
                pending_node,
            } => {
                // Consolidating a pening page.
                let mut page = page_set.fresh();
                let mut diff = PageDiff::default();

                // Set the pending node.
                if let Some((node, node_index)) = pending_node.take() {
                    let sibling_index = sibling_index(node_index);
                    page.set_node(node_index, node);
                    page.set_node(sibling_index, trie::TERMINATOR);
                    diff.set_changed(node_index);
                    diff.set_changed(sibling_index);
                }

                *self = StackPageItem::Page {
                    data: StackPageData {
                        page_id: page_id.clone(),
                        page,
                        diff,
                        bucket_info: None,
                    },
                    elision_data: elision_data.clone(),
                    maybe_jump: None,
                };
            }
            // Do nothing if a page is already consolidated.
            _ => (),
        }
    }
}

impl StackPageData {
    /// Join both diffs associated with the reconstruction phase and
    /// those involved in the update process.
    fn total_diff(&self, elision_data: &ElisionData) -> PageDiff {
        elision_data
            .reconstruction_diff
            .as_ref()
            .map(|reconstruction_diff| reconstruction_diff.join(&self.diff))
            .unwrap_or(self.diff.clone())
    }
}

/// It contains all the data required to respect the [`PAGE_ELISION_THRESHOLD`].
#[derive(Clone)]
struct ElisionData {
    /// Store the number of leaves contained within the page. There must be at least two.
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

/// Left-to-right updating walker over the page tree.
pub struct PageWalker<H> {
    // last position `advance` was invoked with.
    last_position: Option<TriePosition>,
    // actual position
    position: TriePosition,
    parent_page: Option<PageId>,
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
            parent_page,
            child_page_roots: Vec::new(),
            root,
            output_pages: Vec::new(),
            stack: Vec::new(),
            sibling_stack: Vec::new(),
            prev_node: None,
            _marker: std::marker::PhantomData,
            reconstruction,
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
            self.node()
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
        let ops: Vec<_> = ops.into_iter().collect();

        // replace sub-trie at the given position
        nomt_core::update::build_trie::<H>(self.position.depth() as usize, ops, |control| {
            let node = control.node();
            let up = control.up();
            let mut down = control.down();
            let jump = control.jump();

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

            // avoid popping pages off the stack if we are jumping to a sibling.
            if up && !down.is_empty() {
                if down[0] == !self.position.peek_last_bit() {
                    // UNWRAP: checked above
                    self.position.sibling();
                    down = &down[1..];
                } else {
                    self.up(page_set);
                }
            } else if up {
                self.up(page_set)
            }

            let fresh = self.position.depth() > start_position.depth();

            if !fresh && !down.is_empty() {
                // first bit is only fresh if we are at the start position and the start is at the
                // end of its page (or at the root). after that, definitely is.
                self.down(
                    page_set,
                    &down[..1],
                    self.position.depth_in_page() == DEPTH || self.position.is_root(),
                );
                self.down(page_set, &down[1..], true);
            } else {
                self.down(page_set, &down, true);
            }

            if self.position.is_root() {
                self.root = node;
            } else {
                self.set_node(node);
                self.jump(jump, page_set);
            }
        });
        assert_eq!(self.position, start_position);

        // build_trie should always return us to the original position.
        if !self.position.is_root() {
            assert_eq!(
                self.stack.last().unwrap().page_id(),
                &self.position.page_id().unwrap()
            );
        } else {
            assert!(self.stack.is_empty());
        }
    }

    // Move the current position up.
    fn up(&mut self, page_set: &impl PageSet) {
        // Handle the popped stack top.
        if self.position.depth_in_page() == 1 {
            let Some(stack_page) = self.stack.pop() else {
                // Nothing to handle.
                return;
            };

            // UNWRAP: Only consolidated pages are expected at the top of the stack.
            let (data, elision_data, maybe_jump) = stack_page.page_data().unwrap();
            self.handle_traversed_page(data, elision_data, maybe_jump, page_set);
        }

        self.position.up(1);
    }

    // Starting from pos and going up by the specified amount performing
    // transparent hashes, thus copying the branch node from which it started.
    //
    // Make sure to jump pages if more than two sequential pages are created
    // only by a transparent hash chain. Jumps do not introduce any new leaves,
    // thus, elision data will simply be carried to higher pages, and the funcion
    // will take care of savign jump pages and consolidating pages if needed.
    fn jump(&mut self, mut up: usize, page_set: &impl PageSet) {
        dbg!(&self.position);
        dbg!(self.stack.len());
        // If jump not required the current page could be
        // a pending page and thus must be consolidated.
        if up == 0 {
            // UNWRAP: jump cannot be called on top of the root.
            let stack_top = self.stack.last_mut().unwrap();
            stack_top.consolidate(page_set);
            return;
        }

        let jump_to_root = up == self.position.depth() as usize;

        // The last step will not need a terminator sibling but just
        // to set the branch node at the destination position.

        // TODO: postpone this until we are sure that the root
        // page will contain the last node, or the root will.
        up -= 1;

        // The jump can be divided into four steps:
        // 1. Performing the hash up within the current page up to the first layer
        // 2. Possibly creating jump pages if more than two were skipped
        // 3. Performing the hash up within the destination page of the jump
        // 3.1. If the destination is a pending page, it will be consolidated because
        //      if the jump stopped there, it means that in the sibling subtree
        //      of the destination, something different from a terminator node will be stored
        // 3.2. If the destination is an already consolidated page, let's save the
        //      information realted to the jump because from the destinatoin position
        //      it could continue upwords, assuming the sibling subtree of the destination
        //      is completely deleted.
        // 4. Setting the last node, the start of the transparent hash.

        // Step 1, transparent hash up within the current page.
        let node;

        // The jump stars from the last written node, which was written by the control
        // function within the build_trie. The jump could start from:
        // a proper page, where the node can be easily read, or from a pending page.
        //
        // In the first step, the possibilities are:
        // 1. The jump starts from a page and ends within the same page
        // 2. The jump starts from a page but ends on higher pages
        // 3. The jump starts from a pending page
        match self.stack.last() {
            Some(StackPageItem::Page { .. }) => {
                node = self.node();
                let layer_in_page = self.position.depth_in_page() - 1;

                // The sibling of the current position needs to be set before
                // performing the first step of transparent hash up.
                self.set_sibling(trie::TERMINATOR);

                let hash_up_layers = std::cmp::min(up, layer_in_page);
                self.transparent_hash_up(node, hash_up_layers);
                up -= hash_up_layers;

                if up == 0 && self.position.depth_in_page() != 1 {
                    // First step, case 1, the transparent hash up
                    // ends within the same page.
                    self.position.up(1);
                    self.set_node(node);
                    return;
                }

                // First step, case 2
            }
            Some(StackPageItem::Pending {
                pending_node: Some((pending_node, node_index)),
                ..
            }) if self.position.node_index() == *node_index => {
                // First step, case 3, this pending page could be jumped
                // or consolidated later on.
                node = *pending_node;
                println!("first step case 3");
            }
            // PANIC: a jump can only occur from a page or a pending page where the
            // pending node was positioned in the current position.
            _ => unreachable!(),
        }

        // Step two, check if the jump is large enough to cover more than two entire
        // pages, if so, they will be compressed into one unique jump page.
        // This step could have multiple scenarios:
        // 1. The amount of covered pages is greater than two, thus, they will become
        //    a single jump page, and the page elision data will be properly carried to the top page
        // 2. Only one page is covered, thus, this page will be consolidated and filled with
        //    the transparent hash up.
        // 3. No pages are covered, leaving the job of filling the last page to the third step
        let covered_pages = if !jump_to_root {
            dbg!(up) / 6
        } else {
            // if we are jumping to the root we want to make sure that the root
            // page will be part of the jump.
            (up + 1) / 6
        };

        let mut pending_jump = None;

        if dbg!(covered_pages) >= 2 {
            // Step two, case 1, this again splits into two different possibilities,
            // which depend on what the current position is pointing at after the first step:
            //
            // 1. The position could still be on the first layer of the page that will
            //    be pop to continue the transparent hash on the parent page.
            //    This allow to easily have a jump page which points direclty to current position.
            //
            // 2. The first step could have been skip being on top of pending page,
            //    thus the jump page will not point directly to one of the first two child
            //    of a page but to their parent.
            //
            // Both cases though results in the same logic to be applied, it just needs to be
            // known to be able to properly traverse the trie later.

            let mut covered_layers = 0;
            // If case 1, the position is still in the first layer of the current page,
            // which needs to be popped and handled.
            dbg!(&self.position);
            dbg!(self.stack.len());
            if self.position.is_first_layer_in_page() {
                println!("Popping from step two case 1, first layer in page");
                // UNWRAP :TODO
                let stack_top = self.stack.pop().unwrap();
                let (data, elision_data, maybe_jump) = stack_top.page_data().unwrap();
                self.handle_traversed_page(data, elision_data, maybe_jump, page_set);
                covered_layers += 1;
            }

            assert!(covered_pages <= dbg!(self.stack.len()));

            // UNWRAPs: each covered page is expected to be present in the stack
            // and to be a Pending page.
            println!("Popping from step two case 1, first page");
            let (_, first_elision_data) = self.stack.pop().unwrap().pending_data().unwrap();

            let covered_pages_range = self.stack.len() + 2 - covered_pages..self.stack.len();
            println!(
                "Popping from step two case 1, pages: {}",
                covered_pages_range.len()
            );
            self.stack.drain(covered_pages_range);

            println!("Popping from step two case 1, last page");
            let (last_page_id, _) = self.stack.pop().unwrap().pending_data().unwrap();

            // One layers is already being added if the position started
            // from the first layer of the previous page. Now we need to add
            // 6 layers per covered pages but minus one because the final
            // position must be the first layer of the first jumped page.
            covered_layers += covered_pages as u16 * DEPTH as u16;
            covered_layers -= 1;

            // The destination and start positions of the jump.
            let destination_pos = self.position.clone();
            let mut start_pos = destination_pos.clone();
            // The starting position of the jump will be not on the first layer
            // of the first jumped page but on the last layer of the parent page.
            start_pos.up(covered_layers + 1);

            pending_jump = Some(PendingJump {
                start: dbg!(start_pos),
                destination: dbg!(destination_pos),
                node,
                page_id: dbg!(last_page_id),
                elision_data: first_elision_data,
                jumped_pages: vec![],
            });

            self.position.up(covered_layers);
            up -= covered_layers as usize;

            assert!(self.position.is_first_layer_in_page());
        } else if covered_pages == 1 {
            // Step two, case 2

            // NOTE: the position after the first step could still be on the first
            // layer of the page, which will be popped to continue the transparent hash
            // on the parent page. Alternatively, the first step could have been
            // skipped if it is on top of the pending page, thus requiring less than
            // DEPTH hash up, as the position is already at the last layer of the
            // page that will be consolidated
            let hash_up_layers;
            if self.position.is_first_layer_in_page() {
                // UNWRAP: TODO
                let stack_top = self.stack.pop().unwrap();
                let (data, elision_data, maybe_jump) = stack_top.page_data().unwrap();
                self.handle_traversed_page(data, elision_data, maybe_jump, page_set);
                hash_up_layers = DEPTH;
            } else {
                assert_eq!(self.position.depth_in_page(), DEPTH);
                hash_up_layers = DEPTH - 1;
            }

            // UNWRAP: the covered is expected to be present in the stack.
            let stack_top = self.stack.last_mut().unwrap();
            stack_top.consolidate(page_set);

            self.transparent_hash_up(node, hash_up_layers);
            up -= hash_up_layers;

            assert!(self.position.is_first_layer_in_page());
        } else {
            // Step two, case 3. No pages covered, consolidate possible pending page.
            // UNWRAP: A page for the jump destination is expected to exist.
            let stack_top = self.stack.last_mut().unwrap();
            stack_top.consolidate(page_set);
        }

        // Step three is the same as step one, just performed on the destinaton
        // page instead of the starting page.
        // Currently, the position could either be on the first layer of the page that
        // stills needs to be pop or it is already on the last layer of the next page.
        // From here, the possibilities are:
        // 1. The destination page is a proper page, it must be filled with the
        // transparent hash up, up to the destination position, while saving the pending
        // jump that could be made longer.
        // 2. If the destination page is pending, it needs to be consolidated and then
        // the same as case 1.
        let hash_up_layers = up;

        // Possibly pop the top page of the stack if the position is on the last
        // layer of the page but if there is no pending jump, if so the pop already
        // happened.
        if self.position.is_first_layer_in_page() && pending_jump.is_none() {
            // UNWRAP: if there is no pending jump there will always
            // at least be the the root page becase without jump the last
            // page has been filled with transparent hash up and not it needs
            // to be pop.
            let stack_top = self.stack.pop().unwrap();
            let (data, elision_data, maybe_jump) = stack_top.page_data().unwrap();
            self.handle_traversed_page(data, elision_data, maybe_jump, page_set);
        }

        if self.position.depth() == 1 {
            // Special case of jump starting from the root node.
            assert_eq!(hash_up_layers, 0);
            if let Some(pending_jump) = pending_jump {
                self.handle_pending_jump(Some(pending_jump), page_set);
            }
            self.position.up(1);
            self.root = node;
            return;
        }

        // UNWRAP: the page jump destination is expected to exists.
        let stack_top = self.stack.last_mut().unwrap();
        stack_top.consolidate(page_set);

        if let Some(pending_jump) = pending_jump {
            // UNWRAP: the page has just been consolidated.
            let (_, _, page_pending_jump) = stack_top.page_data_mut().unwrap();
            *page_pending_jump = Some(pending_jump);
        }

        self.transparent_hash_up(node, dbg!(hash_up_layers));

        // Possibly pop the last page from the stack if the third step hash up reached
        // the first layer of the page, consolidate the next one.
        // Do so only if there was actually an hash up, otherwise the page has already
        // been popped.
        if self.position.is_first_layer_in_page() && hash_up_layers != 0 {
            // UNWRAPs: TODO
            let stack_top = self.stack.pop().unwrap();
            let (data, elision_data, maybe_jump) = stack_top.page_data().unwrap();
            self.handle_traversed_page(data, elision_data, maybe_jump, page_set);

            let stack_top = self.stack.last_mut().unwrap();
            stack_top.consolidate(page_set);
        }

        self.position.up(1);
        self.set_node(node);

        // Placing last node withtout sibling

        // OLD:

        //// Early return if the third step does not require any hash up.
        //if hash_up_layers == 0 {
        //// TODO: what about pending jumps here
        //self.position.up(1);
        //if self.position.is_root() {
        //println!("enter here right?");
        //self.root = node;
        //} else {
        //// UNWRAP: the page where to place the last node is expected to exists.
        //let stack_top = self.stack.last_mut().unwrap();
        //stack_top.consolidate(page_set);
        //self.set_node(node)
        //}
        //return;
        //}
        //
        //// UNWRAP: root not reached thus pages are expected in the stack.
        //let stack_top = self.stack.last_mut().unwrap();
        //stack_top.consolidate(page_set);
        //
        //if let Some(pending_jump) = pending_jump {
        //// UNWRAP: the page has just been consolidated.
        //let (_, _, page_pending_jump) = stack_top.page_data_mut().unwrap();
        //*page_pending_jump = Some(pending_jump);
        //}
        //
        //self.transparent_hash_up(node, hash_up_layers);
        //
        //// Special case of storing the last node in the new page and possibly within the root,
        //// or store it in the current last page.
        //if self.position.is_first_layer_in_page() {
        //self.position.up(1);
        //
        //// UNWRAP: root not reached thus pages are expected in the stack.
        //println!("Popping after step three, first_layer_in_page");
        //let stack_top = self.stack.pop().unwrap();
        //let (data, elision_data, maybe_jump) = stack_top.page_data().unwrap();
        //self.handle_traversed_page(data, elision_data, maybe_jump, page_set);
        //
        //match self.stack.last_mut() {
        //Some(new_stack_top) => {
        //new_stack_top.consolidate(page_set);
        //self.set_node(node);
        //}
        //None => {
        //self.root = node;
        //}
        //};
        //} else {
        //self.position.up(1);
        //self.set_node(node);
        //}
        dbg!(&self.position);
        dbg!(self.stack.len());
    }

    fn transparent_hash_up(&mut self, node: Node, layers: usize) {
        for _ in 0..layers {
            self.position.up(1);
            self.set_node(node);
            self.set_sibling(trie::TERMINATOR);
        }
    }

    // move the current position down, hinting whether the location is guaranteed to be fresh.
    fn down(&mut self, page_set: &impl PageSet, bit_path: &BitSlice<u8, Msb0>, fresh: bool) {
        let mut new_pending = false;
        for bit in bit_path.iter().by_vals() {
            if self.position.is_root() {
                let stack_item = if fresh {
                    // Do not consolidate the root immediately
                    StackPageItem::new_pending(ROOT_PAGE_ID)
                } else {
                    // UNWRAP: all pages on the path to the node should be in the cache.
                    let (page, page_origin) = page_set
                        .get(&ROOT_PAGE_ID)
                        .map(|(p, b)| (p.deep_copy(), b))
                        .unwrap();
                    StackPageItem::new_page(ROOT_PAGE_ID, page, page_origin)
                };
                self.stack.push(stack_item);
            } else if self.position.depth_in_page() == DEPTH {
                // UNWRAP: the only legal positions are below the "parent" (root or parent_page)
                //         and stack always contains all pages to position.
                let parent_stack_page = &self.stack.last().unwrap();
                let child_page_index = self.position.child_page_index();

                // UNWRAP: we never overflow the page stack.
                let child_page_id = parent_stack_page
                    .page_id()
                    .child_page_id(child_page_index.clone())
                    .unwrap();

                let stack_item = if fresh {
                    new_pending = true;
                    println!(" new pending {child_page_id:?}");
                    StackPageItem::new_pending(child_page_id)
                } else {
                    // UNWRAP: all pages on the path to the node should be in the cache.
                    let (page, page_origin) = page_set
                        .get(&child_page_id)
                        .map(|(p, b)| (p.deep_copy(), b))
                        .unwrap();
                    StackPageItem::new_page(child_page_id, page, page_origin)
                };
                self.stack.push(stack_item);
            }
            self.position.down(bit);
        }

        // While going down and building the stack, we are sure that a position where a
        // leaf will be placed is reached. Thus, if the last page in the stack is pending,
        // it needs to be consolidated to allow the update to properly store nodes.
        // Higher pages remain pending.
        match self.stack.last_mut() {
            Some(stack_top) if new_pending => stack_top.consolidate(page_set),
            _ => (),
        }
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

        // SAFETY: PageWlaker was initialized to not reconstruct pages.
        let updated_pages = self
            .output_pages
            .into_iter()
            .map(|output_page| match output_page {
                PageWalkerPageOutput::Updated(updated_page) => updated_page,
                _ => unreachable!(),
            })
            .collect();

        if self.parent_page.is_none() {
            Output::Root(self.root, updated_pages)
        } else {
            Output::ChildPageRoots(self.child_page_roots, updated_pages)
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

        // Create the first page that will be reconstructed.
        let parent_page_id = self.parent_page.as_ref().unwrap();
        let first_elided_page_id = parent_page_id
            .child_page_id(position.child_page_index())
            .unwrap();

        if page_set.contains(&first_elided_page_id) {
            // Reconstruction already happened, avoid doing it twice.
            return None;
        }

        let mut first_elided_page = page_set.fresh();
        first_elided_page.set_node(0, TERMINATOR);
        first_elided_page.set_node(1, TERMINATOR);
        let mut diff = PageDiff::default();
        diff.set_changed(0);
        diff.set_changed(1);
        page_set.insert(
            first_elided_page_id,
            first_elided_page.freeze(),
            PageOrigin::Reconstructed {
                page_leaves_counter: 0,
                children_leaves_counter: 0,
                diff,
            },
        );

        // Split the ops into the two subtrees present in a page.
        let mut ops = ops.into_iter().peekable();

        let divisor_bit = (parent_page_id.depth() + 1) * DEPTH;

        let left_subtree_ops = std::iter::from_fn(|| {
            ops.next_if(|(key_path, _)| {
                !key_path
                    .view_bits::<Msb0>()
                    .get(divisor_bit)
                    .map(|bit| *bit)
                    .unwrap_or(false)
            })
        });
        let mut left_subtree_position = position.clone();
        left_subtree_position.down(false);
        self.advance_and_replace(page_set, left_subtree_position, left_subtree_ops);

        let right_subtree_ops = ops;
        let mut right_subtree_position = position;
        right_subtree_position.down(true);
        self.advance_and_replace(page_set, right_subtree_position, right_subtree_ops);

        self.compact_up(None, page_set);

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

    fn compact_up(&mut self, target_pos: Option<TriePosition>, page_set: &impl PageSet) {
        // This serves as a check to see if we have anything to compact.
        if self.stack.is_empty() {
            return;
        }

        let compact_layers = if let Some(target_pos) = target_pos {
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

        for i in 0..compact_layers {
            let next_node = self.compact_step();
            self.up(page_set);

            if self.stack.is_empty() {
                if self.parent_page.is_none() {
                    self.root = next_node;
                } else {
                    // though there are more layers to compact, we are all done. track the node
                    // to place into the parent page and stop compacting.
                    self.child_page_roots
                        .push((self.position.clone(), next_node));
                }

                break;
            } else {
                // save the final relevant sibling.
                if i == compact_layers - 1 {
                    self.sibling_stack
                        .push((self.node(), self.position.depth() as usize));
                }

                self.set_node(next_node);
            }
        }
    }

    fn compact_step(&mut self) -> Node {
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

                H::hash_internal(&node_data)
            }
        }
    }

    // read the node at the current position. panics if no current page.
    fn node(&self) -> Node {
        let node_index = self.position.node_index();
        // UNWRAP: if a node is being read, then a page in the stack must be present.
        let stack_top = self.stack.last().unwrap();
        // UNWRAP: reading node is expected to happen only from consoldiated pages.
        let (data, _, _) = stack_top.page_data_ref().unwrap();
        data.page.node(node_index)
    }

    // read the sibling node at the current position. panics if no current page.
    fn sibling_node(&self) -> Node {
        let node_index = self.position.sibling_index();

        // UNWRAP: if a sibling node is being read, then a page in the stack must be present.
        let stack_top = self.stack.last().unwrap();
        // UNWRAP: reading node is expected to happen only from consoldiated pages.
        let (data, _, _) = stack_top.page_data_ref().unwrap();

        data.page.node(node_index)
    }

    // set a node in the current page at the given index. panics if no current page.
    fn set_node(&mut self, node: Node) {
        let node_index = self.position.node_index();
        let sibling_node_index = self.position.sibling_index();

        // UNWRAP: if a sibling node is being written, then a page in the stack must be present.
        let stack_top = self.stack.last_mut().unwrap();
        let (page_data, _) = match stack_top {
            StackPageItem::Pending {
                ref mut pending_node,
                ..
            } if pending_node.is_none() => {
                // Special case of setting a node within a pending page,
                // save this as pending node which will be stored on consolidation
                // or will be used as jump node
                *pending_node = Some((node, node_index));
                return;
            }
            StackPageItem::Page {
                data, elision_data, ..
            } => (data, elision_data),
            // PANIC: pending node in pending pages can be set only once.
            _ => unreachable!(),
        };

        page_data.page.set_node(node_index, node);
        let sibling_node = page_data.page.node(sibling_node_index);

        if self.position.is_first_layer_in_page()
            && node == TERMINATOR
            && sibling_node == TERMINATOR
        {
            page_data.diff.set_cleared();
        } else {
            page_data.diff.set_changed(node_index);
        }
    }

    // set the sibling node in the current page at the given index. panics if no current page.
    fn set_sibling(&mut self, node: Node) {
        let node_index = self.position.sibling_index();

        // UNWRAP: if a sibling node is being set, then a page in the stack must be present.
        let stack_top = self.stack.last_mut().unwrap();
        // UNWRAP: reading node is expected to happen only from consoldiated pages.
        let (data, _, _) = stack_top.page_data_mut().unwrap();

        data.page.set_node(node_index, node);
        data.diff.set_changed(node_index);
    }

    fn assert_page_in_scope(&self, page_id: Option<&PageId>) {
        match page_id {
            Some(page_id) => {
                if let Some(ref parent_page) = self.parent_page {
                    assert!(&page_id != &parent_page);
                    assert!(page_id.is_descendant_of(&parent_page));
                }
            }
            None => assert!(self.parent_page.is_none()),
        }
    }

    // Build the stack to target a particular position.
    //
    // Precondition: the stack is either empty or contains an ancestor of the page ID the position
    // lands in.
    fn build_stack(&mut self, page_set: &impl PageSet, position: TriePosition) {
        let new_page_id = position.page_id();
        self.assert_page_in_scope(new_page_id.as_ref());

        self.position = position;
        let Some(page_id) = new_page_id else {
            while !self.stack.is_empty() {
                let Some(stack_page) = self.stack.pop() else {
                    // Nothing to handle.
                    return;
                };

                // UNWRAP: Only consolidated pages are expected at the top of the stack.
                let (data, elision_data, maybe_jump) = stack_page.page_data().unwrap();
                self.handle_traversed_page(data, elision_data, maybe_jump, page_set);
            }
            return;
        };

        // push all pages from the given page down to (not including) the target onto the stack.
        // target is either:
        //   - last item in stack (guaranteed ancestor)
        //   - the over-arching parent page (if any)
        //   - or `None`, if we need to push the root page as well.
        let target = self
            .stack
            .last()
            .map(|item| item.page_id().clone())
            .or(self.parent_page.as_ref().map(|p| p.clone()));

        let start_len = self.stack.len();
        let mut cur_ancestor = page_id;
        let mut push_count = 0;
        while Some(&cur_ancestor) != target.as_ref() {
            // UNWRAP: all pages on the path to the terminal are present in the page set.
            let (page, page_origin) = page_set.get(dbg!(&cur_ancestor)).unwrap();

            let stack_item =
                StackPageItem::new_page(cur_ancestor.clone(), page.deep_copy(), page_origin);
            self.stack.push(stack_item);
            push_count += 1;

            // stop pushing once we reach the root page.
            if cur_ancestor == ROOT_PAGE_ID {
                break;
            }
            cur_ancestor = cur_ancestor.parent_page_id();
        }

        // we pushed onto the stack in descending, so now reverse everything we just pushed to
        // make it ascending.
        self.stack[start_len..start_len + push_count].reverse();
    }

    fn handle_traversed_page(
        &mut self,
        mut page_data: StackPageData,
        elision_data: ElisionData,
        maybe_jump: Option<PendingJump>,
        page_set: &impl PageSet,
    ) {
        self.handle_pending_jump(maybe_jump, page_set);

        if page_data.page_id != ROOT_PAGE_ID {
            // Store the updated elided_children field into the page.
            page_data
                .page
                .set_elided_children(&elision_data.elided_children);
        }

        let push_reconstructed = |output_pages: &mut Vec<_>,
                                  reconstructed: StackPageData,
                                  elision_data: &ElisionData| {
            output_pages.push(PageWalkerPageOutput::Reconstructed(ReconstructedPage {
                diff: reconstructed.total_diff(&elision_data),
                page_id: reconstructed.page_id,
                page: reconstructed.page,
                // UNWRAPs: If the page is being reconstructed, it must have its
                // children_leaves_counter updated by a child page or from a previous
                // children_leaves_counter state.
                children_leaves_counter: elision_data
                    .children_leaves_counter
                    .unwrap_or(elision_data.prev_children_leaves_counter.unwrap()),
            }));
        };

        let push_updated =
            |output_pages: &mut Vec<_>, updated: StackPageData, elision_data: &ElisionData| {
                output_pages.push(PageWalkerPageOutput::Updated(UpdatedPage {
                    diff: updated.total_diff(elision_data),
                    page_id: updated.page_id,
                    page: updated.page,
                    bucket_info: updated.bucket_info.unwrap_or(BucketInfo::Fresh),
                }));
            };

        // If the stack is empty or the page is a child of the root,
        // elision and the carrying of elided children do not occur.
        // The stack could be empty if the page is the root page or one of its children,
        // and if the page is the last to be reconstructed.
        if self.stack.is_empty() || page_data.page_id.parent_page_id() == ROOT_PAGE_ID {
            if self.reconstruction {
                push_reconstructed(&mut self.output_pages, page_data, &elision_data);
            } else {
                push_updated(&mut self.output_pages, page_data, &elision_data);
            }
            return;
        }

        if let Some(children_leaves_counter) = elision_data
            .children_leaves_counter
            .or(elision_data.prev_children_leaves_counter)
        {
            let page_leaves_counter = count_leaves::<H>(&page_data.page);

            #[cfg(not(test))]
            let elide = page_leaves_counter + children_leaves_counter < PAGE_ELISION_THRESHOLD;
            #[cfg(test)]
            let elide = page_leaves_counter + children_leaves_counter < PAGE_ELISION_THRESHOLD
                && !self.inhibit_elision;

            if elide {
                // The total number of leaves in the subtree of this pages is lower than the threshold.
                // UNWRAP: The stack has been checked to not be empty.
                let parent_stack_elision_data = self.stack.last_mut().unwrap().elision_data_mut();

                if let Some(ref mut parent_children_leaves_counter) = parent_stack_elision_data
                    .children_leaves_counter
                    .or(parent_stack_elision_data.prev_children_leaves_counter)
                {
                    let prev_page_leaves_counter = elision_data.page_leaves_counter.unwrap_or(0);
                    let page_delta = page_leaves_counter as i64 - prev_page_leaves_counter as i64;

                    let prev_children_leaves_counter =
                        elision_data.prev_children_leaves_counter.unwrap();
                    let children_delta =
                        children_leaves_counter as i64 - prev_children_leaves_counter as i64;

                    let new_parent_children_leaves_counter =
                        *parent_children_leaves_counter as i64 + page_delta + children_delta;

                    // UNWRAP: page_delta and children_delta, if negative, will always be smaller than
                    // parent_children_leaves_counter. More leaves that what was previously present
                    // cannot be removed.
                    parent_stack_elision_data
                        .children_leaves_counter
                        .replace(new_parent_children_leaves_counter.try_into().unwrap());
                }

                // Elide current page from parent.
                let page_id = &page_data.page_id;

                // This will never underflow because page_id.depth() would be 0
                // only if page_id is the root and it cannot happen because the stack
                // would have been empty if the last stack item pop was the root.
                let child_index = page_id.child_index_at_level(page_id.depth() - 1);
                parent_stack_elision_data
                    .elided_children
                    .set_elide(child_index.clone(), true);

                // If `reconstruction` is true, pages do not get elided, they are simply pushed as reconstructed.
                // The bitfield needs to be present so that if, during the update phase, this page gets promoted
                // to be stored on disk, we don't want to recompute which child is elided.
                if self.reconstruction {
                    push_reconstructed(&mut self.output_pages, page_data, &elision_data);
                    return;
                }

                // If the page was previously resident in memory we need to clear it.
                // While reconstructed pages do not need this.
                if page_data.bucket_info.is_some() {
                    page_data.diff.set_cleared();
                    push_updated(&mut self.output_pages, page_data, &elision_data);
                }
                return;
            }
        };

        // If either `children_leaves_counter` and its previous value were already `None`
        // or the total number of leaves exceeded the threshold, this needs to be propagated.
        // UNWRAP: The stack has beed checked to not being empty.
        let parent_stack_elision_data = self.stack.last_mut().unwrap().elision_data_mut();
        parent_stack_elision_data.children_leaves_counter = None;
        parent_stack_elision_data.prev_children_leaves_counter = None;

        // Toggle as not elide the current page from the parent page.
        let page_id = &page_data.page_id;
        // It does not overflow for the same reason as above.
        let child_index = page_id.child_index_at_level(page_id.depth() - 1);
        parent_stack_elision_data
            .elided_children
            .set_elide(child_index.clone(), false);

        if self.reconstruction {
            push_reconstructed(&mut self.output_pages, page_data, &elision_data);
        } else {
            push_updated(&mut self.output_pages, page_data, &elision_data);
        }
    }

    // Given a possible jump create a jump page and toggle as cleared each jumped page.
    fn handle_pending_jump(&mut self, maybe_jump: Option<PendingJump>, page_set: &impl PageSet) {
        let Some(PendingJump {
            start,
            destination,
            node,
            page_id,
            elision_data,
            jumped_pages,
        }) = maybe_jump
        else {
            return;
        };

        // Create the jump page and toggle as clear each jumped page.
        let mut page = page_set.fresh();
        let partial_path = destination.path()[start.depth() as usize..].to_bitvec();

        let diff = PageDiff::from_jump_page(partial_path.len());

        // TODO: jump pages will not be filled until pending jumps will not be handled
        // by the compact up. Because only pending pages are jumped by core::update.
        // Once they are collected they need to be pushed in self.output_pages.
        // Also jump pages are expected to be empty while reconstrucing.
        assert!(jumped_pages.is_empty());

        page.tag_jump_page(node, partial_path);

        let jump_page_data = StackPageData {
            page_id,
            page,
            diff,
            bucket_info: None,
        };

        // A jump page will be hanlded as a simple traversed page to properly carry each elision data.
        println!("JUMP PAGE BEING ADDED");
        self.handle_traversed_page(jump_page_data, elision_data, None, page_set);
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
    let subtree_root = page.node(position.node_index());

    let page_walker = PageWalker::<H>::new_reconstructor(subtree_root, page_id.clone());

    let (root, reconstructed_pages) = page_walker.reconstruct(page_set, position, ops)?;

    assert_eq!(root, subtree_root);

    Some(reconstructed_pages.into_iter().map(|reconstructed_page| {
        let page_leaves_counter = count_leaves::<H>(&reconstructed_page.page);
        (
            reconstructed_page.page_id,
            reconstructed_page.page.freeze(),
            reconstructed_page.diff,
            page_leaves_counter,
            reconstructed_page.children_leaves_counter,
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        trie, Node, NodeHasher, Output, PageSet, PageWalker, TriePosition, UpdatedPage,
        ROOT_PAGE_ID,
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
    use nomt_core::page_id::{ChildPageIndex, PageId, PageIdsIterator};
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
                (leaf_b_key_path, val(2)),
                (leaf_c_key_path, val(3)),
                (leaf_d_key_path, val(4)),
                (leaf_e_key_path, val(5)),
                (leaf_f_key_path, val(6)),
            ],
        );

        let new_root = match walker.conclude(&page_set) {
            Output::Root(new_root, diffs) => {
                page_set.apply(diffs);
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
                assert_eq!(diffs.len(), 7);
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
                let diffs: HashMap<PageId, PageDiff> = updates
                    .iter()
                    .map(|p| (p.page_id.clone(), p.diff.clone()))
                    .collect();
                assert!(diffs.get(&page_id_2).unwrap().cleared());
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
                let diffs: HashMap<PageId, PageDiff> = updates
                    .iter()
                    .map(|p| (p.page_id.clone(), p.diff.clone()))
                    .collect();
                assert!(diffs.get(&root_page).unwrap().cleared());
                assert!(diffs.get(&page_id_1).unwrap().cleared());
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

    // TODO: this require the first two pages to be a jump page thus it
    // must be uncommended once jump pages are properly read
    //#[test]
    //fn count_cumulative_leaves() {
    //let root = trie::TERMINATOR;
    //let mut page_set = MockPageSet::default();
    //
    //// Build pages in the first two layers.
    //let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    //walker.set_inhibit_elision();
    //
    //#[rustfmt::skip]
    //walker.advance_and_replace(
    //&page_set,
    //TriePosition::new(),
    //vec![
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0], val(1),),
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1], val(2),),
    //],
    //);
    //
    //let Output::Root(root, updates) = walker.conclude(&page_set) else {
    //unreachable!();
    //};
    //
    //page_set.apply(updates);
    //
    //// Construct leaves in multiple pages and make sure the parent page's leaves counter has been updated correctly.
    //let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    //#[rustfmt::skip]
    //walker.advance_and_replace(
    //&page_set,
    //trie_pos![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    //vec![
    //// [8, 8, 8, 16] 2 leaves
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0], val(1),),
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1], val(2),),
    //
    //// [8, 8, 8, 17] 3 leaves
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0], val(3),),
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0], val(3),),
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1], val(4),),
    //
    //// [8, 8, 8] 1 leaf
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1], val(5),),
    //
    //// [8, 8, 8, 49] 3 leaves
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0], val(6),),
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0], val(7),),
    //(key_path![0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1], val(8),),
    //],
    //);
    //
    //let stack_top = walker.stack.last_mut().unwrap().elision_data_mut();
    //assert_eq!(stack_top.children_leaves_counter, Some(9));
    //}

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

        let stack_top = walker.stack.last_mut().unwrap().elision_data_mut();
        assert_eq!(stack_top.children_leaves_counter, Some(6));
    }

    // TODO: this require the first two pages to be a jump page thus it
    // must be uncommended once jump pages are properly read
    //#[test]
    //fn cumulative_delta_children() {
    //let root = trie::TERMINATOR;
    //let mut page_set = MockPageSet::default();
    //
    //// Build pages in the first two layers.
    //let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    //
    //#[rustfmt::skip]
    //let ops = vec![
    //// [21, 21] 1 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0], val(1),),
    ////(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1], val(2),),
    //
    //// [21, 21, 21, 0] 4 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], val(2),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0], val(3),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0], val(4),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1], val(4),),
    //
    //// [21, 21, 21] 1 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1], val(8),),
    //
    //// [21, 21, 21, 63] 3 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0], val(5),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1], val(6),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1], val(7),),
    //];
    //
    //walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());
    //
    //let Output::Root(root, updates) = walker.conclude(&page_set) else {
    //unreachable!();
    //};
    //page_set.apply(updates);
    //
    //let page_id = PageId::decode(&[21]).unwrap();
    //let (page, _) = page_set.get(&page_id).unwrap();
    //let position = trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
    //let maybe_pages =
    //super::reconstruct_pages::<Blake3Hasher>(&page, page_id, position, &mut page_set, ops);
    //
    //if let Some(pages) = maybe_pages {
    //for (page_id, page, diff, page_leaves_counter, children_leaves_counter) in pages {
    //page_set.reconstructed.insert(
    //page_id,
    //(
    //page,
    //PageOrigin::Reconstructed {
    //page_leaves_counter,
    //children_leaves_counter,
    //diff,
    //},
    //),
    //);
    //}
    //}
    //
    //// Construct leaves in multiple pages and make sure the parent page's leaves counter has been updated correctly.
    //let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    //#[rustfmt::skip]
    //walker.advance_and_replace(
    //&page_set,
    //// [21, 21, 21, 0] 3 leaves
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0],
    //vec![],
    //);
    //#[rustfmt::skip]
    //walker.advance_and_replace(
    //&page_set,
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
    //vec![
    //// [21, 21, 21] 2 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0], val(11),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1], val(12),),
    //],
    //);
    //#[rustfmt::skip]
    //walker.advance_and_replace(
    //&page_set,
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1],
    //vec![
    //// [21, 21, 21, 63] 5 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0], val(11),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1 ,0], val(12),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1], val(12),),
    //],
    //);
    //#[rustfmt::skip]
    //walker.advance(
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1],
    //&page_set
    //);
    //
    //let stack_top = walker.stack.last_mut().unwrap().elision_data_mut();
    //assert_eq!(stack_top.children_leaves_counter, Some(10));
    //}

    // TODO: this require the first two pages to be a jump page thus it
    // must be uncommended once jump pages are properly read
    //#[test]
    //fn delete_chain_of_elided_pages() {
    //let root = trie::TERMINATOR;
    //let mut page_set = MockPageSet::default();
    //
    //// Build pages in the first two layers.
    //let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    //
    //#[rustfmt::skip]
    //let ops = vec![
    //// [21, 21] 1 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0], val(1),),
    //
    //// [21, 21, 21, 21, 0] 4 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], val(2),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0], val(3),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0], val(4),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1], val(4),),
    //
    //// [21, 21, 21, 21] 1 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1], val(8),),
    //
    //// [21, 21, 21, 21, 63] 3 leaves
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0], val(5),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1], val(6),),
    //(key_path![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1], val(7),),
    //];
    //
    //walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());
    //
    //let Output::Root(root, updates) = walker.conclude(&page_set) else {
    //unreachable!();
    //};
    //page_set.apply(updates);
    //
    //let page_id = PageId::decode(&[21]).unwrap();
    //let (page, _) = page_set.get(&page_id).unwrap();
    //let position = trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
    //let maybe_pages =
    //super::reconstruct_pages::<Blake3Hasher>(&page, page_id, position, &mut page_set, ops);
    //
    //if let Some(pages) = maybe_pages {
    //for (page_id, page, diff, page_leaves_counter, children_leaves_counter) in pages {
    //page_set.reconstructed.insert(
    //page_id,
    //(
    //page,
    //PageOrigin::Reconstructed {
    //page_leaves_counter,
    //children_leaves_counter,
    //diff,
    //},
    //),
    //);
    //}
    //}
    //
    //// Construct leaves in multiple pages and make sure the parent page's leaves counter has been updated correctly.
    //let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
    //let mut delete_leaf = |trie_pos| {
    //walker.advance_and_replace(&page_set, trie_pos, vec![]);
    //};
    //
    //#[rustfmt::skip]
    //let leaf_positions = vec![
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0],
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1],
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0],
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1],
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1],
    //];
    //
    //for trie_pos in leaf_positions {
    //delete_leaf(trie_pos);
    //}
    //
    //#[rustfmt::skip]
    //walker.advance(
    //trie_pos![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1],
    //&page_set
    //);
    //
    //let stack_top = walker.stack.last_mut().unwrap().elision_data_mut();
    //assert_eq!(stack_top.children_leaves_counter, Some(0));
    //}

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
                // Added to avoid jumps
                (key_path![1], val(8),),
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
            ops[..ops.len() - 1].into_iter().cloned(),
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

        let is_collision =
            trie::is_collision_leaf::<Blake3Hasher>(&page.node(position.node_index()));
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
        let mut page_set = MockPageSet::default();
        let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
        walker.set_inhibit_elision();

        #[rustfmt::skip]
        let ops = vec![
            (vec![0b00100000, 0b00100000,0b00100000, 0b00100000], val(1),),
            (vec![0b00100000, 0b00100000,0b00100000, 0b00100001], val(2),),
            (vec![0b10100000], val(3),),
        ];

        walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

        let Output::Root(_, updates) = walker.conclude(&page_set) else {
            unreachable!();
        };

        assert_eq!(updates.len(), 3);

        let expected_jump_page = updates
            .iter()
            .find(|update| update.page_id == PageId::decode(&[8]).unwrap())
            .unwrap();
        assert!(expected_jump_page.page.read_jump_page().is_some());
    }

    #[test]
    fn root_page_is_jump_page() {
        let root = trie::TERMINATOR;
        let page_set = MockPageSet::default();

        // Build pages in the first two layers.
        let mut walker = PageWalker::<Blake3Hasher>::new(root, None);
        walker.set_inhibit_elision();

        #[rustfmt::skip]
        let ops = vec![
            (vec![0b00100000, 0b00100000, 0b00000000, 0b00100000], val(1),),
            (vec![0b00100000, 0b00100000, 0b00000000, 0b00100001], val(2),),
            (vec![0b00100000, 0b00100000, 0b00100000, 0b00100000, 0b00100000], val(3),),
            (vec![0b00100000, 0b00100000, 0b00100000, 0b00100000, 0b00100001], val(4),),
        ];

        let expected_root = nomt_core::update::build_trie::<Blake3Hasher>(
            0,
            ops.clone()
                .into_iter()
                .map(|(k, v)| (k, v, false /*collision*/)),
            |_| {},
        );

        walker.advance_and_replace(&page_set, TriePosition::new(), ops.clone());

        let Output::Root(root, updates) = walker.conclude(&page_set) else {
            unreachable!();
        };

        assert_eq!(root, expected_root);

        assert_eq!(updates.len(), 6);
        let updated_root = updates
            .iter()
            .find(|update| update.page_id == ROOT_PAGE_ID)
            .unwrap();
        assert!(updated_root.page.read_jump_page().is_some());
        let other_expected_jump_page = updates
            .iter()
            .find(|update| update.page_id == PageId::decode(&[8, 2, 0, 32]).unwrap())
            .unwrap();
        assert!(other_expected_jump_page.page.read_jump_page().is_some());
    }
}
