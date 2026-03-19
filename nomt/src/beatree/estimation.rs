//! An adjacent key-value pair within the beatree isn't strictly a
//! neighbor within the merkle trie. What this module does is load,
//! alongside the value of the lookup key, its neighbors, which mainly
//! requires taking into consideration the collision keys.

use std::collections::BTreeSet;

use bitvec::{order::Msb0, view::BitView};
use nomt_core::{
    collisions::collides,
    proof::shared_bits,
    witness::{CollisionInfo, EstimationInfo},
};
use parking_lot::RwLockReadGuard;

use crate::{
    beatree::{self, ops, Key, Tree, ValueChange},
    io::IoPool,
    LiveOverlay, NomtIterator,
};

/// Search for the left neighbor of the specified key within the provided map.
/// Take into consideration the deletions, and use the provided closure
/// to determine if a key present within the map is a deletion or not.
fn collect_left_neighbors(
    start_key: &Key,
    end_key: &Option<Key>,
    candidates: &mut BTreeSet<Key>,
    get_strict_prev: impl Fn(&Key) -> Option<Key>,
    is_deletion: impl Fn(&Key) -> bool,
) {
    let mut key = start_key.clone();
    loop {
        match get_strict_prev(&key) {
            Some(prev_key) if end_key.as_ref().map_or(false, |end| prev_key < *end) => return,
            None => return,
            Some(prev_key) if is_deletion(&prev_key) => {
                candidates.remove(&prev_key);
                key = prev_key;
            }
            Some(prev_key) => {
                candidates.insert(prev_key.clone());

                // If there is no limit over the end key then
                // stop as soon as a non-delete key is found.
                if end_key.is_none() {
                    break;
                }

                key = prev_key;
            }
        }
    }
}

impl Tree {
    fn lookup_left_neighbor(&self, key: Key, overlay: &LiveOverlay) -> Option<Vec<u8>> {
        let shared = self.shared.read();

        let mut left_most: Option<Vec<u8>> = None;
        let mut candidates = BTreeSet::<Vec<u8>>::new();

        loop {
            // overlays -> primary -> secondary -> store
            //
            // This is the order of priority in which insertion and deletions
            // should be treated.
            //
            // To find the left neighbor the search must be performed in reverse order,
            // starting from the store up to the overlay to properly take into considerations
            // all items.
            //
            // Given the order with which the layers are checked we are sure that each
            // deletion from every layer only can alter the previously collected items.
            //
            // 1. Find left neighbor from the disk, use the previous candidate or the initial key.
            let k = left_most.as_ref().unwrap_or(&key).clone();

            left_most = self.find_leaf_neighbor_within_tree(&shared, &k);

            if let Some(candidate) = &left_most {
                candidates.insert(candidate.clone());
            }

            // 2. Look for a candidate within the secondary staging, collect deletions to filter out
            // the candidate from the previous layers.
            if let Some(secondary_staging) = shared.secondary_staging.as_ref() {
                collect_left_neighbors(
                    &k,
                    &left_most,
                    &mut candidates,
                    |key| {
                        secondary_staging
                            .range(..key.clone())
                            .map(|(k, _)| k.clone())
                            .next_back()
                    },
                    |key| matches!(secondary_staging.get(key), Some(ValueChange::Delete)),
                )
            };

            if left_most.is_none() {
                left_most = candidates.first().cloned();
            }

            // 3. Look for a candidate within the primary staging, collect deletions to filter out
            // the candidate from the previous layers.
            collect_left_neighbors(
                &k,
                &left_most,
                &mut candidates,
                |key| {
                    shared
                        .primary_staging
                        .range(..key.clone())
                        .map(|(k, _)| k.clone())
                        .next_back()
                },
                |key| matches!(shared.primary_staging.get(key), Some(ValueChange::Delete)),
            );

            if left_most.is_none() {
                left_most = candidates.first().cloned();
            }

            // 4. Look for a candidate within the overlays, collect deletions to filter out
            // the candidate from the previous layers.
            collect_left_neighbors(
                &k,
                &left_most,
                &mut candidates,
                |key| overlay.get_strict_prev(key),
                |key| matches!(overlay.value(key), Some(ValueChange::Delete)),
            );

            if left_most.is_none() {
                left_most = candidates.first().cloned();
            }

            if let Some(left_neighbor) = candidates.last() {
                break Some(left_neighbor.clone());
            }

            if left_most.is_none() {
                break None;
            }
        }
    }

    /// Look up the key alongside its merkle trie neighbors.
    pub fn lookup_with_estimation_info(
        &self,
        key: Key,
        overlay: &LiveOverlay,
        io_pool: &IoPool,
    ) -> (Option<Vec<u8>>, EstimationInfo) {
        // The key must be trimmed of trailing zeros to make it possible to find
        // the real left merkle neighbor of a possible collision key.
        let trailing_zeros = key.iter().rev().take_while(|b| **b == 0).count();
        let mut trim_key = key.clone();
        trim_key.truncate(key.len() - trailing_zeros);

        let left_neighbor = self.lookup_left_neighbor(trim_key.clone(), overlay);

        let mut key_value_iter = NomtIterator::new(
            io_pool,
            self.read_transaction(),
            overlay,
            left_neighbor.clone().unwrap_or(vec![0]),
            None,
        );

        if left_neighbor.is_some() {
            assert_eq!(key_value_iter.next().map(|(key, _)| key), left_neighbor);
        }

        // Start looking for the right neighbor, there are multiple possibilities to be handled:
        // 1. The value is found
        // 2. The value is found within a collision group
        // 3. The value is not found
        //
        // Cases 1 and 2 just require counting the amount of collisions and
        // fetching the first key which doesn't collide.
        // Case 3 instead just requires stopping at the first key which doesn't collide.
        //
        // NOTE: the iteration starts from the left neighbor and the left neighbor has been found
        // by trimming the trailing zeros of the key, thus this iterator is expected to go over
        // all the keys which collide with the key that is being searched.

        let mut maybe_value = None;

        // Track the number of collisions found and the base key of the collision group.
        let mut collisions = 0;
        let mut collision_base: Option<Key> = None;

        // Additional data required if the right or left neighbor are part
        // of a collision group.
        let right_neighbor = loop {
            match key_value_iter.next() {
                Some((next_key, val)) if key == next_key => {
                    // The key has been found. It could be the base of a set of collisions.
                    collision_base.get_or_insert(next_key);
                    maybe_value = Some(val);
                }
                Some((next_key, _val)) if collides(&key, &next_key) => {
                    // A collision key has been found.
                    collision_base.get_or_insert(next_key);
                    collisions += 1;
                }
                Some((next_key, _val)) => break Some(next_key),
                None => break None,
            }
        };

        // If the key has been found or collides with an existing leaf (collision or not),
        // there is no need for any other neighbor, the left and right one are enough to
        // calculate the depth of the reached terminal leaf.
        //
        // Instead, if the value is not present and does not collide with any existing key,
        // there is a need to fetch one additional neighbor and maybe iterate over
        // all the collision keys associated to one of the two neighbors fetched above.
        //
        // The additional neighbor could be the neighbor of the left or right neighbor
        // that on its turn could be a collision leaf rather than just a leaf.
        //
        // If collisions has been found but with no item that matches
        // there could be two scenarios:
        // 1. only 1 collision key has been collected, thus the key
        //    we are looking for collides with an existing leaf.
        // 2. a number of collisions has been collected, thus the
        //    first collision element will be the right neighbor.
        let collision = if maybe_value.is_some() {
            // There is no collision with something existing because
            // the value is present, so count the presence as one additional
            // key within the collision group
            collisions += 1;
            false
        } else {
            collisions > 0
        };

        let collision_info = (collisions > 1).then(|| CollisionInfo {
            base_key_len: collision_base.take().unwrap().len(),
            amount: collisions,
        });

        let mut estimation_info = EstimationInfo {
            key,
            left_neighbor,
            right_neighbor,
            collision_info,
            presence: maybe_value.is_some(),
            collision,
            additional_neighbor: None,
        };

        // If the key is present or one of the two neighbor is missing
        // we can return early.
        if estimation_info.presence || estimation_info.collision {
            return (maybe_value, estimation_info);
        }

        // Otherwise the additional neighbor and maybe collision needs to be fetched.
        let mut additional_neighbor;

        // Based on whether the key falls into the left or right subtree
        // one additional neighbor needs to be fetched.
        //
        // If either of the two neighbors is not present then an additional
        // neighbor on the opposite side is required.
        let k = estimation_info.key.view_bits::<Msb0>();
        let additional_left = match (
            estimation_info.left_neighbor.as_ref(),
            estimation_info.right_neighbor.as_ref(),
        ) {
            // Both neighbors are present thus compare the keys,
            // the key falls into the left subtree and thus one additional
            // left neighbor is required if the amount of shared bits
            // between the key and l is greater than the shared bits with r,
            // the right neighbor.
            (Some(left_neighbor), Some(right_neighbor)) => {
                let l = left_neighbor.view_bits::<Msb0>();
                let r = right_neighbor.view_bits::<Msb0>();
                shared_bits(k, l) > shared_bits(k, r)
            }
            // If there is only the right neighbor then one additional right
            // neighbor is required.
            (None, Some(_right_neighbor)) => false,
            // The same as above for the left neighbor.
            (Some(_left_neighbor), None) => true,
            // No neighbors and presence within the db implies that the db is empty.
            (None, None) => {
                return (None, estimation_info);
            }
        };

        if additional_left {
            // UNWRAPs: if an additional left is required then left_neighbor is expected to be present.
            let left_neighbor = estimation_info.left_neighbor.as_ref().unwrap();
            additional_neighbor = self.lookup_left_neighbor(left_neighbor.clone(), overlay);

            if additional_neighbor
                .as_ref()
                .map_or(false, |key| collides(left_neighbor, &key))
            {
                let mut amount = 2;
                let mut base_key_len = left_neighbor.len();

                loop {
                    additional_neighbor =
                        self.lookup_left_neighbor(additional_neighbor.clone().unwrap(), overlay);
                    match &additional_neighbor {
                        None => break,
                        Some(k) if !collides(left_neighbor, &k) => break,
                        Some(k) => base_key_len = k.len(),
                    }
                    amount += 1;
                }

                estimation_info.collision_info = Some(CollisionInfo {
                    base_key_len,
                    amount,
                });
            }
        } else {
            // UNWRAPs: if an additional right is required then right_neighbor is expected to be present.
            let right_neighbor = estimation_info.right_neighbor.as_ref().unwrap();
            additional_neighbor = key_value_iter.next().map(|(key, _val)| key);

            if additional_neighbor
                .as_ref()
                .map_or(false, |key| collides(right_neighbor, &key))
            {
                let mut amount = 2;
                loop {
                    additional_neighbor = key_value_iter.next().map(|(key, _val)| key);
                    match &additional_neighbor {
                        None => break,
                        Some(k) if !collides(right_neighbor, &k) => break,
                        Some(_) => (),
                    }
                    amount += 1;
                }

                estimation_info.collision_info = Some(CollisionInfo {
                    base_key_len: right_neighbor.len(),
                    amount,
                });
            }
        };

        estimation_info.additional_neighbor = Some((additional_left, additional_neighbor));

        (maybe_value, estimation_info)
    }

    fn find_leaf_neighbor_within_tree(
        &self,
        shared: &RwLockReadGuard<'_, beatree::Shared>,
        key: &Key,
    ) -> Option<Key> {
        // let mut branch = shared.bbn_index.lookup(key).map(|(_, branch)| branch)?;
        let (separator, mut branch) = shared.bbn_index.lookup(key)?;
        let (mut branch_index, leaf_pn) = ops::search_branch(&branch, &key)?;
        let leaf = ops::fetch_leaf_blocking(&shared.leaf_cache, &shared.leaf_store_rd, leaf_pn)?;
        let (_found, leaf_index) = ops::leaf_find_key_pos(&leaf, &key, None);

        if leaf_index == 0 {
            if branch_index == 0 {
                let prev_key = shared
                    .bbn_index
                    .inner()
                    .range(..separator)
                    .map(|(k, _)| k.clone())
                    .next_back()?;
                branch = shared
                    .bbn_index
                    .lookup(&prev_key)
                    .map(|(_, branch)| branch)?;
                branch_index = branch.n() as usize;
            }
            let leaf_pn = branch.node_pointer(branch_index - 1).into();
            let leaf =
                ops::fetch_leaf_blocking(&shared.leaf_cache, &shared.leaf_store_rd, leaf_pn)?;
            Some(leaf.key(leaf.n() - 1))
        } else {
            Some(leaf.key(leaf_index - 1))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        beatree::{branch::BRANCH_NODE_SIZE, leaf::node::MAX_KEY_LEN, Tree, ValueChange},
        io::{start_test_io_pool, IoPool, PagePool},
        LiveOverlay,
    };
    use bitvec::{order::Msb0, view::BitView};
    use lazy_static::lazy_static;
    use nomt_core::{collisions::collides, proof::shared_bits, witness::CollisionInfo};
    use quickcheck::{Arbitrary, Gen, QuickCheck, TestResult};
    use std::{collections::BTreeMap, sync::Arc};

    fn init_beatree(
        key_value_pairs: Vec<(Vec<u8>, Vec<u8>)>,
        page_pool: &PagePool,
        io_pool: &IoPool,
    ) -> Tree {
        let ln_fd = tempfile::tempfile().unwrap();
        let bbn_fd = tempfile::tempfile().unwrap();
        ln_fd.set_len(BRANCH_NODE_SIZE as u64).unwrap();
        bbn_fd.set_len(BRANCH_NODE_SIZE as u64).unwrap();

        let ln_fd = Arc::new(ln_fd);
        let bbn_fd = Arc::new(bbn_fd);

        let tree = Tree::open(
            page_pool.clone(),
            &io_pool,
            0, /* empty free list */
            0, /* empty free list */
            1, /* first ln pn */
            1, /* first bbn pn */
            bbn_fd,
            ln_fd,
            1,   /* commit_concurrency */
            256, /* MiB leaf cache size */
        )
        .unwrap();

        let mut sync = tree.sync();
        sync.begin_sync(
            key_value_pairs
                .into_iter()
                .map(|(k, v)| (k, ValueChange::Insert(v))),
        );
        sync.wait_pre_meta().unwrap();
        sync.post_meta();

        tree
    }

    fn rescale(init: u16, lower_bound: usize, upper_bound: usize) -> usize {
        ((init as f64 / u16::MAX as f64) * ((upper_bound - 1 - lower_bound) as f64)).round()
            as usize
            + lower_bound
    }

    #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    struct Key {
        inner: Vec<u8>,
    }

    // required to let quickcheck generate arbitrary keys as arguments for the tests
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

    // required to let quickcheck generate arbitrary values as arguments for the tests
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
    struct LookupNeighborsInputs {
        insertions: BTreeMap<Key, Value>,
        lookups: Vec<(u16, bool)>,
        collisions: Vec<(u16, u16)>,
    }

    impl Arbitrary for LookupNeighborsInputs {
        fn arbitrary(g: &mut Gen) -> Self {
            Self {
                insertions: BTreeMap::<Key, Value>::arbitrary(g),
                lookups: Vec::<(u16, bool)>::arbitrary(g),
                collisions: Vec::<(u16, u16)>::arbitrary(g),
            }
        }
    }

    fn inner_lookup_neighbors(
        LookupNeighborsInputs {
            insertions,
            lookups,
            collisions,
        }: LookupNeighborsInputs,
    ) -> TestResult {
        if insertions.is_empty() || lookups.is_empty() {
            return TestResult::discard();
        }

        let mut key_value_pairs: Vec<_> = insertions
            .into_iter()
            .map(|(key, value)| (key.inner.clone(), value.inner.clone()))
            .collect();

        key_value_pairs.dedup_by(|(a, _), (b, _)| collides(a, b));

        let mut collisions: Vec<(usize, usize)> = collisions
            .into_iter()
            .map(|(index, amount)| {
                (
                    rescale(index, 0, key_value_pairs.len()),
                    rescale(amount, 0, 100),
                )
            })
            .collect();
        collisions.sort_by(|(a, _), (b, _)| a.cmp(b));
        collisions.dedup_by(|(a, _), (b, _)| a == b);

        let mut added_collisions = 0;
        let collisions: Vec<std::ops::Range<usize>> = collisions
            .into_iter()
            .map(|(index, mut amount)| {
                let (mut key, mut value) = key_value_pairs[added_collisions + index].clone();
                amount = std::cmp::min(amount, MAX_KEY_LEN - key.len());
                let collision_range =
                    added_collisions + index..added_collisions + index + amount + 1;
                while amount > 0 {
                    key.push(0);
                    value.push(0);
                    key_value_pairs
                        .insert(added_collisions + index + 1, (key.clone(), value.clone()));
                    amount -= 1;
                    added_collisions += 1;
                }

                collision_range
            })
            .collect();

        let lookups: Vec<_> = lookups
            .into_iter()
            .map(|(idx, is_present)| (rescale(idx, 0, key_value_pairs.len()), is_present))
            .collect();

        let page_pool: PagePool = PagePool::new();
        let io_pool: IoPool = start_test_io_pool(3, page_pool.clone());
        let tree = init_beatree(key_value_pairs.clone(), &page_pool, &io_pool);

        // NOTE: ensure the db was properly filled:
        {
            let mut iter = tree.read_transaction().iterator(&io_pool, vec![0], None);
            for (key, val) in key_value_pairs.iter().by_ref() {
                let (btree_key, btree_val) = iter.next().unwrap();
                assert_eq!(&btree_key, key);
                assert_eq!(&btree_val, val);
            }
        }

        let (keys, values): (Vec<Vec<u8>>, Vec<Vec<u8>>) = key_value_pairs.into_iter().unzip();

        for (lookup_index, is_present) in lookups {
            if is_present {
                let lookup_key = &keys[lookup_index];
                let (val, estimation_info) = tree.lookup_with_estimation_info(
                    lookup_key.clone(),
                    &LiveOverlay::new([].iter()).unwrap(),
                    &io_pool,
                );

                assert_eq!(val.as_ref(), Some(&values[lookup_index]));

                let (expected_left, expected_right) = match collisions
                    .iter()
                    .find(|range| range.contains(&lookup_index))
                {
                    Some(collision_range) => (
                        collision_range
                            .start
                            .clone()
                            .checked_sub(1)
                            .map(|idx| &keys[idx]),
                        keys.get(collision_range.end),
                    ),
                    None => (
                        lookup_index
                            .checked_sub(1)
                            .filter(|idx| *idx < keys.len())
                            .map(|idx| &keys[idx]),
                        lookup_index
                            .checked_add(1)
                            .filter(|idx| *idx < keys.len())
                            .map(|idx| keys.get(idx))
                            .flatten(),
                    ),
                };

                assert_eq!(estimation_info.left_neighbor.as_ref(), expected_left);
                assert_eq!(estimation_info.right_neighbor.as_ref(), expected_right);
                let expected_collision_info = collisions
                    .iter()
                    .find(|range| range.contains(&lookup_index))
                    .filter(|range| range.len() > 1)
                    .map(|range| nomt_core::witness::CollisionInfo {
                        base_key_len: keys[range.start].len(),
                        amount: range.len(),
                    });

                assert_eq!(
                    estimation_info
                        .collision_info
                        .as_ref()
                        .map(|c| (c.base_key_len, c.amount)),
                    expected_collision_info
                        .as_ref()
                        .map(|c| (c.base_key_len, c.amount)),
                );
            } else {
                let (left_index, right_index) = match collisions
                    .iter()
                    .find(|range| range.contains(&lookup_index))
                {
                    Some(collision_range) => (lookup_index, collision_range.start),
                    None => (lookup_index, lookup_index + 1),
                };
                let left_neighbor = keys.get(left_index);
                let right_neighbor = keys.get(right_index);

                let lookup_key = {
                    let mut key = left_neighbor.cloned().unwrap_or(vec![0]);
                    let last_byte = key.last_mut().unwrap();
                    if *last_byte < 255 {
                        *last_byte += 1;
                    } else {
                        key.push(1);
                    }
                    if right_neighbor.map_or(false, |right| key >= *right || collides(&key, right))
                    {
                        continue;
                    }

                    key
                };

                let additional_neighbor = match (left_neighbor, right_neighbor) {
                    (None, None) => None,
                    (Some(l), None) => {
                        // Additional is to the left of L, skip L's collision group.
                        let start = collisions
                            .iter()
                            .find(|range| range.contains(&left_index))
                            .map_or(left_index, |range| range.start);
                        Some(start.checked_sub(1).and_then(|idx| keys.get(idx)).cloned())
                    }
                    (None, Some(r)) => {
                        // Additional is to the right of R, skip R's collision group.
                        let end = collisions
                            .iter()
                            .find(|range| range.contains(&right_index))
                            .map_or(right_index, |range| range.end - 1);
                        Some(keys.get(end + 1).cloned())
                    }
                    (Some(l), Some(r)) => {
                        let k = lookup_key.view_bits::<Msb0>();
                        let l = l.view_bits::<Msb0>();
                        let r = r.view_bits::<Msb0>();
                        let additional_neighbor = if shared_bits(k, l) > shared_bits(k, r) {
                            // keys.get(left_index - 1)
                            // Additional is to the left of L, skip L's collision group.
                            let start = collisions
                                .iter()
                                .find(|range| range.contains(&left_index))
                                .map_or(left_index, |range| range.start);
                            start.checked_sub(1).and_then(|idx| keys.get(idx))
                        } else {
                            // keys.get(right_index + 1)
                            // Additional is to the right of R, skip R's collision group.
                            let end = collisions
                                .iter()
                                .find(|range| range.contains(&right_index))
                                .map_or(right_index, |range| range.end - 1);
                            keys.get(end + 1)
                        };
                        Some(additional_neighbor.cloned())
                    }
                };

                // let additional_neighbor = if left_neighbor.is_none() && right_neighbor.is_none() {
                //     None
                // } else ;

                let (val, estimation_info) = tree.lookup_with_estimation_info(
                    lookup_key.clone(),
                    &LiveOverlay::new([].iter()).unwrap(),
                    &io_pool,
                );

                assert_eq!(val.as_ref(), None);
                assert_eq!(estimation_info.left_neighbor.as_ref(), left_neighbor);
                assert_eq!(estimation_info.right_neighbor.as_ref(), right_neighbor);

                assert_eq!(
                    estimation_info
                        .additional_neighbor
                        .map(|(_, n)| n)
                        .flatten(),
                    additional_neighbor.flatten()
                );

                let expected_additional_collision =
                    if left_neighbor.is_some() && right_neighbor.is_some() {
                        let k = lookup_key.view_bits::<Msb0>();
                        // UNWRAPs: both neighbors have already been checked to be Some.
                        let l = left_neighbor.as_ref().unwrap().view_bits::<Msb0>();
                        let r = right_neighbor.as_ref().unwrap().view_bits::<Msb0>();

                        let closer_is_left = shared_bits(k, l) > shared_bits(k, r);
                        let closer_index = if closer_is_left {
                            left_index
                        } else {
                            right_index
                        };

                        // Check if the closer neighbor is part of a collision group
                        // additional_collision describes the collision group that the closer neighbor belongs to
                        // as seen from the additional_neighbor side
                        collisions
                            .iter()
                            .find(|range| range.contains(&closer_index))
                            .filter(|range| range.len() > 1)
                            .map(|range| CollisionInfo {
                                base_key_len: keys[range.start].len(),
                                amount: range.len(),
                            })
                    } else {
                        None
                    };

                assert_eq!(
                    estimation_info
                        .collision_info
                        .as_ref()
                        .map(|c| (c.base_key_len, c.amount)),
                    expected_additional_collision
                        .as_ref()
                        .map(|c| (c.base_key_len, c.amount)),
                );
            }
        }

        TestResult::passed()
    }

    #[test]
    fn lookup_neighbors() {
        QuickCheck::new()
            .gen(quickcheck::Gen::new(400))
            .max_tests(10)
            .quickcheck(inner_lookup_neighbors as fn(_) -> TestResult)
    }
}
