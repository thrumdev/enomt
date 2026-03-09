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

/// Get the strictly previous key within the specified map. It returns a key
/// smaller than the one returned by `get_prev(key)`.
///
/// Return None if the key is already associated to the minimum key within the map.
fn get_strict_previous_key(
    get_prev: impl Fn(&Key) -> Option<Key>,
    get_next: impl Fn(&Key) -> Option<Key>,
    key: &Key,
) -> Option<Key> {
    let prev_key = get_prev(key)?;
    let mut decreased_prev_key = prev_key.clone();
    if let None = decreased_prev_key.pop_if(|last| *last == 0) {
        decreased_prev_key.last_mut().map(|last| *last -= 1);
    }
    let mut prev_prev_key = get_prev(&decreased_prev_key)?;

    // It could be that the real prev_prev_key is greater than
    // the one we fetched by `get_prev(&decreased_prev_key)`.
    //
    // Example: the key is [7, 10] and prev_key = get_prev([7, 10]) is [7].
    // Now decreased_key becomes [6] but prev_prev_key = get_prev([6])
    // could end up being something like [5], which is fine on its own,
    // but decreasing prev_key by one could have made us lose the real
    // prev_prev_key, which could have been [6, 107].
    //
    // To solve this, once we have prev_prev_key we need to advance to
    // the next key one after the other until next_key matches prev_key,
    // then we are sure the real prev_prev_key has been reached.
    loop {
        // UNWRAP: `prev_key` has been fetched from the map,
        // thus it is expected to be found.
        let next_key = get_next(&prev_prev_key).unwrap();
        if next_key == prev_key {
            break Some(prev_prev_key);
        }
        prev_prev_key = next_key;
    }
}

/// Search for the left neighbor of the specified key within the provided map.
/// Take into consideration the deletions, and use the provided closure
/// to determine if a key present within the map is a deletion or not.
fn collect_left_neighbors(
    start_key: &Key,
    end_key: &Option<Key>,
    candidates: &mut BTreeSet<Key>,
    get_prev: impl Fn(&Key) -> Option<Key>,
    get_next: impl Fn(&Key) -> Option<Key>,
    is_deletion: impl Fn(&Key) -> bool,
) {
    let mut key = start_key.clone();
    loop {
        let maybe_key = match get_prev(&key) {
            None => None,
            Some(prev_key) if prev_key != key => Some(prev_key),
            _ => get_strict_previous_key(&get_prev, &get_next, &key),
        };

        match maybe_key {
            Some(prev_key) if end_key.as_ref().map_or(false, |end| prev_key < *end) => return,
            None => return,
            Some(prev_key) if is_deletion(&prev_key) => {
                candidates.remove(&prev_key);
                key = prev_key;
            }
            Some(prev_key) => {
                candidates.insert(prev_key.clone());

                // If there is no limit over the end key than
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
            // starting from the store up to the overlay to properly take into consideratoins
            // all items.
            //
            // Given the order with wich the layers are check we are sure that each
            // deletion from every layer only can alter the previously collected items.
            //
            // 1. Find left neighbor from the disk, use the previous candidate or the initialk key.
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
                    |key| secondary_staging.get_prev(key).map(|(k, _)| k.clone()),
                    |key| {
                        secondary_staging
                            .range(key.clone()..)
                            .map(|(k, _)| k.clone())
                            .skip_while(|k| k == key)
                            .next()
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
                |key| shared.primary_staging.get_prev(key).map(|(k, _)| k.clone()),
                |key| {
                    shared
                        .primary_staging
                        .range(key.clone()..)
                        .map(|(k, _)| k.clone())
                        .skip_while(|k| k == key)
                        .next()
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
                |key| overlay.get_prev_key(key),
                |key| overlay.get_strictly_next_key(key).cloned(),
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
        // The key must be trimmed from trailing zero to make possible to find
        // the real left merkle neighbor of a possible collision key.
        let trailing_zeros = key.iter().rev().take_while(|b| **b == 0).count();
        let mut trim_key = key.clone();
        trim_key.truncate(key.len() - trailing_zeros);

        let left_neighbor = self.lookup_left_neighbor(trim_key, overlay);

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

        // The boolean flag represent if a collision group has been found while
        // the usize the len of the first key in the group.
        let mut collisions = 0;
        let mut collision_base: Option<Key> = None;

        // Additional data required if the right or left neighbor are part
        // of a collision group.
        let mut pending_additional_info = None;

        let mut maybe_value = None;

        // Looking for the right neighbor could imply to iterate over al collisions
        // which can be between the left and right neighbor.
        let right_neighbor = loop {
            match key_value_iter.next() {
                Some((next_key, val)) if key == next_key => {
                    // The key has been found. It could be the base of a set of collisions.
                    collision_base.get_or_insert(next_key);
                    maybe_value = Some(val);
                    collisions += 1;
                }
                Some((next_key, _val)) if collides(&key, &next_key) => {
                    // A collision key has been found.
                    collision_base.get_or_insert(next_key);
                    collisions += 1;
                }
                Some((next_key, _val)) if collisions >= 1 && maybe_value.is_none() => {
                    // If collisions has been found but with no item that matches
                    // then the first collision element will be the right neighbor.

                    // UNWRAP: If collision was greater than 1 then the collision_base_len must be Some.
                    let right_neighbor = collision_base.take().unwrap();

                    let collision_info = if collisions == 1 {
                        None
                    } else {
                        Some(CollisionInfo {
                            base_key_len: right_neighbor.len(),
                            amount: collisions,
                        })
                    };

                    // Additional info are the neighbor of the collisions and
                    // the collision group associated to the right neighbor or the key.
                    pending_additional_info = Some((next_key, collision_info));

                    break Some(right_neighbor);
                }
                Some((next_key, _val)) => break Some(next_key),
                None => break None,
            }
        };

        let collision_info = if collisions > 1 {
            // UNWRAP: If collision was greater than 1 then the collision_base_len must be Some.
            Some(CollisionInfo {
                base_key_len: collision_base.take().unwrap().len(),
                amount: collisions,
            })
        } else {
            None
        };

        let mut estimation_info = EstimationInfo {
            key,
            left_neighbor,
            right_neighbor,
            collision_info,
            presence: false,
            additional_neighbor: None,
            additional_collision: None,
        };

        // If the key is present or one of the two neighbor is missing
        // we can return early.
        if maybe_value.is_some() {
            estimation_info.presence = true;
            return (maybe_value, estimation_info);
        } else if estimation_info.left_neighbor.is_none()
            || estimation_info.right_neighbor.is_none()
        {
            return (maybe_value, estimation_info);
        }

        // Otherwise the additional neighbor and maybe collision needs to be fetched.
        let mut additional_neighbor;
        let mut additional_collision = None;

        let k = estimation_info.key.view_bits::<Msb0>();
        // UNWRAPs: both neighbors has already been checked to be Some.
        let left_neighbor = estimation_info.left_neighbor.as_ref().unwrap();
        let right_neighbor = estimation_info.right_neighbor.as_ref().unwrap();
        let l = left_neighbor.view_bits::<Msb0>();
        let r = right_neighbor.view_bits::<Msb0>();

        // Wether the key falls into the left subtree or the right one.
        let key_on_the_left = shared_bits(k, l) > shared_bits(k, r);

        if let Some((additional_neighbor, collision_info)) =
            pending_additional_info.take_if(|_| !key_on_the_left)
        {
            estimation_info
                .additional_neighbor
                .replace(additional_neighbor);
            estimation_info.additional_collision = collision_info;
            return (maybe_value, estimation_info);
        }

        if key_on_the_left {
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

                additional_collision = Some(CollisionInfo {
                    base_key_len,
                    amount,
                });
            }
        } else {
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
                        Some(k) => (),
                    }
                    amount += 1;
                }

                additional_collision.replace(CollisionInfo {
                    base_key_len: right_neighbor.len(),
                    amount,
                });
            }
        };

        estimation_info.additional_neighbor = additional_neighbor;
        estimation_info.additional_collision = additional_collision;
        (maybe_value, estimation_info)
    }

    fn find_leaf_neighbor_within_tree(
        &self,
        shared: &RwLockReadGuard<'_, beatree::Shared>,
        key: &Key,
    ) -> Option<Key> {
        let mut branch = shared.bbn_index.lookup(key).map(|(_, branch)| branch)?;
        let (mut branch_index, leaf_pn) = ops::search_branch(&branch, &key)?;
        let leaf = ops::fetch_leaf_blocking(&shared.leaf_cache, &shared.leaf_store_rd, leaf_pn)?;
        let (_found, leaf_index) = ops::leaf_find_key_pos(&leaf, &key, None);

        if leaf_index == 0 {
            if branch_index == 0 {
                let prev_key = get_strict_previous_key(
                    |key| {
                        shared
                            .bbn_index
                            .inner()
                            .get_prev(key)
                            .map(|(k, _)| k.clone())
                    },
                    |key| {
                        shared
                            .bbn_index
                            .inner()
                            .range(key.clone()..)
                            .map(|(k, _)| k.clone())
                            .skip_while(|k| k == key)
                            .next()
                    },
                    &key,
                )?;
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

    lazy_static! {
        static ref PAGE_POOL: PagePool = PagePool::new();
        static ref IO_POOL: IoPool = start_test_io_pool(3, PAGE_POOL.clone());
    }

    fn init_beatree(key_value_pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Tree {
        let ln_fd = tempfile::tempfile().unwrap();
        let bbn_fd = tempfile::tempfile().unwrap();
        ln_fd.set_len(BRANCH_NODE_SIZE as u64).unwrap();
        bbn_fd.set_len(BRANCH_NODE_SIZE as u64).unwrap();

        let ln_fd = Arc::new(ln_fd);
        let bbn_fd = Arc::new(bbn_fd);

        let tree = Tree::open(
            PAGE_POOL.clone(),
            &IO_POOL,
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

    // required to let quickcheck generate arbitrary keys as arguments for the tests
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

        let tree = init_beatree(key_value_pairs.clone());

        // NOTE: ensure the db was properly filled:
        {
            let mut iter = tree.read_transaction().iterator(&IO_POOL, vec![0], None);
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
                    &IO_POOL,
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

                let additional_neighbor = if left_neighbor.is_none() || right_neighbor.is_none() {
                    None
                } else {
                    let k = lookup_key.view_bits::<Msb0>();
                    // UNWRAPs: both neighbors has already been checked to be Some.
                    let left_neighbor = left_neighbor.as_ref().unwrap();
                    let l = left_neighbor.view_bits::<Msb0>();
                    let r = right_neighbor.as_ref().unwrap().view_bits::<Msb0>();
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
                };

                let (val, estimation_info) = tree.lookup_with_estimation_info(
                    lookup_key.clone(),
                    &LiveOverlay::new([].iter()).unwrap(),
                    &IO_POOL,
                );

                assert_eq!(val.as_ref(), None);
                assert_eq!(estimation_info.left_neighbor.as_ref(), left_neighbor);
                assert_eq!(estimation_info.right_neighbor.as_ref(), right_neighbor);
                assert_eq!(
                    estimation_info.additional_neighbor,
                    additional_neighbor.flatten()
                );
                // Compute expected additional_collision
                let expected_additional_collision =
                    if left_neighbor.is_some() && right_neighbor.is_some() {
                        let k = lookup_key.view_bits::<Msb0>();
                        // UNWRAPs: both neighbors has already been checked to be Some.
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
                        .additional_collision
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
            .gen(quickcheck::Gen::new(10000))
            .max_tests(10)
            .quickcheck(inner_lookup_neighbors as fn(_) -> TestResult)
    }
}
