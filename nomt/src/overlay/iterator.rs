//! Database iterators over [`LiveOverlay`] and the Beatree.

use std::{cmp::Ordering, iter::Peekable};

use crate::{
    beatree::{KeyValueIterator, ReadTransaction, ValueChange},
    io::IoPool,
    overlay::OverlayIterator,
    KeyPath, LiveOverlay, Value,
};

/// An iterator over the state of the db at some particular point.
///
/// This combines a [`LiveOverlay`] with the values stored on disk.
pub struct NomtIterator {
    overlay_key_value_iter: Peekable<OverlayIterator>,
    key_value_iter: Peekable<KeyValueIterator>,
}

impl NomtIterator {
    /// Create a NomtOverlay which takes into consideration [`LiveOverlay`]
    /// the in memory overlays and the value stored on disk.
    pub(crate) fn new(
        io_pool: &IoPool,
        read_transaction: ReadTransaction,
        overlay: &LiveOverlay,
        start: KeyPath,
        end: Option<KeyPath>,
    ) -> Self {
        let key_value_iter = read_transaction
            .iterator(io_pool, start.clone(), end.clone())
            .peekable();
        let overlay_key_value_iter = overlay.value_iter(start, end).peekable();

        Self {
            overlay_key_value_iter,
            key_value_iter,
        }
    }
}

impl Iterator for NomtIterator {
    type Item = (KeyPath, Value);

    fn next(&mut self) -> Option<Self::Item> {
        let extract_value = |v: ValueChange| -> Vec<u8> {
            match v {
                ValueChange::Insert(val) | ValueChange::InsertOverflow(val, _) => val,
                ValueChange::Delete => unreachable!(),
            }
        };

        match (
            self.overlay_key_value_iter.peek(),
            self.key_value_iter.peek(),
        ) {
            (None, None) => None,
            (None, Some(_)) => self.key_value_iter.next(),
            (Some((next_overlay_key, next_overlay_value)), None)
                if matches!(next_overlay_value, ValueChange::Delete) =>
            {
                // Something has been added and deleted only within the overlays. Skip it.
                self.overlay_key_value_iter.next();
                self.next()
            }
            (Some(_), None) => self
                .overlay_key_value_iter
                .next()
                .map(|(k, v)| (k.clone(), extract_value(v))),
            (Some((next_overlay_key, next_overlay_value)), Some((next_iter_key, _))) => {
                match (next_overlay_key.cmp(&next_iter_key), &next_overlay_value) {
                    (Ordering::Less, ValueChange::Delete) => {
                        // Something has been added and deleted only within the overlays. Skip it.
                        self.overlay_key_value_iter.next();
                        self.next()
                    }
                    (Ordering::Less, _) => self
                        .overlay_key_value_iter
                        .next()
                        .map(|(k, v)| (k.clone(), extract_value(v))),
                    (Ordering::Equal, ValueChange::Delete) => {
                        self.overlay_key_value_iter.next();
                        self.key_value_iter.next();
                        self.next()
                    }
                    (Ordering::Equal, _) => {
                        self.key_value_iter.next();
                        self.overlay_key_value_iter
                            .next()
                            .map(|(k, v)| (k.clone(), extract_value(v)))
                    }
                    (Ordering::Greater, _) => self.key_value_iter.next(),
                }
            }
        }
    }
}
