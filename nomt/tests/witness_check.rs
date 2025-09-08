mod common;

use common::Test;
use nomt::{
    hasher::Blake3Hasher,
    proof::{self, MultiProof},
    trie::LeafData,
    Root, Witness, WitnessedPath,
};

//fn prepare_for_witness_check(name: &str) -> (Root, Root, Witness) {
//let mut t = Test::new(name);
//
//let k1 = vec![0; 56];
//let mut k2 = k1.clone();
//*k2.last_mut().unwrap() += 1;
//
//let k3 = vec![1, 2];
//
//let k4 = vec![3; 900];
//let mut k5 = k4.clone();
//*k5.last_mut().unwrap() += 1;
//
//let k6 = vec![85; 500];
//let mut k7 = k6.clone();
//*k7.last_mut().unwrap() += 1;
//
//let k8 = vec![150; 432];
//let mut k9 = k8.clone();
//*k9.last_mut().unwrap() += 1;
//
//let k10 = vec![255; 1000];
//
//let k11 = vec![12, 12, 12];
//let k12 = vec![12, 12, 12, 0, 0, 0, 0, 0, 0, 0, 1];
//
//let k13 = vec![37, 37, 37, 37, 37, 37];
//let k14 = vec![37, 37, 37, 37, 37, 37, 0, 0, 0, 0, 0, 0, 0, 1];
//
//let (prev_root, _) = {
//t.write(k1.clone(), Some(vec![1]));
//t.write(k2.clone(), Some(vec![2]));
//t.write(k3.clone(), Some(vec![3]));
//t.write(k4.clone(), Some(vec![4]));
//t.write(k5.clone(), Some(vec![5]));
//t.write(k6.clone(), Some(vec![6]));
//t.write(k7.clone(), Some(vec![7]));
//t.write(k8.clone(), Some(vec![8]));
//t.write(k9.clone(), Some(vec![9]));
//t.write(k10.clone(), Some(vec![10]));
//t.write(k11.clone(), Some(vec![11]));
//t.write(k12.clone(), Some(vec![12]));
//t.write(k13.clone(), Some(vec![13]));
//t.write(k14.clone(), Some(vec![14]));
//t.commit()
//};
//
//let (new_root, witness) = {
//// read two long keys
//t.read(k1);
//t.read(k2);
//
//// read short key
//t.read(k3);
//
//// update two long keys
//t.write(k4, Some(vec![10]));
//t.write(k5, Some(vec![11]));
//
//// update and delete long keys
//t.write(k6.clone(), None);
//t.write(k7.clone(), Some(vec![12]));
//
//t.write(k8.clone(), Some(vec![13]));
//t.write(k9.clone(), None);
//
//// read single long keys
//t.read(k10);
//
//// read keys with zero padding
//t.read(k11);
//t.read(k12);
//
//// delete key with zero padding
//t.write(k13, None);
//
//t.commit()
//};
//let witness = witness.unwrap();
//
//assert_eq!(witness.operations.reads.len(), 6);
//assert_eq!(witness.operations.writes.len(), 7);
//(prev_root, new_root, witness)
//}
//
//// TODO: add them back once the proofs are adapted to jumps
////#[test]
////fn witness_with_var_len_keys() {
////let (prev_root, new_root, witness) = prepare_for_witness_check("witness_with_var_len_keys");
////let mut updates = Vec::new();
////for (i, witnessed_path) in witness.path_proofs.iter().enumerate() {
////let verified = witnessed_path
////.inner
////.verify::<Blake3Hasher>(&witnessed_path.path.path(), prev_root.into_inner())
////.unwrap();
////for read in witness
////.operations
////.reads
////.iter()
////.skip_while(|r| r.path_index != i)
////.take_while(|r| r.path_index == i)
////{
////match read.value {
////None => assert!(verified.confirm_nonexistence(&read.key).unwrap()),
////Some(ref v) => {
////let leaf = LeafData {
////key_path: read.key.clone(),
////value_hash: *v,
////collision: false,
////};
////assert!(verified
////.confirm_value::<Blake3Hasher>(&leaf.key_path, leaf.value_hash)
////.unwrap());
////}
////}
////}
////
////let mut write_ops = Vec::new();
////for write in witness
////.operations
////.writes
////.iter()
////.skip_while(|r| r.path_index != i)
////.take_while(|r| r.path_index == i)
////{
////write_ops.push((write.key.clone(), write.value.clone()));
////}
////
////if !write_ops.is_empty() {
////updates.push(proof::PathUpdate {
////inner: verified,
////ops: write_ops,
////});
////}
////}
////
////assert_eq!(
////proof::verify_update::<Blake3Hasher>(prev_root.into_inner(), &updates).unwrap(),
////new_root.into_inner(),
////);
////}
//
////#[test]
////fn multiproof_with_var_len_keys() {
////let (prev_root, new_root, witness) = prepare_for_witness_check("multiproof_with_var_len_keys");
////let mut path_proofs: Vec<_> = witness
////.path_proofs
////.into_iter()
////.map(|WitnessedPath { inner, .. }| inner)
////.collect();
////path_proofs.sort_by(|p1, p2| p1.terminal.path().cmp(p2.terminal.path()));
////
////let multi_proof = MultiProof::from_path_proofs(path_proofs);
////let verified_multi_proof =
////nomt_core::proof::verify_multi_proof::<Blake3Hasher>(&multi_proof, prev_root.into_inner())
////.unwrap();
////
////for read in witness.operations.reads {
////let index = verified_multi_proof.find_index_for(&read.key).unwrap();
////assert_eq!(index, read.path_index);
////
////match read.value {
////None => {
////assert!(verified_multi_proof
////.confirm_nonexistence(&read.key)
////.unwrap());
////assert!(verified_multi_proof
////.confirm_nonexistence_with_index(&read.key, index)
////.unwrap());
////}
////Some(ref v) => {
////let leaf = LeafData {
////key_path: read.key.clone(),
////value_hash: *v,
////collision: false,
////};
////assert!(verified_multi_proof
////.confirm_value(&leaf.key_path, leaf.value_hash)
////.unwrap());
////assert!(verified_multi_proof
////.confirm_value_with_index(&leaf.key_path, leaf.value_hash, index)
////.unwrap());
////}
////}
////}
////
////let updates: Vec<_> = witness
////.operations
////.writes
////.into_iter()
////.map(|w| (w.key, w.value))
////.collect();
////
////assert_eq!(
////proof::verify_multi_proof_update::<Blake3Hasher>(&verified_multi_proof, updates).unwrap(),
////new_root.into_inner(),
////);
////}
//
//#[test]
//fn witness_with_collision_keys() {
//let (prev_root, new_root, witness) = {
//let mut t = Test::new("witness_with_collision_keys");
//
//let k1 = vec![0, 0, 0];
//let k2 = vec![0, 0, 0, 0, 0];
//let k3 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0];
//let k4 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//let k5 = vec![0, 0, 1];
//
//let k6 = vec![0, 0, 0, 0];
//let k7 = vec![0, 0, 0, 0, 0, 0, 0, 0, 1];
//
//let k_wrong1 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
//let k_wrong2 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//
//let (prev_root, _) = {
//t.write(k1.clone(), Some(vec![1]));
//t.write(k2.clone(), Some(vec![2]));
//t.write(k3.clone(), Some(vec![3]));
//t.write(k4.clone(), Some(vec![4]));
//t.write(k5.clone(), Some(vec![5]));
//t.commit()
//};
//
//let (new_root, witness) = {
//// read a keys from the collision subtree
//t.read(k1);
//t.read(k2.clone());
//t.read(k3.clone());
//t.read(k4);
//t.read(k5.clone());
//
//// read a key which doesn not collide and is not present in the subtree
//assert!(t.read(k_wrong1).is_none());
//
//// read a key which collides but is not in the collision subtree
//assert!(t.read(k_wrong2).is_none());
//
//// Write new key within the collision subtree
//t.write(k6.clone(), Some(vec![5]));
//
//// Delete a key from the collision subtree
//t.write(k3.clone(), None);
//
////// Modify a leaf within the collision subtree
//t.write(k2.clone(), Some(vec![6]));
//
//// Add a leaf which goes on top of a collison leaf
//// but do not collides
//t.write(k7.clone(), Some(vec![7]));
//
////// Remove a key which should move the collision leaf
//t.write(k5.clone(), Some(vec![7]));
//
//t.commit()
//};
//let witness = witness.unwrap();
//
//assert_eq!(witness.operations.reads.len(), 7);
//assert_eq!(witness.operations.writes.len(), 5);
//(prev_root, new_root, witness)
//};
//
//let mut updates = Vec::new();
//for (i, witnessed_path) in witness.path_proofs.iter().enumerate() {
//let verified = witnessed_path
//.inner
//.verify::<Blake3Hasher>(&witnessed_path.path.path(), prev_root.into_inner())
//.unwrap();
//for read in witness
//.operations
//.reads
//.iter()
//.skip_while(|r| r.path_index != i)
//.take_while(|r| r.path_index == i)
//{
//match read.value {
//None => assert!(verified.confirm_nonexistence(&read.key).unwrap()),
//Some(ref v) => {
//let leaf = LeafData {
//key_path: read.key.clone(),
//value_hash: *v,
//collision: false,
//};
//assert!(verified
//.confirm_value::<Blake3Hasher>(&leaf.key_path, leaf.value_hash)
//.unwrap());
//}
//}
//}
//
//let mut write_ops = Vec::new();
//for write in witness
//.operations
//.writes
//.iter()
//.skip_while(|r| r.path_index != i)
//.take_while(|r| r.path_index == i)
//{
//write_ops.push((write.key.clone(), write.value.clone()));
//}
//
//if !write_ops.is_empty() {
//updates.push(proof::PathUpdate {
//inner: verified,
//ops: write_ops,
//});
//}
//}
//
//assert_eq!(
//proof::verify_update::<Blake3Hasher>(prev_root.into_inner(), &updates).unwrap(),
//new_root.into_inner(),
//);
//}
//
//#[test]
//fn multiproof_with_collision_keys() {
//let (prev_root, new_root, witness) = {
//let mut t = Test::new("multiproof_with_collision_keys");
//
//let k1 = vec![0, 0, 0];
//let k2 = vec![0, 0, 0, 0, 0];
//let k3 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0];
//let k4 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//let k5 = vec![0, 0, 1];
//
//let k6 = vec![0, 0, 0, 0];
//let k7 = vec![0, 0, 0, 0, 0, 0, 0, 0, 1];
//
//let k_wrong1 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
//let k_wrong2 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//let k_wrong_eq_len = vec![0, 0, 0, 0, 0, 0, 0, 0, 1];
//
//let (prev_root, _) = {
//t.write(k1.clone(), Some(vec![1]));
//t.write(k2.clone(), Some(vec![2]));
//t.write(k3.clone(), Some(vec![3]));
//t.write(k4.clone(), Some(vec![4]));
//t.write(k5.clone(), Some(vec![5]));
//t.commit()
//};
//
//let (new_root, witness) = {
//// read a keys from the collision subtree
//t.read(k1);
//t.read(k2.clone());
//t.read(k3.clone());
//t.read(k4);
//t.read(k5.clone());
//
//// read a key which does not collide and is not present in the subtree
//assert!(t.read(k_wrong1).is_none());
//
//// read a key that does not collide, is not present in the subtree,
//// but has the same length of another key in the collision subtree
//assert!(t.read(k_wrong_eq_len).is_none());
//
//// read a key which collides but is not in the collision subtree
//assert!(t.read(k_wrong2).is_none());
//
//// Write new key within the collision subtree
//t.write(k6.clone(), Some(vec![5]));
//
//// Delete a key from the collision subtree
//t.write(k3.clone(), None);
//
//// Modify a leaf within the collision subtree
//t.write(k2.clone(), Some(vec![6]));
//
//// Add a leaf which goes on top of a collison leaf
//// but do not collides
//t.write(k7.clone(), Some(vec![7]));
//
//// Remove a key which should move the collision leaf
//t.write(k5.clone(), Some(vec![7]));
//
//t.commit()
//};
//let witness = witness.unwrap();
//
//assert_eq!(witness.operations.reads.len(), 8);
//assert_eq!(witness.operations.writes.len(), 5);
//(prev_root, new_root, witness)
//};
//
//let mut path_proofs: Vec<_> = witness
//.path_proofs
//.into_iter()
//.map(|WitnessedPath { inner, .. }| inner)
//.collect();
//path_proofs.sort_by(|p1, p2| p1.terminal.path().cmp(p2.terminal.path()));
//
//let multi_proof = MultiProof::from_path_proofs(path_proofs);
//let verified_multi_proof =
//nomt_core::proof::verify_multi_proof::<Blake3Hasher>(&multi_proof, prev_root.into_inner())
//.unwrap();
//
//for read in witness.operations.reads {
//let index = verified_multi_proof.find_index_for(&read.key).unwrap();
//assert_eq!(index, read.path_index);
//
//match read.value {
//None => {
//assert!(verified_multi_proof
//.confirm_nonexistence(&read.key)
//.unwrap());
//assert!(verified_multi_proof
//.confirm_nonexistence_with_index(&read.key, index)
//.unwrap());
//}
//Some(ref v) => {
//let leaf = LeafData {
//key_path: read.key.clone(),
//value_hash: *v,
//collision: false,
//};
//assert!(verified_multi_proof
//.confirm_value(&leaf.key_path, leaf.value_hash)
//.unwrap());
//assert!(verified_multi_proof
//.confirm_value_with_index(&leaf.key_path, leaf.value_hash, index)
//.unwrap());
//}
//}
//}
//
//let updates: Vec<_> = witness
//.operations
//.writes
//.into_iter()
//.map(|w| (w.key, w.value))
//.collect();
//
//assert_eq!(
//proof::verify_multi_proof_update::<Blake3Hasher>(&verified_multi_proof, updates).unwrap(),
//new_root.into_inner(),
//);
//}
//
//#[test]
//fn produced_witness_validity() {
//let mut accounts = 0;
//let mut t = Test::new("witness_validity");
//let (prev_root, _) = {
//for _ in 0..10 {
//common::set_balance(&mut t, accounts, 1000);
//accounts += 1;
//}
//t.commit()
//};
//
//let (new_root, witness) = {
//// read all existing accounts.
//for i in 0..accounts {
//t.read_id(i);
//}
//
//// read some nonexistent accounts.
//for i in 100..105 {
//t.read_id(i);
//}
//
//// kill half the existing ones.
//for i in 0..5 {
//common::kill(&mut t, i);
//}
//
//// and add 5 more.
//for _ in 0..5 {
//common::set_balance(&mut t, accounts, 1000);
//accounts += 1;
//}
//t.commit()
//};
//let witness = witness.unwrap();
//
//assert_eq!(witness.operations.reads.len(), 15); // 10 existing + 5 nonexisting
//assert_eq!(witness.operations.writes.len(), 10); // 5 deletes + 5 inserts
//
//let mut updates = Vec::new();
//for (i, witnessed_path) in witness.path_proofs.iter().enumerate() {
//let verified = witnessed_path
//.inner
//.verify::<Blake3Hasher>(&witnessed_path.path.path(), prev_root.into_inner())
//.unwrap();
//for read in witness
//.operations
//.reads
//.iter()
//.skip_while(|r| r.path_index != i)
//.take_while(|r| r.path_index == i)
//{
//match read.value {
//None => assert!(verified.confirm_nonexistence(&read.key).unwrap()),
//Some(ref v) => {
//let leaf = LeafData {
//key_path: read.key.clone(),
//value_hash: *v,
//collision: false,
//};
//assert!(verified
//.confirm_value::<nomt::hasher::Blake3Hasher>(
//&leaf.key_path,
//leaf.value_hash
//)
//.unwrap());
//}
//}
//}
//
//let mut write_ops = Vec::new();
//for write in witness
//.operations
//.writes
//.iter()
//.skip_while(|r| r.path_index != i)
//.take_while(|r| r.path_index == i)
//{
//write_ops.push((write.key.clone(), write.value.clone()));
//}
//
//if !write_ops.is_empty() {
//updates.push(proof::PathUpdate {
//inner: verified,
//ops: write_ops,
//});
//}
//}
//
//assert_eq!(
//proof::verify_update::<Blake3Hasher>(prev_root.into_inner(), &updates).unwrap(),
//new_root.into_inner(),
//);
//}
//
//#[test]
//fn empty_witness() {
//let mut accounts = 0;
//let mut t = Test::new("empty_witness");
//
//let (prev_root, _) = {
//for _ in 0..10 {
//common::set_balance(&mut t, accounts, 1000);
//accounts += 1;
//}
//t.commit()
//};
//
//// Create a commit with no operations performed
//let (new_root, witness) = t.commit();
//let witness = witness.unwrap();
//
//// The roots should be identical since no changes were made
//assert_eq!(prev_root, new_root);
//
//// The witness should be empty
//assert_eq!(witness.operations.reads.len(), 0);
//assert_eq!(witness.operations.writes.len(), 0);
//assert_eq!(witness.path_proofs.len(), 0);
//
//// Verify that an empty update produces the same root
//let updates: Vec<proof::PathUpdate> = Vec::new();
//assert_eq!(
//proof::verify_update::<Blake3Hasher>(prev_root.into_inner(), &updates).unwrap(),
//new_root.into_inner(),
//);
//}
//
//#[test]
//fn test_verify_update_with_identical_paths() {
//use nomt::{
//hasher::Blake3Hasher,
//proof::{verify_update, PathUpdate},
//trie::ValueHash,
//};
//
//let account0 = 0;
//
//// Create a simple trie, create an update witness.
//let mut t = Test::new("identical_paths_test");
//common::set_balance(&mut t, account0, 1000);
//let (root, _) = t.commit();
//t.read_id(account0);
//let (_, witness) = t.commit();
//let witness = witness.unwrap();
//
//// Using that witness extract and verify the proof.
//let witnessed_path = &witness.path_proofs[0];
//let verified_proof = witnessed_path
//.inner
//.verify::<Blake3Hasher>(&witnessed_path.path.path(), root.into_inner())
//.unwrap();
//
//// Create two identical PathUpdate objects
//let mut updates = Vec::new();
//
//// First update
//let value1 = ValueHash::default();
//let ops1 = vec![(vec![0; 32], Some(value1))];
//updates.push(PathUpdate {
//inner: verified_proof.clone(),
//ops: ops1,
//});
//
//// Second update with identical path
//let value2 = ValueHash::default();
//let ops2 = vec![(vec![1; 32], Some(value2))];
//updates.push(PathUpdate {
//inner: verified_proof, // Using the same verified proof
//ops: ops2,
//});
//
//// Try to verify the update. We expect an error due to identical paths, because that violates
//// the requirement of ascending keys.
//verify_update::<Blake3Hasher>(root.into_inner(), &updates).unwrap_err();
//}
