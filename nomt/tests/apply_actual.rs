mod common;
use nomt::KeyReadWrite;
use common::Test;
use bitvec::prelude::*;
use bitvec::bits;

#[test]
fn apply_actual() {
    let backup_db_path = "/home/gab/work/data/backup_nomt_100k";

    let db_path =  "/home/gab/work/data/nomt_100k";
    let full_db_path =  "/home/gab/work/data/nomt_100k/chains/dev/dbs/full/nomt/full";

    if std::fs::exists(db_path).unwrap() {
        println!("Removing");
        std::fs::remove_dir_all(db_path).unwrap();
    }

    println!("Copying");
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("cp -r {} {}", backup_db_path, db_path))
        .output()
        .expect("failed to copy");


    let actual_path = "/home/gab/work/data/actual";

    println!("opening");
    let mut t = Test::new_with_params(full_db_path, 1, 5_000_000, None, false);
    println!("opened");

    for i in 0.. {
        let actual_path_name = format!("{}{}", actual_path, i);
        println!("looking for: {actual_path_name}");
        if std::fs::exists(&actual_path_name).unwrap() {
            println!("{i} - reading and committing");
            let raw_actuals = std::fs::read_to_string(&actual_path_name).unwrap();
            let actuals: Vec<(Vec<u8>, KeyReadWrite)> = serde_json::from_str(&raw_actuals).unwrap();
            let mut prev_values = vec![];
            for (key, keyreadwrite) in actuals.iter().by_ref() {
               use bitvec::prelude::*;
               use bitvec::bits;
               if key.view_bits::<Msb0>().starts_with(bits![u8, Msb0; 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0]) {
                    let key_bits =  key.view_bits::<Msb0>();
                    let n_bits = std::cmp::min(key_bits.len(), 24);
                    println!("actual has key: {:?}", &key_bits[..n_bits] );
                    println!("keyreadwrite: {:?}", keyreadwrite );
                }

                let prev_val = t.read(key.clone()).unwrap();

                prev_values.push((key.clone(), prev_val));
            }

            t.commit();

            t.commit_actual(actuals);
            println!("committed");

            println!("init rollback");
            t.rollback();
            println!("rollbacked");

            println!(" prev_values len: {}",  prev_values.len());

            for (key, prev_val) in prev_values {
                let rollbacked_val = t.read(key.clone()).unwrap();
                assert_eq!(rollbacked_val, prev_val);
            }
        } else {
            break;
        }
    }

    println!("DONE");
}

#[test]
fn apply_and_test_each_actual() {
    let actuals_path =  "/home/gab/work/data/fill_100k_bench/actual";

    let mut t = Test::new_with_params("apply_and_test_each_actual", 1, 5_000_000, None, true);

    for i in 0.. {
        let actual_path_name = format!("{}{}", actuals_path, i);
        println!("looking for: {actual_path_name}");
        if !std::fs::exists(&actual_path_name).unwrap() {
            println!("FINISHED WITH ACTUALS");
            break;
        }

        println!("COMMIT: {i}");
        let raw_actuals = std::fs::read_to_string(&actual_path_name).unwrap();
        let actuals: Vec<(Vec<u8>, nomt::KeyReadWrite)> = serde_json::from_str(&raw_actuals).unwrap();

        let mut read_count = 0;
        let mut write_count = 0;
        let mut read_write_count = 0;

        // for (key, keyreadwrite ) in &actuals {

        //     // if key.view_bits::<Msb0>().starts_with(bits![u8, Msb0; 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1]) {
        //     if key.view_bits::<Msb0>().starts_with(bits![u8, Msb0; 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1]) {
        //         let bits = key.view_bits::<Msb0>();
        //         println!("Writing key len:  {}Byte - {} bits", key.len(), bits.len());
        //         let n = std::cmp::min(128 + 18, bits .len());
        //         println!("Writing key bits: {:?}", &bits);
        //         println!("keyreadwrite: {:?}", keyreadwrite );
        //     }

        //     match  keyreadwrite {
        //         KeyReadWrite::Read(_) => read_count += 1,
        //         KeyReadWrite::Write(_) => write_count += 1,
        //         KeyReadWrite::ReadThenWrite(_, _) =>  read_write_count += 1,
        //      }
        // }

        println!("Writing {} actuals", actuals.len());
        println!("Writing {} read", read_count);
        println!("Writing {} write", write_count);
        println!("Writing {} read and write", read_write_count);

        // NOTE: the error is here?
        t.commit_actual(actuals.clone());

        println!("Committed actuals");

        println!("Init reading actuals");
        for (key, keyreadwrite) in actuals.iter().by_ref() {
            match  keyreadwrite {
                KeyReadWrite::Read(expected_read_value) => {
                     let read_value = t.read(key.clone());
                     t.commit();
                     assert_eq!(read_value, expected_read_value.clone());
                },
                KeyReadWrite::Write(expected_value) => {
                    let value = t.read(key.clone());
                     t.commit();
                    assert_eq!(value, expected_value.clone());
                },
                KeyReadWrite::ReadThenWrite(_, expected_value) => {
                    let value = t.read(key.clone());
                     t.commit();
                    assert_eq!(value, expected_value.clone());
                }
            }
        }
        println!("Done reading actuals");
    }
}

#[test]
fn fill_and_bench() {
    let actuals_path =  "/home/gab/work/data/fill/committed_actual";

    let mut t = Test::new_with_params("fill_and_bench", 1, 5_000_000, None, true);

    let mut present_keys = std::collections::HashSet::<Vec<u8>>::new();

    for i in 0.. {
        let actual_path_name = format!("{}{}", actuals_path, i);
        println!("looking for: {actual_path_name}");
        if !std::fs::exists(&actual_path_name).unwrap() {
            println!("FINISHED WITH ACTUALS");
            break;
        }

        println!("COMMITING: {i}");
        let raw_actuals = std::fs::read_to_string(&actual_path_name).unwrap();
        let actuals: Vec<(Vec<u8>, nomt::KeyReadWrite)> = serde_json::from_str(&raw_actuals).unwrap();

        t.commit_actual(actuals.clone());
        println!("COMMTTED: {i}");

        for (key, keyreadwrite) in actuals.iter().by_ref() {
            match  keyreadwrite {
                KeyReadWrite::Write(Some(_)) | KeyReadWrite::ReadThenWrite(_, Some(_)) => {
                    present_keys.insert(key.clone());
                },
                KeyReadWrite::Write(None) | KeyReadWrite::ReadThenWrite(_, None) => {
                    present_keys.remove(key);
                },
                _ => ()
            }
        }

        // NOTE: this has just been checked once, can be skiped now.
        // println!("Check Presence");
        // let mut keys_to_read: Vec<_> = present_keys.iter().cloned().collect();
        // for chunk_of_keys in keys_to_read.chunks(10_000) {
        //     for key in chunk_of_keys {
        //         assert!(t.read(key.to_vec()).is_some());
        //     }
        //     t.commit();
        // }
    }

    println!("Fill DONE");
    println!("");
    println!("");

    use bitvec::prelude::*;
    for key in present_keys.iter().by_ref() {
        if key
            .view_bits::<Msb0>()
            .starts_with(bits![u8, Msb0; 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0]) {
            println!("present key: {:?}", key .view_bits::<Msb0>());
        }
    }
    println!("");

    drop(t);
    println!("Opening again");
    let mut t = Test::new_with_params("fill_and_bench", 1, 5_000_000, None, false);
    println!("Opened");

    let actuals_path =  "/home/gab/work/data/bench/actual";
    for i in 0.. {
        let actual_path_name = format!("{}{}", actuals_path, i);
        println!("looking for: {actual_path_name}");
        if !std::fs::exists(&actual_path_name).unwrap() {
            println!("FINISHED WITH ACTUALS");
            break;
        }

        println!("BENCH COMMIT: {i}");
        let raw_actuals = std::fs::read_to_string(&actual_path_name).unwrap();
        let actuals: Vec<(Vec<u8>, nomt::KeyReadWrite)> = serde_json::from_str(&raw_actuals).unwrap();

        t.commit_actual(actuals.clone());
        println!("BENCH COMMTTED: {i}");

        t.rollback();
        println!("ROLLABACK");

        // println!("Check Presence");
        // let mut keys_to_read: Vec<_> = present_keys.iter().cloned().collect();
        // println!("tot keys: {}", keys_to_read.len());
        // for chunk_of_keys in keys_to_read.chunks(10_000) {
        //     println!("keys read this chunk: {}", chunk_of_keys.len());
        //     for key in chunk_of_keys {
        //         assert!(t.read(key.to_vec()).is_some());
        //     }
        //     t.commit();
        // }
    }
}
