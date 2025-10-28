mod common;
use common::Test;

#[test]
fn apply_actual() {
    let db_path = "";
    let actual_path = "";

    let mut t = Test::new_with_params(db_path, 1, 64_000, None, false);
    let raw_actuals = std::fs::read_to_string(&actual_path).unwrap();

    let actuals = serde_json::from_str(&raw_actuals).unwrap();

    t.commit_actual(actuals);
}
