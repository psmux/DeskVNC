//! The spec's cases, the same file the Python prototype checks.

use fastlane_plan::rules::{self, Table, CLICKABLE, EDITABLE};
use serde_json::{json, Value};

const CASES: &str = include_str!("../../../tools/fastlane/spec/cases.json");

fn table(case: &Value) -> Table {
    let mut table: Table = serde_json::from_value(case["table"].clone()).expect("case table");
    for (n, row) in table.elements.iter_mut().enumerate() {
        if row.i == 0 {
            row.i = n as u32 + 1;
        }
    }
    table
}

fn outcome(case: &Value) -> Value {
    let table = table(case);
    let i = |row: Option<&rules::Row>| row.map_or(Value::Null, |r| json!(r.i));
    match case["check"].as_str().unwrap() {
        "find" => match case["click"].as_str() {
            Some(name) => i(rules::find(&table.elements, name, CLICKABLE)),
            None => i(rules::find(&table.elements, case["into"].as_str().unwrap(), EDITABLE)),
        },
        "recover" => {
            let picks = if case["typo"] == json!(true) { Vec::new() } else { rules::dismissers(&table) };
            picks.first().map_or(json!("Escape"), |r| json!(r.i))
        }
        "met" => json!(rules::met(&serde_json::from_value(case["expect"].clone()).unwrap(), &table)),
        "read" => json!(rules::read(&table, case["read"].as_str().unwrap(), case["limit"].as_u64().unwrap_or(15) as usize)),
        "echo" => json!(rules::echoed(case["type"].as_str().unwrap(), &table)),
        other => panic!("unknown check {other}"),
    }
}

#[test]
fn every_case_in_the_spec_passes() {
    let spec: Value = serde_json::from_str(CASES).unwrap();
    assert_eq!(spec["version"], json!(fastlane_plan::SPEC_VERSION));
    let cases = spec["cases"].as_array().unwrap();
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            let got = outcome(case);
            (got != case["want"]).then(|| format!("{}: want {}, got {got}", case["name"], case["want"]))
        })
        .collect();
    assert!(failures.is_empty(), "{} of {} cases fail:\n{}", failures.len(), cases.len(), failures.join("\n"));
}
