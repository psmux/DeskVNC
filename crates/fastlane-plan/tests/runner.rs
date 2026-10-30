//! The runner against a pretend desk: a Run box that opens Notepad, and a
//! popup in the way that has to be sent off.

use fastlane_plan::{Desk, Runner, Step, Table};
use serde_json::{json, Value};

/// Screens the desk moves between, and what was done to it.
struct Pretend {
    screen: &'static str,
    done: Vec<String>,
    /// The popup comes up the first time Notepad is asked for.
    popup_once: bool,
}

fn screen(name: &str) -> Table {
    let body = match name {
        "desktop" => json!({"window": {"title": "Program Manager"}, "elements": [
            {"area": "taskbar", "role": "button", "name": "Start", "y": 1040}]}),
        "run" => json!({"window": {"title": "Run"}, "elements": [
            {"role": "combobox", "name": "Open:", "x": 100, "y": 200, "w": 200, "h": 20},
            {"role": "button", "name": "OK", "x": 100, "y": 260}]}),
        "popup" => json!({"window": {"title": "Run"}, "elements": [
            {"role": "text", "name": "Try the new Notepad?"},
            {"role": "button", "name": "Close tab", "y": 300},
            {"role": "button", "name": "Not now", "x": 400, "y": 300}]}),
        "notepad" => json!({"window": {"title": "Untitled - Notepad"}, "elements": [
            {"role": "document", "name": "Text editor", "focus": true, "w": 1600, "h": 900},
            {"role": "text", "name": "Hello", "x": 20, "y": 100},
            {"role": "text", "name": "Ln 1, Col 6", "x": 20, "y": 1000}]}),
        _ => unreachable!(),
    };
    let mut table: Table = serde_json::from_value(body).unwrap();
    table.hash = name.into();
    table
}

impl Desk for Pretend {
    async fn snapshot(&mut self) -> Result<Table, String> {
        Ok(screen(self.screen))
    }
    async fn settle(&mut self, _after: &str, _change_ms: u64, _max_ms: u64) -> Result<Table, String> {
        Ok(screen(self.screen))
    }
    async fn key(&mut self, keys: &str) -> Result<(), String> {
        self.done.push(format!("key {keys}"));
        match (self.screen, keys) {
            ("desktop", "super+r") => self.screen = "run",
            ("run", "Enter") if self.popup_once => {
                self.popup_once = false;
                self.screen = "popup";
            }
            ("run", "Enter") => self.screen = "notepad",
            _ => {}
        }
        Ok(())
    }
    async fn type_text(&mut self, text: &str) -> Result<(), String> {
        self.done.push(format!("type {text}"));
        Ok(())
    }
    async fn click(&mut self, x: i64, y: i64) -> Result<(), String> {
        self.done.push(format!("click {x},{y}"));
        if self.screen == "popup" && (x, y) == (450, 310) {
            self.screen = "run";
        }
        Ok(())
    }
    async fn pause(&mut self, _ms: u64) {}
}

fn steps(plan: Value) -> Vec<Step> {
    plan.as_array().unwrap().iter().map(|s| Step::parse(s).unwrap()).collect()
}

#[tokio::test]
async fn a_plan_runs_and_sends_a_popup_away_by_its_safest_button() {
    let desk = Pretend { screen: "desktop", done: Vec::new(), popup_once: true };
    let plan = steps(json!([
        {"key": "super+r", "expect": {"window": "Run"}},
        {"type": "notepad", "into": "Open"},
        {"key": "Enter", "expect": {"window": "Notepad"}},
        {"read": ""}
    ]));
    let outcome = Runner::new(desk).await.unwrap().run(&plan).await;
    let result = outcome.to_json();
    assert!(result.get("failed").is_none(), "{result:#}");
    assert_eq!(result["front"]["title"], "Untitled - Notepad");
    let did: Vec<&str> = outcome.log.iter().filter_map(|e| e["did"].as_str()).collect();
    assert_eq!(did, [
        "pressed super+r",
        "typed \"notepad\" into Open:",
        "dismissed with Not now",
        "pressed Enter",
    ]);
    assert_eq!(outcome.log.last().unwrap()["read"], json!(["Hello"]));
}

#[tokio::test]
async fn a_missing_control_fails_the_plan_after_two_recoveries() {
    let desk = Pretend { screen: "notepad", done: Vec::new(), popup_once: false };
    let plan = steps(json!([{"click": "Save"}, {"key": "Enter"}]));
    let result = Runner::new(desk).await.unwrap().run(&plan).await.to_json();
    assert_eq!(result["failed"], json!({"click": "Save"}));
    let log = result["log"].as_array().unwrap();
    assert_eq!(log.iter().filter(|e| e["did"] == "pressed Escape").count(), 2);
    assert_eq!(log.last().unwrap()["missing"], "Save");
}

#[test]
fn steps_that_do_not_say_one_thing_are_refused() {
    assert!(Step::parse(&json!({"goal": "save the file"})).is_err());
    assert!(Step::parse(&json!({"key": "Enter", "click": "OK"})).is_err());
    assert!(Step::parse(&json!({"expect": {"window": "Run"}})).is_err());
    assert!(Step::parse(&json!({"key": "Enter", "wait": 3})).is_err());
}
