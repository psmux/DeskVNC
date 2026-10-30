//! Carrying out a plan: one step at a time, reading the screen only when a
//! step needs it, and recovering from what the plan did not expect.

use std::future::Future;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::rules::{self, Expect, Table, CLICKABLE, EDITABLE};

/// The screen and the hands a runner works through. DeskVNC gives it the
/// sense for eyes and a limb for hands; a browser would give it a page.
pub trait Desk: Send {
    /// Read the screen now.
    fn snapshot(&mut self) -> impl Future<Output = Result<Table, String>> + Send;
    /// Read until the table differs from `after` and then holds still, or
    /// until `change_ms` passes with no change, or `max_ms` in all.
    fn settle(&mut self, after: &str, change_ms: u64, max_ms: u64) -> impl Future<Output = Result<Table, String>> + Send;
    fn key(&mut self, keys: &str) -> impl Future<Output = Result<(), String>> + Send;
    fn type_text(&mut self, text: &str) -> impl Future<Output = Result<(), String>> + Send;
    fn click(&mut self, x: i64, y: i64) -> impl Future<Output = Result<(), String>> + Send;
    fn pause(&mut self, ms: u64) -> impl Future<Output = ()> + Send;
}

/// One step of a plan, as `tools/fastlane/spec` writes it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, rename = "type")]
    pub text: Option<String>,
    #[serde(default)]
    pub into: Option<String>,
    #[serde(default)]
    pub replace: Option<bool>,
    #[serde(default)]
    pub click: Option<String>,
    #[serde(default)]
    pub read: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub when: Option<Expect>,
    #[serde(default)]
    pub expect: Option<Expect>,
    #[serde(default)]
    pub expect_ms: Option<u64>,
    #[serde(default)]
    pub echo: bool,
    /// The step as the plan wrote it, for the log.
    #[serde(skip)]
    pub source: Value,
}

impl Step {
    /// A step from JSON, refused unless it does exactly one thing.
    pub fn parse(value: &Value) -> Result<Step, String> {
        if value.get("goal").is_some() {
            return Err("a goal step needs a model to choose the action; write it as key, type, click or read".into());
        }
        let mut step: Step = serde_json::from_value(value.clone()).map_err(|e| format!("step {value}: {e}"))?;
        step.source = value.clone();
        let actions = [step.key.is_some(), step.text.is_some(), step.click.is_some(), step.read.is_some()];
        if actions.iter().filter(|a| **a).count() != 1 {
            return Err(format!("step {value} must have exactly one of key, type, click or read"));
        }
        Ok(step)
    }

    fn expect(&self) -> Option<&Expect> {
        self.expect.as_ref().filter(|e| !e.is_empty())
    }
}

/// What a plan did.
pub struct Outcome {
    pub log: Vec<Value>,
    pub actions: usize,
    pub failed: Option<Value>,
    pub table: Table,
    pub seconds: f64,
}

impl Outcome {
    /// The result an agent gets: the log, and the screen as it ended so it
    /// can check the outcome or plan from there without a picture.
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "seconds": (self.seconds * 100.0).round() / 100.0,
            "actions": self.actions,
            "log": self.log,
            "front": { "title": self.table.window.title, "class": self.table.window.class },
            "controls": rules::rows_text(&self.table),
        });
        if let Some(failed) = &self.failed {
            out["failed"] = failed.clone();
        }
        out
    }
}

/// How many times a failed step is tried again after a recovery.
const RETRIES: usize = 2;

/// How long a step's expectation gets by default, in milliseconds.
const EXPECT_MS: u64 = 4000;

pub struct Runner<D: Desk> {
    desk: D,
    table: Table,
    /// The last step expected nothing, so the screen has not been read since.
    stale: bool,
    started: Instant,
    log: Vec<Value>,
}

impl<D: Desk> Runner<D> {
    pub async fn new(mut desk: D) -> Result<Runner<D>, String> {
        let table = desk.snapshot().await?;
        Ok(Runner { desk, table, stale: false, started: Instant::now(), log: Vec::new() })
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// The screen as it is now, read only once something needs it.
    async fn table(&mut self) -> Result<&Table, String> {
        if self.stale {
            self.stale = false;
            self.table = self.desk.settle(&self.table.hash, 300, 5000).await?;
        }
        Ok(&self.table)
    }

    async fn settle(&mut self, expect: Option<&Expect>, limit: u64) -> Result<u64, String> {
        let started = Instant::now();
        let change = if expect.is_some() { 1000 } else { 300 };
        self.table = self.desk.settle(&self.table.hash, change, 5000).await?;
        let none = Expect::default();
        let expect = expect.unwrap_or(&none);
        // Bounded by count as well as time, so a desk that answers at once
        // cannot spin here.
        for _ in 0..20 {
            if rules::met(expect, &self.table) || started.elapsed() >= Duration::from_millis(limit) {
                break;
            }
            self.table = self.desk.settle(&self.table.hash, limit, limit).await?;
        }
        Ok(started.elapsed().as_millis() as u64)
    }

    /// Run every step until one fails. Errors from the desk end the plan.
    pub async fn run(mut self, steps: &[Step]) -> Outcome {
        let mut failed = None;
        for step in steps {
            match self.step(step).await {
                Ok(true) => {}
                Ok(false) => {
                    failed = Some(step.source.clone());
                    break;
                }
                Err(e) => {
                    failed = Some(json!({ "error": e }));
                    break;
                }
            }
        }
        if self.stale {
            let _ = self.table().await;
        }
        Outcome {
            actions: self.log.iter().filter(|e| e.get("did").is_some()).count(),
            log: self.log,
            failed,
            table: self.table,
            seconds: self.started.elapsed().as_secs_f64(),
        }
    }

    /// One step, recovering and trying again when it does not work.
    async fn step(&mut self, step: &Step) -> Result<bool, String> {
        for attempt in 0..=RETRIES {
            let mut entry = self.attempt(step).await?;
            if entry.get("ok").is_some() {
                entry.as_object_mut().map(|e| e.remove("ok"));
                self.log.push(entry);
                return Ok(true);
            }
            if attempt < RETRIES {
                let typo = entry.get("echo") == Some(&json!(false));
                self.recover(typo).await?;
                continue;
            }
            entry["failed"] = json!(true);
            self.log.push(entry);
        }
        Ok(false)
    }

    async fn attempt(&mut self, step: &Step) -> Result<Value, String> {
        let mut entry = json!({ "t": self.now(), "step": step.source });
        if let Some(when) = &step.when {
            if !rules::met(when, self.table().await?) {
                entry["skipped"] = json!(true);
                entry["ok"] = json!(true);
                return Ok(entry);
            }
        }
        let finds = step.click.is_some() || step.into.is_some();
        if finds || step.read.is_some() {
            self.table().await?;
        }
        // A partial table is a window that has not answered yet: look again
        // before calling a control missing.
        for _ in 0..8 {
            if !finds || !self.table.partial {
                break;
            }
            self.desk.pause(400).await;
            self.table = self.desk.snapshot().await?;
        }
        if let Some(filter) = &step.read {
            entry["read"] = json!(rules::read(&self.table, filter, step.limit.unwrap_or(15)));
            entry["ok"] = json!(true);
            return Ok(entry);
        }
        if let Some(keys) = &step.key {
            self.desk.key(keys).await?;
            entry["did"] = json!(format!("pressed {keys}"));
        } else if let Some(text) = &step.text {
            let mut field = String::new();
            if let Some(into) = &step.into {
                let Some(row) = rules::find(&self.table.elements, into, EDITABLE) else {
                    entry["missing"] = json!(into);
                    return Ok(entry);
                };
                field = format!(" into {}", row.name);
                let (focus, (x, y)) = (row.focus, row.middle());
                if !focus {
                    self.desk.click(x, y).await?;
                }
            }
            // A named field is set, not added to. Text typed where the caret
            // is, in a document, must never select all of it first.
            if step.replace.unwrap_or(step.into.is_some()) {
                self.desk.key("ctrl+a").await?;
            }
            self.desk.type_text(text).await?;
            let shown: String = text.chars().take(40).collect();
            entry["did"] = json!(format!("typed {shown:?}{field}"));
        } else if let Some(name) = &step.click {
            let Some(row) = rules::find(&self.table.elements, name, CLICKABLE) else {
                entry["missing"] = json!(name);
                return Ok(entry);
            };
            let (x, y) = row.middle();
            let did = format!("clicked {} {}", row.role, row.name.chars().take(40).collect::<String>());
            self.desk.click(x, y).await?;
            entry["did"] = json!(did);
        }
        let expect = step.expect().cloned();
        if expect.is_none() && !step.echo {
            // Nothing to check: keys and text reach the app in order, so the
            // next step waits only if it reads the screen.
            self.stale = true;
            entry["ok"] = json!(true);
            return Ok(entry);
        }
        entry["settle_ms"] = json!(self.settle(expect.as_ref(), step.expect_ms.unwrap_or(EXPECT_MS)).await?);
        let mut ok = expect.as_ref().is_none_or(|e| rules::met(e, &self.table));
        if ok && step.echo {
            if let Some(text) = &step.text {
                ok = rules::echoed(text, &self.table);
                entry["echo"] = json!(ok);
            }
        }
        if ok {
            entry["ok"] = json!(true);
        }
        Ok(entry)
    }

    /// Send away whatever is in front, by its safest button or by Escape.
    /// After a lost keystroke there is nothing to dismiss.
    async fn recover(&mut self, typo: bool) -> Result<(), String> {
        let t = self.now();
        let table = self.table().await?;
        let pick = if typo { None } else { rules::dismissers(table).first().map(|r| (r.name.clone(), r.middle())) };
        let mut entry = json!({ "t": t, "recover": true, "front": table.window.title });
        match pick {
            Some((name, (x, y))) => {
                self.desk.click(x, y).await?;
                entry["did"] = json!(format!("dismissed with {name}"));
            }
            None => {
                self.desk.key("Escape").await?;
                entry["did"] = json!("pressed Escape");
            }
        }
        entry["settle_ms"] = json!(self.settle(None, EXPECT_MS).await?);
        self.log.push(entry);
        Ok(())
    }
}
