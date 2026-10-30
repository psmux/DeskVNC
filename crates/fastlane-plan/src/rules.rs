//! The rules of `tools/fastlane/spec`: finding a control, sending a popup
//! away, checking an expectation, reading rows. Pure functions over a table,
//! so the spec's cases test them without a screen.

use serde::Deserialize;

/// One read of the screen.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Table {
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub window: Front,
    #[serde(default)]
    pub partial: bool,
    #[serde(default)]
    pub elements: Vec<Row>,
}

/// What is in front.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Front {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub class: String,
}

/// One control.
#[derive(Debug, Clone, Deserialize)]
pub struct Row {
    #[serde(default)]
    pub i: u32,
    #[serde(default = "window_area")]
    pub area: String,
    pub role: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub x: i64,
    #[serde(default)]
    pub y: i64,
    #[serde(default = "default_w")]
    pub w: i64,
    #[serde(default = "default_h")]
    pub h: i64,
    #[serde(default)]
    pub focus: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub checked: bool,
}

fn window_area() -> String {
    "window".into()
}
fn default_w() -> i64 {
    100
}
fn default_h() -> i64 {
    20
}

impl Row {
    /// The middle, where a click goes.
    pub fn middle(&self) -> (i64, i64) {
        (self.x + self.w / 2, self.y + self.h / 2)
    }

    fn in_window(&self) -> bool {
        self.area == "window"
    }

    /// Name and value, as `expect.shows` and the echo check see them.
    fn said(&self) -> String {
        format!("{} {}", self.name, self.value)
    }
}

/// What a `click` step may land on.
pub const CLICKABLE: &[&str] = &[
    "button", "checkbox", "radio", "combobox", "link", "listitem", "menuitem", "tab", "treeitem", "row", "header",
    "textbox", "document",
];

/// What an `into` field may be.
pub const EDITABLE: &[&str] = &["textbox", "combobox", "document"];

/// Words on buttons that make an unexpected screen go away without agreeing
/// to anything. Safest first.
pub const DISMISS: &[&str] = &[
    "not now", "no thanks", "no, thanks", "maybe later", "remind me later", "later", "skip", "dismiss", "got it",
    "close", "cancel", "don't allow", "block", "decline", "reject", "no",
];

/// Runs of letters and digits, lower case, two characters or longer.
fn words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() > 1)
        .map(String::from)
        .collect()
}

/// The row a step names, or None when it is missing. Never a guess.
pub fn find<'a>(rows: &'a [Row], name: &str, roles: &[&str]) -> Option<&'a Row> {
    let candidates: Vec<&Row> = rows
        .iter()
        .filter(|r| roles.contains(&r.role.as_str()) && !r.disabled)
        .collect();
    let want = name.to_lowercase();
    let named = |r: &Row| r.name.to_lowercase().trim_end_matches(':').to_string();
    let tests: [&dyn Fn(&str) -> bool; 3] = [&|n| n == want, &|n| n.starts_with(&want), &|n| n.contains(&want)];
    for test in tests {
        let hits: Vec<&Row> = candidates.iter().copied().filter(|r| test(&named(r))).collect();
        if hits.is_empty() {
            continue;
        }
        // A combo box and the edit inside it share a name; the one with the
        // keyboard focus is the one that takes text.
        let focused: Vec<&Row> = hits.iter().copied().filter(|r| r.focus).collect();
        if focused.len() == 1 {
            return Some(focused[0]);
        }
        return closest(&hits, &want);
    }
    // A near miss only when it shares a word, and a whole page never stands
    // in for a field.
    let wanted = words(name);
    let near: Vec<&Row> = candidates
        .into_iter()
        .filter(|r| r.role != "document" && words(&r.name).iter().any(|w| wanted.contains(w)))
        .collect();
    closest(&near, &want)
}

/// Focused first, then in the window over the taskbar, then the name nearest
/// in length, then top, then left.
fn closest<'a>(rows: &[&'a Row], want: &str) -> Option<&'a Row> {
    let length = want.chars().count() as i64;
    rows.iter()
        .min_by_key(|r| (!r.focus, !r.in_window(), (r.name.chars().count() as i64 - length).abs(), r.y, r.x))
        .copied()
}

/// Where a name stands in [`DISMISS`], or None when it does not dismiss.
pub fn dismisses(name: &str) -> Option<usize> {
    let n = name.trim().to_lowercase();
    // Closing something the person has open is never how to get past a popup.
    if n.split_whitespace().any(|w| w == "tab") {
        return None;
    }
    DISMISS.iter().position(|w| n == *w || (w.contains(' ') && n.starts_with(w)))
}

/// The buttons that would send away what is in front, safest first.
pub fn dismissers(table: &Table) -> Vec<&Row> {
    let rows: Vec<&Row> = table
        .elements
        .iter()
        .filter(|r| r.in_window() && (r.role == "button" || r.role == "link") && !r.disabled)
        .collect();
    // A window's own caption buttons sit in a row with Minimize.
    let caption: Vec<i64> = rows
        .iter()
        .filter(|r| r.name.to_lowercase().starts_with("minimize"))
        .map(|r| r.y)
        .collect();
    let mut picks: Vec<(usize, &Row)> = rows
        .into_iter()
        .filter(|r| !caption.iter().any(|y| (r.y - y).abs() <= 6))
        .filter_map(|r| dismisses(&r.name).map(|k| (k, r)))
        .collect();
    picks.sort_by_key(|(k, _)| *k);
    picks.into_iter().map(|(_, r)| r).collect()
}

/// An `expect` or `when` condition.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct Expect {
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub shows: Option<String>,
}

impl Expect {
    pub fn is_empty(&self) -> bool {
        self.window.is_none() && self.shows.is_none()
    }
}

/// Whether the screen meets a condition.
pub fn met(expect: &Expect, table: &Table) -> bool {
    if let Some(window) = &expect.window {
        if !table.window.title.to_lowercase().contains(&window.to_lowercase()) {
            return false;
        }
    }
    if let Some(shows) = &expect.shows {
        let shows = shows.to_lowercase();
        if !table.elements.iter().any(|r| r.said().to_lowercase().contains(&shows)) {
            return false;
        }
    }
    true
}

/// Whether typed text shows up on screen, letters and digits in order.
pub fn echoed(text: &str, table: &Table) -> bool {
    let plain = |t: &str| t.to_lowercase().chars().filter(|c| c.is_alphanumeric()).collect::<String>();
    let typed = plain(text);
    table.elements.iter().any(|r| plain(&r.said()).contains(&typed))
}

/// The text of rows holding any of the `|` separated words, or all of them.
/// In a browser only the page counts, not the toolbar around it.
pub fn read(table: &Table, filter: &str, limit: usize) -> Vec<String> {
    let want: Vec<String> = filter.split('|').filter(|w| !w.is_empty()).map(str::to_lowercase).collect();
    let page = table
        .elements
        .iter()
        .filter(|r| r.role == "document" && r.in_window())
        .max_by_key(|r| r.w * r.h);
    let inside = |r: &Row| match page {
        None => true,
        Some(p) => {
            !std::ptr::eq(r, p) && p.x <= r.x && r.x < p.x + p.w && p.y <= r.y && r.y < p.y + p.h
        }
    };
    let mut found: Vec<String> = Vec::new();
    for r in &table.elements {
        let text = if !r.value.is_empty() && r.role != "link" {
            format!("{} · {}", r.name, r.value)
        } else {
            r.name.clone()
        };
        if !r.in_window() || !inside(r) || text.is_empty() || found.contains(&text) {
            continue;
        }
        if want.is_empty() || want.iter().any(|w| text.to_lowercase().contains(w)) {
            found.push(text);
            if found.len() == limit {
                break;
            }
        }
    }
    found
}

/// The table as text, one numbered line per row, for an agent to read.
pub fn rows_text(table: &Table) -> String {
    table
        .elements
        .iter()
        .map(|r| {
            let mut line = format!("[{}] {} {} {}", r.i, r.area, r.role, r.name);
            if !r.value.is_empty() {
                line.push_str(&format!(" · {}", r.value));
            }
            for (on, word) in [(r.focus, " (focused)"), (r.disabled, " (disabled)"), (r.checked, " (checked)")] {
                if on {
                    line.push_str(word);
                }
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}
