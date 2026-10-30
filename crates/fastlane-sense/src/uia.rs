//! UI Automation: the foreground window's controls and the taskbar's.

use serde_json::{json, Value};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};
use windows::Win32::System::Variant::{VARIANT, VT_BSTR, VT_I4};
use windows::core::Interface;
use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::UI::Accessibility::*;
use windows::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetClassNameW, GetForegroundWindow, GetSystemMetrics, GetWindowTextW,
    SM_CXSCREEN, SM_CYSCREEN,
};

use crate::{fnv, Table};

/// The most rows one read returns. A browser page can expose thousands of
/// text nodes, and a table longer than this costs the model more than the
/// rows add.
const MAX_ROWS: usize = 600;

/// The most one read of a window may take before it stops going deeper.
const READ_BUDGET: Duration = Duration::from_millis(1500);

/// How long a snapshot waits for the reader before it answers without the
/// window's controls. UI Automation's own timeouts do not cover every call:
/// Excel behind one of its dialogs held a read for nine seconds with them set.
const READ_DEADLINE: Duration = Duration::from_millis(1800);

enum Ask {
    Read(isize, &'static str),
    Cells(isize, Vec<String>),
}

enum Answer {
    /// The rows, the hash key, and whether the read got the whole window.
    Rows(Vec<Value>, String, bool),
    Cells(Result<Value, String>),
}

/// One thread doing UI Automation calls, and the way to it.
struct Worker {
    asks: Sender<Ask>,
    answers: Receiver<Answer>,
    busy: bool,
}

impl Worker {
    fn spawn() -> Result<Worker, String> {
        let (asks, inbox) = channel::<Ask>();
        let (outbox, answers) = channel::<Answer>();
        let (ready_tx, ready) = channel::<Result<(), String>>();
        std::thread::spawn(move || {
            let reader = match Reader::new() {
                Ok(reader) => {
                    let _ = ready_tx.send(Ok(()));
                    reader
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            for ask in inbox {
                let answer = unsafe {
                    match ask {
                        Ask::Read(hwnd, area) => {
                            let (mut rows, mut key) = (Vec::new(), String::new());
                            let whole = reader.read(HWND(hwnd as *mut _), area, &mut rows, &mut key);
                            Answer::Rows(rows, key, whole)
                        }
                        Ask::Cells(hwnd, names) => Answer::Cells(reader.cells(HWND(hwnd as *mut _), &names)),
                    }
                };
                if outbox.send(answer).is_err() {
                    return;
                }
            }
        });
        ready.recv().map_err(|e| e.to_string())??;
        Ok(Worker { asks, answers, busy: false })
    }
}

/// The most reader threads at once. A thread stuck in an app that stopped
/// answering is left to finish on its own while another reads the next
/// window; past this many, reads answer partial until one is free.
const WORKERS: usize = 8;

/// The screen reader. UI Automation calls run on worker threads, so a call
/// that hangs holds up a worker, never the caller: the caller answers with
/// what it has and marks the table partial.
pub struct Sense {
    workers: Vec<Worker>,
}

impl Sense {
    pub fn new() -> Result<Sense, String> {
        Ok(Sense { workers: vec![Worker::spawn()?] })
    }

    /// One answer within `wait`, from a worker that is not stuck.
    fn ask(&mut self, ask: Ask, wait: Duration) -> Option<Answer> {
        for worker in self.workers.iter_mut().filter(|w| w.busy) {
            // A late answer to an ask that ran out of time: dropped.
            if worker.answers.try_recv().is_ok() {
                worker.busy = false;
            }
        }
        let index = match self.workers.iter().position(|w| !w.busy) {
            Some(i) => i,
            None if self.workers.len() < WORKERS => {
                self.workers.push(Worker::spawn().ok()?);
                self.workers.len() - 1
            }
            None => return None,
        };
        let worker = &mut self.workers[index];
        worker.asks.send(ask).ok()?;
        match worker.answers.recv_timeout(wait) {
            Ok(answer) => Some(answer),
            Err(RecvTimeoutError::Timeout) => {
                worker.busy = true;
                None
            }
            Err(RecvTimeoutError::Disconnected) => None,
        }
    }

    pub fn snapshot(&mut self) -> Result<Table, String> {
        unsafe {
            let foreground = GetForegroundWindow();
            let taskbar = FindWindowW(windows::core::w!("Shell_TrayWnd"), None).unwrap_or_default();
            let mut rows: Vec<Value> = Vec::new();
            let mut key = String::new();
            let mut partial = false;
            for (hwnd, area) in [(foreground, "window"), (taskbar, "taskbar")] {
                if hwnd.is_invalid() || (area == "taskbar" && hwnd == foreground) {
                    continue;
                }
                match self.ask(Ask::Read(hwnd.0 as isize, area), READ_DEADLINE) {
                    Some(Answer::Rows(found, k, whole)) => {
                        partial |= !whole;
                        for mut row in found {
                            if rows.len() >= MAX_ROWS {
                                break;
                            }
                            row["i"] = json!(rows.len() + 1);
                            rows.push(row);
                        }
                        key.push_str(&k);
                    }
                    _ => partial = true,
                }
            }
            let title = text_of(foreground, true);
            let class = text_of(foreground, false);
            key.push_str(&title);
            key.push_str(&class);
            let mut body = json!({
                "screen": { "w": GetSystemMetrics(SM_CXSCREEN), "h": GetSystemMetrics(SM_CYSCREEN) },
                "window": { "title": title, "class": class },
                "elements": rows,
            });
            if partial {
                // The window did not answer in time: its title and class are
                // right, its controls are missing.
                body["partial"] = json!(true);
            }
            Ok(Table { hash: fnv(&key), body })
        }
    }

    /// The values of named cells ("C4") in the window in front.
    pub fn cells(&mut self, names: &[String]) -> Result<Value, String> {
        let hwnd = unsafe { GetForegroundWindow() };
        match self.ask(Ask::Cells(hwnd.0 as isize, names.to_vec()), Duration::from_secs(5)) {
            Some(Answer::Cells(result)) => result,
            _ => Err("the window did not answer in time".into()),
        }
    }
}

struct Reader {
    automation: IUIAutomation,
    cache: IUIAutomationCacheRequest,
    condition: IUIAutomationCondition,
    gave_up: std::cell::RefCell<bool>,
}

impl Reader {
    fn new() -> Result<Reader, String> {
        unsafe {
            // Physical pixels, the same ones the VNC or Boundary framebuffer
            // carries, so a rectangle here is a click target there.
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(|e| format!("COM: {e}"))?;
            let automation: IUIAutomation =
                CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER)
                    .map_err(|e| format!("UI Automation: {e}"))?;
            // An app that is busy or stuck (Excel behind its own Save As) does
            // not answer, and UI Automation waits twenty seconds per call by
            // default. A second is plenty for an app that is answering.
            if let Ok(timeouts) = automation.cast::<IUIAutomation2>() {
                let _ = timeouts.SetConnectionTimeout(1000);
                let _ = timeouts.SetTransactionTimeout(1000);
            }
            let cache = automation.CreateCacheRequest().map_err(|e| e.to_string())?;
            for property in [
                UIA_NamePropertyId,
                UIA_ControlTypePropertyId,
                UIA_BoundingRectanglePropertyId,
                UIA_IsEnabledPropertyId,
                UIA_IsOffscreenPropertyId,
                UIA_HasKeyboardFocusPropertyId,
                UIA_ValueValuePropertyId,
                UIA_ToggleToggleStatePropertyId,
            ] {
                cache.AddProperty(property).map_err(|e| e.to_string())?;
            }
            cache.SetTreeScope(TreeScope_Element).map_err(|e| e.to_string())?;
            // Spreadsheet cells are left out of the table: Excel exposes every
            // visible cell, and walking a thousand of them made one read take
            // minutes. `cells` reads the ones a caller names.
            let view = automation.ControlViewCondition().map_err(|e| e.to_string())?;
            let is_cell = automation
                .CreatePropertyCondition(UIA_ControlTypePropertyId, &variant_i4(UIA_DataItemControlTypeId.0))
                .map_err(|e| e.to_string())?;
            let not_cell = automation.CreateNotCondition(&is_cell).map_err(|e| e.to_string())?;
            let condition = automation.CreateAndCondition(&view, &not_cell).map_err(|e| e.to_string())?;
            Ok(Reader { automation, cache, condition, gave_up: std::cell::RefCell::new(false) })
        }
    }

    /// The values of named cells ("C4") in the window in front.
    unsafe fn cells(&self, hwnd: HWND, names: &[String]) -> Result<Value, String> {
        unsafe {
            let root = self
                .automation
                .ElementFromHandle(hwnd)
                .map_err(|e| e.to_string())?;
            let mut out = serde_json::Map::new();
            for name in names {
                let by_name = self
                    .automation
                    .CreatePropertyCondition(UIA_NamePropertyId, &variant_bstr(name))
                    .map_err(|e| e.to_string())?;
                let value = root
                    .FindFirst(TreeScope_Descendants, &by_name)
                    .ok()
                    .and_then(|el| el.GetCurrentPropertyValue(UIA_ValueValuePropertyId).ok())
                    .and_then(|v| string_of(&v));
                out.insert(name.clone(), value.map(Value::from).unwrap_or(Value::Null));
            }
            Ok(Value::Object(out))
        }
    }

    /// The window's controls, level by level. Never inside a grid or a table
    /// (a spreadsheet's cells; `cells` reads those by name), and no deeper
    /// once the read has used its budget: a slow app makes one read
    /// incomplete, never the fast lane wait.
    unsafe fn walk(&self, parent: &IUIAutomationElement, depth: u32, deadline: Instant, out: &mut Vec<IUIAutomationElement>) {
        if depth > 60 || out.len() >= MAX_ROWS * 4 || Instant::now() > deadline || *self.gave_up.borrow() {
            return;
        }
        let Ok(children) = parent.FindAllBuildCache(TreeScope_Children, &self.condition, &self.cache) else {
            // An app that stopped answering (timed out) will not answer the
            // next call either: give up on this window now.
            out.push(parent.clone());
            *self.gave_up.borrow_mut() = true;
            return;
        };
        for i in 0..children.Length().unwrap_or(0) {
            let Ok(el) = children.GetElement(i) else { continue };
            let kind = el.CachedControlType().unwrap_or_default();
            out.push(el.clone());
            if kind != UIA_DataGridControlTypeId && kind != UIA_TableControlTypeId {
                self.walk(&el, depth + 1, deadline, out);
            }
        }
    }

    /// False when the window did not answer all of it.
    unsafe fn read(&self, hwnd: HWND, area: &str, rows: &mut Vec<Value>, key: &mut String) -> bool {
        let Ok(root) = self.automation.ElementFromHandle(hwnd) else { return false };
        let mut found = Vec::new();
        *self.gave_up.borrow_mut() = false;
        let deadline = Instant::now() + READ_BUDGET;
        self.walk(&root, 0, deadline, &mut found);
        let whole = !*self.gave_up.borrow() && Instant::now() <= deadline;
        for el in found {
            if rows.len() >= MAX_ROWS {
                return whole;
            }
            let Some(role) = el.CachedControlType().ok().and_then(role_of) else { continue };
            if el.CachedIsOffscreen().is_ok_and(|b| b.as_bool()) {
                continue;
            }
            let r: RECT = el.CachedBoundingRectangle().unwrap_or_default();
            let (w, h) = (r.right - r.left, r.bottom - r.top);
            if w <= 0 || h <= 0 {
                continue;
            }
            let name = el.CachedName().map(|b| clip(&b.to_string())).unwrap_or_default();
            let value = cached_string(&el, UIA_ValueValuePropertyId);
            if role == "text" && name.is_empty() {
                continue;
            }
            // A spreadsheet lists every visible cell and every row and column
            // header; an empty cell says nothing and would fill the table.
            if role == "row" && value.is_empty() && is_cell_or_header(&name) {
                continue;
            }
            let enabled = el.CachedIsEnabled().is_ok_and(|b| b.as_bool());
            let focus = el.CachedHasKeyboardFocus().is_ok_and(|b| b.as_bool());
            let toggled = el
                .GetCachedPropertyValue(UIA_ToggleToggleStatePropertyId)
                .ok()
                .and_then(|v| int_of(&v));
            key.push_str(&format!("{role}|{name}|{value}|{}|{}|{w}|{h}|{enabled}|{focus}|{toggled:?};", r.left, r.top));
            let mut row = json!({
                "i": rows.len() + 1,
                "area": area,
                "role": role,
                "name": name,
                "x": r.left, "y": r.top, "w": w, "h": h,
            });
            if !value.is_empty() {
                row["value"] = json!(value);
            }
            if !enabled {
                row["disabled"] = json!(true);
            }
            if focus {
                row["focus"] = json!(true);
            }
            if let Some(t) = toggled {
                row["checked"] = json!(t == 1);
            }
            rows.push(row);
        }
        whole
    }
}

unsafe fn cached_string(el: &IUIAutomationElement, property: UIA_PROPERTY_ID) -> String {
    el.GetCachedPropertyValue(property)
        .ok()
        .and_then(|v| string_of(&v))
        .map(|s| clip(&s))
        .unwrap_or_default()
}

fn variant_i4(value: i32) -> VARIANT {
    let mut v = VARIANT::default();
    unsafe {
        let inner = &mut *v.Anonymous.Anonymous;
        inner.vt = VT_I4;
        inner.Anonymous.lVal = value;
    }
    v
}

fn variant_bstr(text: &str) -> VARIANT {
    let mut v = VARIANT::default();
    unsafe {
        let inner = &mut *v.Anonymous.Anonymous;
        inner.vt = VT_BSTR;
        inner.Anonymous.bstrVal = std::mem::ManuallyDrop::new(windows::core::BSTR::from(text));
    }
    v
}

unsafe fn string_of(v: &VARIANT) -> Option<String> {
    let inner = &v.Anonymous.Anonymous;
    (inner.vt == VT_BSTR).then(|| inner.Anonymous.bstrVal.to_string())
}

unsafe fn int_of(v: &VARIANT) -> Option<i32> {
    let inner = &v.Anonymous.Anonymous;
    (inner.vt == VT_I4).then(|| inner.Anonymous.lVal)
}

/// The windows a person would see in Alt+Tab, front first: visible, titled,
/// not owned by another window, not a tool window, not cloaked (a Store app
/// parked in the background, or a window on another virtual desktop).
/// Win32 only, so it answers at once even when an app ignores UI Automation,
/// and nothing on screen moves the way Task View does.
pub fn windows() -> Value {
    use windows::Win32::Foundation::{LPARAM, TRUE};
    use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindow, GetWindowLongW, IsIconic, IsWindowVisible, GWL_EXSTYLE, GW_OWNER,
        WS_EX_TOOLWINDOW,
    };
    unsafe extern "system" fn each(hwnd: HWND, list: LPARAM) -> windows::core::BOOL {
        unsafe {
            let list = &mut *(list.0 as *mut Vec<Value>);
            let title = text_of(hwnd, true);
            let owned = GetWindow(hwnd, GW_OWNER).is_ok_and(|o| !o.is_invalid());
            let tool = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32 & WS_EX_TOOLWINDOW.0 != 0;
            let mut cloaked = 0u32;
            let _ = DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &mut cloaked as *mut u32 as *mut _, 4);
            if IsWindowVisible(hwnd).as_bool() && !title.is_empty() && !owned && !tool && cloaked == 0 {
                list.push(json!({
                    "hwnd": hwnd.0 as i64,
                    "title": title,
                    "class": text_of(hwnd, false),
                    "minimized": IsIconic(hwnd).as_bool(),
                }));
            }
            TRUE
        }
    }
    let mut list: Vec<Value> = Vec::new();
    unsafe {
        let _ = EnumWindows(Some(each), LPARAM(&mut list as *mut Vec<Value> as isize));
    }
    Value::Array(list)
}

/// Bring a window to the front, restoring it if minimized; true when it is
/// in front afterwards. Windows lets a background process do this only while
/// it shares input with the window in front, so it attaches to that thread
/// for the moment it takes.
pub fn activate(hwnd: i64) -> bool {
    use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
    use windows::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, GetWindowThreadProcessId, IsIconic, SetForegroundWindow, ShowWindow,
        SW_RESTORE,
    };
    unsafe {
        let target = HWND(hwnd as *mut _);
        if IsIconic(target).as_bool() {
            let _ = ShowWindow(target, SW_RESTORE);
        }
        let front = GetForegroundWindow();
        let theirs = GetWindowThreadProcessId(front, None);
        let ours = GetCurrentThreadId();
        let attached = theirs != 0 && theirs != ours && AttachThreadInput(ours, theirs, true).as_bool();
        let _ = BringWindowToTop(target);
        let _ = SetForegroundWindow(target);
        if attached {
            let _ = AttachThreadInput(ours, theirs, false);
        }
        GetForegroundWindow() == target
    }
}

/// The clipboard's text. The fast lane copies a value and reads it here when
/// an app will not say it through UI Automation (Excel on a bad day), the way
/// a person pastes a number somewhere to look at it.
pub fn clipboard_text() -> Result<String, String> {
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows::Win32::Foundation::HGLOBAL;
    const CF_UNICODETEXT: u32 = 13;
    unsafe {
        OpenClipboard(None).map_err(|e| format!("clipboard: {e}"))?;
        let text = (|| {
            let handle = GetClipboardData(CF_UNICODETEXT).map_err(|e| format!("no text on the clipboard: {e}"))?;
            let global = HGLOBAL(handle.0);
            let ptr = GlobalLock(global) as *const u16;
            if ptr.is_null() {
                return Err("clipboard text would not lock".to_string());
            }
            let mut len = 0;
            while *ptr.add(len) != 0 && len < 1 << 20 {
                len += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = GlobalUnlock(global);
            Ok(text)
        })();
        let _ = CloseClipboard();
        text
    }
}

unsafe fn text_of(hwnd: HWND, title: bool) -> String {
    let mut buf = [0u16; 256];
    let n = if title { GetWindowTextW(hwnd, &mut buf) } else { GetClassNameW(hwnd, &mut buf) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

fn is_cell_or_header(name: &str) -> bool {
    let letters = name.chars().take_while(|c| c.is_ascii_uppercase()).count();
    let rest = &name[letters..];
    name.len() <= 10 && (letters > 0 || !rest.is_empty()) && rest.chars().all(|c| c.is_ascii_digit())
}

fn clip(text: &str) -> String {
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    one_line.chars().take(120).collect()
}

/// The kinds a person acts on or reads. Panes, groups and windows are left
/// out: they are containers, and a model offered them clicks the empty
/// middle of a dialog.
#[allow(non_upper_case_globals)]
fn role_of(id: UIA_CONTROLTYPE_ID) -> Option<&'static str> {
    Some(match id {
        UIA_ButtonControlTypeId => "button",
        UIA_SplitButtonControlTypeId => "button",
        UIA_CheckBoxControlTypeId => "checkbox",
        UIA_RadioButtonControlTypeId => "radio",
        UIA_ComboBoxControlTypeId => "combobox",
        UIA_EditControlTypeId => "textbox",
        UIA_DocumentControlTypeId => "document",
        UIA_HyperlinkControlTypeId => "link",
        UIA_ListItemControlTypeId => "listitem",
        UIA_MenuItemControlTypeId => "menuitem",
        UIA_TabItemControlTypeId => "tab",
        UIA_TreeItemControlTypeId => "treeitem",
        UIA_DataItemControlTypeId => "row",
        UIA_HeaderItemControlTypeId => "header",
        UIA_SliderControlTypeId => "slider",
        UIA_TextControlTypeId => "text",
        _ => return None,
    })
}
