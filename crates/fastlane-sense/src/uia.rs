//! UI Automation: the foreground window's controls and the taskbar's.

use serde_json::{json, Value};
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

pub struct Sense {
    automation: IUIAutomation,
    cache: IUIAutomationCacheRequest,
    condition: IUIAutomationCondition,
}

impl Sense {
    pub fn new() -> Result<Sense, String> {
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
            Ok(Sense { automation, cache, condition })
        }
    }

    pub fn snapshot(&mut self) -> Result<Table, String> {
        unsafe {
            let foreground = GetForegroundWindow();
            let taskbar = FindWindowW(windows::core::w!("Shell_TrayWnd"), None).unwrap_or_default();
            let mut rows: Vec<Value> = Vec::new();
            let mut key = String::new();
            for (hwnd, area) in [(foreground, "window"), (taskbar, "taskbar")] {
                if hwnd.is_invalid() || (area == "taskbar" && hwnd == foreground) {
                    continue;
                }
                self.read(hwnd, area, &mut rows, &mut key);
            }
            let title = text_of(foreground, true);
            let class = text_of(foreground, false);
            key.push_str(&title);
            let body = json!({
                "screen": { "w": GetSystemMetrics(SM_CXSCREEN), "h": GetSystemMetrics(SM_CYSCREEN) },
                "window": { "title": title, "class": class },
                "elements": rows,
            });
            Ok(Table { hash: fnv(&key), body })
        }
    }

    /// The values of named cells ("C4") in the window in front.
    pub fn cells(&mut self, names: &[String]) -> Result<Value, String> {
        unsafe {
            let root = self
                .automation
                .ElementFromHandle(GetForegroundWindow())
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
        if depth > 60 || out.len() >= MAX_ROWS * 4 || Instant::now() > deadline {
            return;
        }
        let Ok(children) = parent.FindAllBuildCache(TreeScope_Children, &self.condition, &self.cache) else { return };
        for i in 0..children.Length().unwrap_or(0) {
            let Ok(el) = children.GetElement(i) else { continue };
            let kind = el.CachedControlType().unwrap_or_default();
            out.push(el.clone());
            if kind != UIA_DataGridControlTypeId && kind != UIA_TableControlTypeId {
                self.walk(&el, depth + 1, deadline, out);
            }
        }
    }

    unsafe fn read(&self, hwnd: HWND, area: &str, rows: &mut Vec<Value>, key: &mut String) {
        let Ok(root) = self.automation.ElementFromHandle(hwnd) else { return };
        let mut found = Vec::new();
        let deadline = Instant::now() + READ_BUDGET;
        self.walk(&root, 0, deadline, &mut found);
        for el in found {
            if rows.len() >= MAX_ROWS {
                return;
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
