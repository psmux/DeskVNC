//! Explicit physical Mac display requests, separate from framebuffer resizing.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum MacDisplayAction {
    List,
    Set { width: u16, height: u16 },
    Restore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MacDisplayMode {
    pub id: i32,
    pub width: u16,
    pub height: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MacDisplayInfo {
    pub display_id: u32,
    pub original_mode_id: i32,
    pub current_mode_id: i32,
    pub width: u16,
    pub height: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
    pub modes: Vec<MacDisplayMode>,
    #[serde(default)]
    pub can_restore: bool,
}
