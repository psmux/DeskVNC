//! The look of the support app, taken from DeskVNC's design tokens
//! (`ui/src/styles/index.css`): the same canvas, surface and inset colours,
//! the same accent, the same 6 px controls and 14 px cards, the system font,
//! and light or dark following the operating system. The layout is the one
//! people know from remote support tools, so nothing on the home screen has
//! to be explained.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, RichText,
    Stroke, TextStyle, Theme,
};
use std::sync::Arc;

pub struct Palette {
    pub canvas: Color32,
    pub surface: Color32,
    pub inset: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub text: Color32,
    pub text_secondary: Color32,
    pub text_tertiary: Color32,
    pub accent: Color32,
    pub accent_fg: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
}

const LIGHT: Palette = Palette {
    canvas: Color32::from_rgb(244, 245, 247),
    surface: Color32::WHITE,
    inset: Color32::from_rgb(236, 238, 241),
    border: Color32::from_rgb(232, 233, 235),
    border_strong: Color32::from_rgb(200, 202, 206),
    text: Color32::from_rgb(26, 29, 35),
    text_secondary: Color32::from_rgb(76, 83, 97),
    text_tertiary: Color32::from_rgb(135, 142, 155),
    accent: Color32::from_rgb(47, 111, 228),
    accent_fg: Color32::WHITE,
    success: Color32::from_rgb(23, 135, 69),
    warning: Color32::from_rgb(160, 106, 0),
    danger: Color32::from_rgb(204, 58, 48),
};

const DARK: Palette = Palette {
    canvas: Color32::from_rgb(17, 19, 24),
    surface: Color32::from_rgb(26, 29, 36),
    inset: Color32::from_rgb(12, 14, 18),
    border: Color32::from_rgb(47, 50, 57),
    border_strong: Color32::from_rgb(74, 77, 84),
    text: Color32::from_rgb(233, 235, 239),
    text_secondary: Color32::from_rgb(164, 170, 182),
    text_tertiary: Color32::from_rgb(117, 124, 137),
    accent: Color32::from_rgb(91, 149, 245),
    accent_fg: Color32::from_rgb(11, 18, 32),
    success: Color32::from_rgb(63, 200, 115),
    warning: Color32::from_rgb(227, 161, 60),
    danger: Color32::from_rgb(238, 96, 85),
};

/// The palette for the theme in use right now.
pub fn pal(ctx: &egui::Context) -> &'static Palette {
    match ctx.theme() {
        Theme::Dark => &DARK,
        Theme::Light => &LIGHT,
    }
}

const BOLD: &str = "system-bold";

/// Applied once at start. Both themes are set, and egui picks the one the
/// operating system asks for.
pub fn apply(ctx: &egui::Context) {
    ctx.set_fonts(fonts());
    ctx.set_visuals_of(Theme::Light, visuals(&LIGHT, egui::Visuals::light()));
    ctx.set_visuals_of(Theme::Dark, visuals(&DARK, egui::Visuals::dark()));
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (
                TextStyle::Small,
                FontId::new(12.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(13.5, FontFamily::Proportional),
            ),
            (
                TextStyle::Heading,
                FontId::new(18.0, FontFamily::Name(BOLD.into())),
            ),
            (
                TextStyle::Monospace,
                FontId::new(13.0, FontFamily::Monospace),
            ),
        ]
        .into();
        style.spacing.button_padding = egui::vec2(14.0, 6.0);
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.interact_size.y = 30.0;
    });
}

fn visuals(p: &Palette, mut visuals: egui::Visuals) -> egui::Visuals {
    visuals.panel_fill = p.canvas;
    visuals.window_fill = p.surface;
    visuals.window_stroke = Stroke::new(1.0, p.border);
    visuals.window_corner_radius = CornerRadius::same(14);
    visuals.extreme_bg_color = p.inset;
    visuals.faint_bg_color = p.inset;
    visuals.hyperlink_color = p.accent;
    visuals.selection.bg_fill = p.accent.gamma_multiply(0.35);
    visuals.selection.stroke = Stroke::new(1.0, p.accent);
    visuals.text_cursor.stroke.color = p.accent;
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        // 4 rather than DeskVNC's 6: egui draws checkboxes with the same
        // radius as buttons, and 6 on a 14 px box reads as a circle.
        widget.corner_radius = CornerRadius::same(4);
        widget.fg_stroke.color = p.text;
    }
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    // Secondary buttons: inset background with a subtle border, as in DeskVNC.
    visuals.widgets.inactive.weak_bg_fill = p.inset;
    visuals.widgets.inactive.bg_fill = p.inset;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, p.border);
    visuals.widgets.hovered.weak_bg_fill = p.inset;
    visuals.widgets.hovered.bg_fill = p.inset;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, p.border_strong);
    visuals.widgets.active.weak_bg_fill = p.inset;
    visuals.widgets.active.bg_fill = p.inset;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, p.accent);
    visuals.widgets.open.weak_bg_fill = p.inset;
    visuals.widgets.open.bg_fill = p.inset;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, p.accent);
    visuals
}

/// The fonts DeskVNC's stylesheet asks for, from the operating system:
/// Segoe UI on Windows, San Francisco on macOS, Ubuntu or DejaVu on Linux,
/// and a matching monospace. egui's own fonts stay behind them for any glyph
/// they lack, and are what is used when none is found.
fn fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    let sans = [
        (r"C:\Windows\Fonts\segoeui.ttf", 0),
        ("/System/Library/Fonts/SFNS.ttf", 0),
        ("/System/Library/Fonts/Helvetica.ttc", 0),
        ("/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf", 0),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 0),
        ("/usr/share/fonts/dejavu/DejaVuSans.ttf", 0),
    ];
    let bold = [
        (r"C:\Windows\Fonts\segoeuib.ttf", 0),
        ("/System/Library/Fonts/Helvetica.ttc", 1),
        ("/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf", 0),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 0),
        ("/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf", 0),
    ];
    let mono = [
        (r"C:\Windows\Fonts\consola.ttf", 0),
        ("/System/Library/Fonts/Menlo.ttc", 0),
        ("/System/Library/Fonts/SFNSMono.ttf", 0),
        ("/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf", 0),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0),
        ("/usr/share/fonts/dejavu/DejaVuSansMono.ttf", 0),
    ];
    let load = |candidates: &[(&str, u32)]| {
        candidates.iter().find_map(|(path, index)| {
            let bytes = std::fs::read(path).ok()?;
            let mut data = FontData::from_owned(bytes);
            data.index = *index;
            Some(Arc::new(data))
        })
    };
    if let Some(data) = load(&sans) {
        fonts.font_data.insert("system".into(), data);
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "system".into());
    }
    let mut bold_family = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    if let Some(data) = load(&bold) {
        fonts.font_data.insert(BOLD.into(), data);
        bold_family.insert(0, BOLD.into());
    }
    fonts
        .families
        .insert(FontFamily::Name(BOLD.into()), bold_family);
    if let Some(data) = load(&mono) {
        fonts.font_data.insert("system-mono".into(), data);
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "system-mono".into());
    }
    fonts
}

fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(BOLD.into()))
}

/// A card: DeskVNC's surface colour, subtle border, 14 px corners.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let p = pal(ui.ctx());
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(20))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // A plain top down layout: `Ui::columns` hands out justified
            // columns, which would stretch every small button to full width.
            ui.vertical(add).inner
        })
        .inner
}

/// The one accent button on a card, DeskVNC's primary button made taller.
pub fn primary(ui: &egui::Ui, text: &str) -> egui::Button<'static> {
    let p = pal(ui.ctx());
    egui::Button::new(RichText::new(text).font(bold(14.0)).color(p.accent_fg))
        .fill(p.accent)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(6))
        .min_size(egui::vec2(0.0, 40.0))
}

/// A red button for ending things.
pub fn danger(ui: &egui::Ui, text: &str) -> egui::Button<'static> {
    let p = pal(ui.ctx());
    egui::Button::new(RichText::new(text).font(bold(13.5)).color(Color32::WHITE))
        .fill(p.danger)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(6))
        .min_size(egui::vec2(0.0, 32.0))
}

/// A card's title.
pub fn title(ui: &mut egui::Ui, text: &str) {
    let p = pal(ui.ctx());
    ui.label(RichText::new(text).font(bold(17.0)).color(p.text));
}

/// A label over a field.
pub fn caption(ui: &mut egui::Ui, text: &str) {
    let p = pal(ui.ctx());
    ui.label(RichText::new(text).font(bold(12.0)).color(p.text_secondary));
}

pub fn muted(ui: &mut egui::Ui, text: impl Into<String>) {
    let p = pal(ui.ctx());
    ui.label(RichText::new(text).color(p.text_secondary));
}

pub fn small(ui: &mut egui::Ui, text: impl Into<String>) {
    let p = pal(ui.ctx());
    ui.label(RichText::new(text).size(12.0).color(p.text_tertiary));
}

/// A full width text field: inset background, 6 px corners.
pub fn field<'a>(value: &'a mut String, hint: &str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(value)
        .hint_text(hint)
        .desired_width(f32::INFINITY)
        .margin(Margin::symmetric(10, 8))
}

/// A coloured dot, the kind every status bar has.
pub fn dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(9.0, 9.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.5, color);
}

/// A large value in an inset box with a Copy button beside it. Returns
/// whether Copy was pressed.
pub fn value_box(ui: &mut egui::Ui, value: &str, size: f32) -> bool {
    let p = pal(ui.ctx());
    egui::Frame::new()
        .fill(p.inset)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(value)
                        .font(FontId::monospace(size))
                        .color(p.text),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.button("Copy").clicked()
                })
                .inner
            })
            .inner
        })
        .inner
}
