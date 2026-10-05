//! The look of the support app: a light page with white cards, one blue
//! primary action per card, and text large enough to read across a desk.
//! The shape follows what people already know from remote support tools,
//! so nothing on the home screen has to be explained.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, RichText, Stroke, TextStyle,
};

pub const PAGE: Color32 = Color32::from_rgb(243, 245, 248);
pub const CARD: Color32 = Color32::WHITE;
pub const FIELD: Color32 = Color32::from_rgb(246, 248, 250);
pub const LINE: Color32 = Color32::from_rgb(222, 226, 232);
pub const TEXT: Color32 = Color32::from_rgb(24, 30, 40);
pub const MUTED: Color32 = Color32::from_rgb(98, 108, 124);
pub const ACCENT: Color32 = Color32::from_rgb(0, 112, 224);
pub const GOOD: Color32 = Color32::from_rgb(22, 140, 82);
pub const WARN: Color32 = Color32::from_rgb(176, 108, 0);
pub const BAD: Color32 = Color32::from_rgb(190, 44, 44);

/// Applied once at start.
pub fn apply(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::light();
    visuals.panel_fill = PAGE;
    visuals.window_fill = CARD;
    visuals.window_stroke = Stroke::new(1.0, LINE);
    visuals.window_corner_radius = CornerRadius::same(12);
    visuals.extreme_bg_color = FIELD;
    visuals.hyperlink_color = ACCENT;
    visuals.selection.bg_fill = Color32::from_rgb(204, 224, 250);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = CornerRadius::same(8);
        widget.fg_stroke.color = TEXT;
    }
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    visuals.widgets.inactive.weak_bg_fill = CARD;
    visuals.widgets.inactive.bg_fill = CARD;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(241, 245, 251);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(241, 245, 251);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(168, 190, 222));
    visuals.widgets.active.weak_bg_fill = Color32::from_rgb(226, 236, 250);
    visuals.widgets.active.bg_fill = Color32::from_rgb(226, 236, 250);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (
                TextStyle::Small,
                FontId::new(12.5, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(15.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Heading,
                FontId::new(21.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(14.0, FontFamily::Monospace),
            ),
        ]
        .into();
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.interact_size.y = 32.0;
    });
}

/// A white card with a thin border, the full width of its column.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(22))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// The one blue button on a card.
pub fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).color(Color32::WHITE).strong())
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(8))
        .min_size(egui::vec2(0.0, 42.0))
}

/// A red button for ending things.
pub fn danger(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).color(Color32::WHITE).strong())
        .fill(BAD)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(8))
        .min_size(egui::vec2(0.0, 36.0))
}

/// A card's title.
pub fn title(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(19.0).strong().color(TEXT));
}

/// A label over a field, small and grey.
pub fn caption(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(12.5).strong().color(MUTED));
}

pub fn muted(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(RichText::new(text).color(MUTED));
}

pub fn small(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(RichText::new(text).size(12.5).color(MUTED));
}

/// A full width text field.
pub fn field<'a>(value: &'a mut String, hint: &str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(value)
        .hint_text(hint)
        .desired_width(f32::INFINITY)
        .margin(Margin::symmetric(12, 9))
}

/// A coloured dot, the kind every status bar has.
pub fn dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
}

/// A large value in a grey box with a Copy button beside it. Returns whether
/// Copy was pressed.
pub fn value_box(ui: &mut egui::Ui, value: &str, size: f32) -> bool {
    egui::Frame::new()
        .fill(FIELD)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(value)
                        .font(FontId::monospace(size))
                        .strong()
                        .color(TEXT),
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
