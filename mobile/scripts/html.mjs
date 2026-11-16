// HTML escaping for the pages these scripts write or serve.
//
// Escapes all five characters that matter in HTML text and in quoted
// attribute values, so one helper is safe in both places. `&` goes first so
// the entities the later replacements add are not escaped twice.
export const escapeHtml = (s) =>
  String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
