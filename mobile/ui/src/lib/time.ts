/** "Used 2 hours ago", in plain words. */
export function usedAgo(ms: number | null, now = Date.now()): string {
  if (ms === null) return "Not used yet";
  const min = Math.round((now - ms) / 60000);
  if (min < 2) return "Used just now";
  if (min < 60) return `Used ${min} minutes ago`;
  const h = Math.round(min / 60);
  if (h < 24) return `Used ${h} ${h === 1 ? "hour" : "hours"} ago`;
  const d = Math.round(h / 24);
  if (d === 1) return "Used yesterday";
  if (d < 30) return `Used ${d} days ago`;
  return "Used a while ago";
}
