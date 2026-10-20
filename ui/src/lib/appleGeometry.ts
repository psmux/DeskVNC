/**
 * What the Mac's desktop looked like, remembered between sessions.
 *
 * The native Apple Screen Sharing client sends the console display's
 * geometry in its first record, so the Mac attaches to the session the
 * person is already using. A client that says nothing about the display
 * lets the Mac choose, and what it may choose is a new session, which
 * shows a login screen.
 *
 * The geometry is not known before the first session, and it must not be
 * guessed: the pixels and the points are separate, and a guess that gets
 * them the wrong way round resizes the person's desktop. So the last
 * confirmed geometry is remembered per host and sent on the next connect.
 */
const PREFIX = "deskvnc.apple.geometry.";

export interface AppleGeometry {
  /** The picture size, in pixels. */
  pixelWidth: number;
  pixelHeight: number;
  /** The desktop size, in points. */
  pointWidth: number;
  pointHeight: number;
}

function key(hostId: string): string {
  return `${PREFIX}${hostId}`;
}

/**
 * The geometry remembered for a host, or null when there is none.
 *
 * A half remembered geometry is no use: the pixels and the points have to
 * come from the same confirmation, so anything incomplete is ignored.
 */
export function readAppleGeometry(hostId: string | null | undefined): AppleGeometry | null {
  if (!hostId) return null;
  try {
    const raw = localStorage.getItem(key(hostId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<AppleGeometry>;
    const { pixelWidth, pixelHeight, pointWidth, pointHeight } = parsed;
    if (
      !Number.isInteger(pixelWidth) || !Number.isInteger(pixelHeight) ||
      !Number.isInteger(pointWidth) || !Number.isInteger(pointHeight) ||
      (pixelWidth as number) <= 0 || (pixelHeight as number) <= 0 ||
      (pointWidth as number) <= 0 || (pointHeight as number) <= 0
    ) {
      return null;
    }
    const geometry = {
      pixelWidth: pixelWidth as number,
      pixelHeight: pixelHeight as number,
      pointWidth: pointWidth as number,
      pointHeight: pointHeight as number,
    };
    return isPanelGeometry(geometry) ? geometry : null;
  } catch {
    return null;
  }
}

/** A desktop large enough to be the Mac's panel rather than the viewer window. */
export function isPanelGeometry(geometry: AppleGeometry | null): geometry is AppleGeometry {
  return !!geometry
    && geometry.pixelWidth >= 1280 && geometry.pixelHeight >= 800
    && geometry.pointWidth >= 1280 && geometry.pointHeight >= 800
    && geometry.pointWidth <= geometry.pixelWidth
    && geometry.pointHeight <= geometry.pixelHeight;
}

/** Remember the geometry a session confirmed. */
export function writeAppleGeometry(hostId: string | null | undefined, geometry: AppleGeometry | null): void {
  if (!hostId || !isPanelGeometry(geometry)) return;
  const existing = readAppleGeometry(hostId);
  if (existing) {
    const existingPoints = existing.pointWidth * existing.pointHeight;
    const nextPoints = geometry.pointWidth * geometry.pointHeight;
    // A later layout can be a shrunk window-sized desktop. Keep the panel.
    if (existingPoints > nextPoints) return;
    // The same desktop at a lower stream quality is not a smaller desktop.
    // Overwriting the sharp pixels with them is how one Low session made
    // every later connection ask the Mac for a blurry stream.
    if (existingPoints === nextPoints
      && existing.pixelWidth * existing.pixelHeight >= geometry.pixelWidth * geometry.pixelHeight) return;
  }
  try {
    localStorage.setItem(
      key(hostId),
      JSON.stringify({
        pixelWidth: geometry.pixelWidth,
        pixelHeight: geometry.pixelHeight,
        pointWidth: geometry.pointWidth,
        pointHeight: geometry.pointHeight,
      }),
    );
  } catch {
    // A browser that refuses to store it is not a reason to fail a session.
  }
}

/** The four numbers the connect command takes. */
export function appleGeometryArguments(geometry: AppleGeometry | null): [number, number, number, number] | null {
  if (!geometry) return null;
  return [
    geometry.pixelWidth,
    geometry.pixelHeight,
    geometry.pointWidth,
    geometry.pointHeight,
  ];
}
