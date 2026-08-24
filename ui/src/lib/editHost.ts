/**
 * "Open this computer's settings", asked for from somewhere that cannot open
 * a dialog itself.
 *
 * The host editor lives in the library window. A session may be in a window
 * of its own, so a disconnect panel that wants to send the user to a setting
 * broadcasts this instead of trying to render the editor where it is not.
 *
 * `section` says where to land. `"security"` opens Advanced with the Security
 * disclosure already expanded, which is the same "open it expanded" rule the
 * editor applies to a setting that is already on: a setting that changes how
 * the connection is made is never reachable only by people who remember it
 * exists.
 */
export const EDIT_HOST_EVENT = "library://edit-host";

export interface EditHostRequest {
  hostId: string;
  section?: "security";
}
