/**
 * A session id for the browser dev mock, where there is no shell to mint one.
 *
 * Two mock sessions must never share an id, or they collide on one tab or
 * pane. `crypto.randomUUID` gives that from the platform's CSPRNG, the same
 * source the hosts store uses for new ids, instead of `Math.random`, which
 * code scanning rightly flags wherever an id could end up meaning something.
 */
export function devSessionId(): string {
  return `dev-${crypto.randomUUID()}`;
}
