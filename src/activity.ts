/**
 * What counts as activity — standard v0.9 §8.2.
 *
 * The rule, quoted, because the whole of this file is one distinction:
 *
 *   "Activity means authenticated requests caused by a USER ACTION, plus a
 *    client heartbeat sent at most every 5 minutes while the user is
 *    interacting with the page (keyboard, pointer, touch, or scroll).
 *
 *    Not activity: background polling, auto-refresh, Socket.io keep-alives,
 *    and prefetching. These requests carry the header `X-Rosor-Background: 1`
 *    and never reset the timer."
 *
 * WHY THIS MATTERS MORE THAN IT LOOKS. Get it wrong in the permissive
 * direction and §8.1's inactivity timeout is enforced against nobody: one page
 * left open on a dashboard that refreshes itself keeps a session alive
 * indefinitely, and the session limits read as policy that is written down and
 * not in effect. Nothing fails, nothing logs, and an audit would find the
 * timeout configured correctly.
 *
 * THE MARKER IS OPT-OUT, NOT OPT-IN, and that is deliberate. A request is
 * activity unless it says otherwise, so forgetting the header makes a
 * background poll count — annoying, and visible, because somebody's session
 * stops timing out. The opposite default would make a forgotten header log
 * people out mid-task, which is the failure people work around rather than
 * report.
 */

/** §8.2's header. Lower case: Node normalises incoming header names. */
export const BACKGROUND_HEADER = 'x-rosor-background';

/** §8.2: at most every 5 minutes, and only while the user is interacting. */
export const HEARTBEAT_MAX_INTERVAL_MS = 5 * 60_000;

type HeaderBag = Record<string, string | string[] | undefined>;

/**
 * Case-insensitive, though Node lower-cases incoming header names itself.
 *
 * The scan is for everyone else: a hand-built object in a test, a framework
 * that preserves the wire casing, a Headers instance spread into a plain
 * object. Relying on the runtime's normalisation would make this correct in
 * production and quietly wrong everywhere it is exercised.
 */
function headerValue(headers: HeaderBag, name: string): string | undefined {
  const wanted = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    const value = headers[key];
    return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

/**
 * Whether the caller has declared this request background traffic.
 *
 * Only the exact string "1". Anything else — "true", "yes", an empty value —
 * is NOT a declaration, on the same reasoning as §7's off-switch: a control
 * whose spelling can be got subtly wrong is one that fails in whichever
 * direction the typo happens to point. Here the safe direction is to treat an
 * unclear marker as ordinary traffic.
 */
export function isBackgroundRequest(headers: HeaderBag): boolean {
  return headerValue(headers, BACKGROUND_HEADER) === '1';
}

/**
 * Whether a request should reset the inactivity timer.
 *
 * Every authenticated request except a declared background one. The library
 * cannot tell a click from a poll on its own — only the application knows
 * which of its own requests are automatic — so the header is the interface and
 * this is the one place the answer is computed.
 */
export function countsAsActivity(headers: HeaderBag): boolean {
  return !isBackgroundRequest(headers);
}
