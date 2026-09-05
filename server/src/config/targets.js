/**
 * TARGET SAFETY POLICY — user-supplied public HTTPS targets.
 *
 * The platform is a general-purpose authorized assessment tool: an
 * authenticated user may submit any PUBLIC https:// URL. "Authorized" is now
 * defined by safety validation, not by a name allowlist:
 *
 *   - HTTPS only (any other scheme is rejected)
 *   - no credentials/userinfo, no explicit port, no fragments
 *   - hostname must not be an IP literal in a non-global range
 *   - DNS resolution must return only globally routable addresses
 *   - connections are pinned to a validated IP (validate → resolve → pin → connect)
 *   - redirects must stay on the scan's own origin
 *   - the crawler may only follow same-origin links
 *
 * Private, loopback, link-local, multicast, reserved and otherwise non-global
 * destinations are rejected at every layer (Node AND Python independently).
 *
 * Legacy note: the original platform hard-coded two targets. Old scan records
 * carry targetId STATIC_TARGET / DYNAMIC_TARGET — the mapping below keeps
 * those records displayable and still accepted as scan inputs for backward
 * compatibility. They are examples now, never an authorization boundary.
 */

const urlGuard = require('../security/urlGuard');

const LEGACY_TARGET_URLS = Object.freeze({
  STATIC_TARGET: 'https://manikmagar.com.np',
  DYNAMIC_TARGET: 'https://mnk.manikmagar.com.np',
});

const POLICY_REQUIREMENTS = [
  'HTTPS protocol only',
  'No credentials (user:password@) in the URL',
  'Default port 443 only — no explicit ports',
  'Hostname must resolve to globally routable IP addresses only',
  'Private, loopback, link-local, multicast and reserved ranges are rejected',
  'Redirects must stay on the scanned origin',
  'Crawling is same-origin only and bounded by rate/request/depth limits',
];

/**
 * Structural + DNS validation of a user-supplied target URL.
 * Returns { url, host } where url is the normalized origin (https://host/).
 * Rejects with UnauthorizedTargetError (code + statusCode 400) on any unsafe form.
 */
async function authorizeTarget(rawUrl, opts = {}) {
  const normalized = urlGuard.normalizeTargetUrl(rawUrl); // structural checks
  await urlGuard.validateTargetUrl(normalized, opts); // DNS: all answers global unicast
  const host = new URL(normalized).hostname;
  return { url: normalized, host };
}

/** Accepts legacy IDs for backward compatibility; returns the mapped URL or null. */
function legacyTargetUrl(targetId) {
  if (typeof targetId !== 'string') return null;
  return LEGACY_TARGET_URLS[targetId] || null;
}

/** Display metadata for any scan (new or legacy). */
function targetInfo(scan) {
  if (scan.targetUrl) {
    const host = scan.targetHost || new URL(scan.targetUrl).hostname;
    return { url: scan.targetUrl, host, label: host, legacy: false };
  }
  const url = LEGACY_TARGET_URLS[scan.targetId];
  if (url) {
    const host = new URL(url).hostname;
    return { url, host, label: host, legacy: true };
  }
  return { url: scan.targetId || '', host: scan.targetId || '', label: scan.targetId || '', legacy: true };
}

module.exports = {
  LEGACY_TARGET_URLS,
  POLICY_REQUIREMENTS,
  authorizeTarget,
  legacyTargetUrl,
  targetInfo,
};
