/**
 * SSRF-safe URL validation for user-supplied public HTTPS targets.
 *
 * The primary boundary is now the TARGET SAFETY POLICY (config/targets.js):
 * any public https:// origin may be submitted, but every destination must
 * pass this guard. The rules are unchanged from the allowlist era except
 * that "exact match against two domains" is replaced by "must be a public,
 * globally routable HTTPS origin":
 *
 *  - Parse with the WHATWG URL parser; malformed input is rejected, never "fixed".
 *  - HTTPS only; no credentials/userinfo; no explicit port (443 only);
 *    fragments/queries are stripped by normalization (the scan target is the origin).
 *  - Hostnames that ARE IP literals must be globally routable (no private/
 *    loopback/link-local/multicast/reserved literals — including decimal, hex,
 *    octal and IPv4-mapped encodings, which the WHATWG parser canonicalizes).
 *  - DNS resolution happens after the structural gate, and EVERY resolved
 *    address must be globally routable (validated per request — rebinding
 *    resistant). Classification uses ipaddr.js range semantics, not regexes.
 *  - The HTTP engine pins the connection to a validated IP (validate →
 *    resolve → pin → connect) and re-authorizes every redirect hop.
 */

const { URL } = require('url');
const dnsPromises = require('dns').promises;
const ipaddr = require('ipaddr.js');

class UnauthorizedTargetError extends Error {
  constructor(code, message) {
    super(message || `Target rejected: ${code}`);
    this.name = 'UnauthorizedTargetError';
    this.code = code;
    this.statusCode = 400;
  }
}

const reject = (code) => {
  throw new UnauthorizedTargetError(code);
};

/** Default DNS resolver; tests inject a fake to stay offline. */
const defaultResolver = (hostname) => dnsPromises.lookup(hostname, { all: true, verbatim: true });

/**
 * Structural validation + normalization of a user-supplied target.
 * Returns the normalized ORIGIN (https://host/) — the scan target.
 * No DNS, no network, synchronous.
 */
function normalizeTargetUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') reject('malformed');

  let u;
  try {
    u = new URL(rawUrl.trim());
  } catch {
    reject('malformed');
  }

  if (u.protocol !== 'https:') reject('scheme'); // http, ftp, file, javascript:, data:, ws: … all rejected
  if (u.username || u.password) reject('userinfo');
  if (u.port !== '') reject('port'); // explicit ports rejected (443 only; the parser hides the default)
  if (!u.hostname) reject('malformed');
  if (u.hostname.endsWith('.')) reject('malformed'); // trailing-dot host forms are unexpected
  if (u.hostname.includes('%')) reject('malformed'); // percent/zone-id forms are unexpected
  // RFC 6761 loopback names can never be legitimate scan targets.
  if (u.hostname === 'localhost' || u.hostname.endsWith('.localhost')) reject('non_public_ip');

  // WHATWG hostname KEEPS brackets for IPv6 literals — strip them for
  // classification, and reject IP-literal hosts that are not globally routable.
  const bareHost = u.hostname.replace(/^\[/, '').replace(/\]$/, '');
  try {
    let addr = ipaddr.parse(bareHost);
    if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) addr = addr.toIPv4Address();
    if (addr.range() !== 'unicast') reject('non_public_ip');
  } catch (e) {
    if (e instanceof UnauthorizedTargetError) throw e;
    // not an IP literal — a regular hostname, fine
  }

  return `https://${u.hostname}/`;
}

/**
 * Full target validation: structural gate first, then DNS — every answer must
 * be globally routable. Returns the normalized origin URL.
 */
async function validateTargetUrl(rawUrl, opts = {}) {
  const normalized = normalizeTargetUrl(rawUrl); // rejects before any DNS
  if (opts.resolveDns !== false) {
    const host = new URL(normalized).hostname;
    const lookup = opts.resolver || defaultResolver;
    let answers = [];
    try {
      answers = await lookup(host);
    } catch {
      reject('dns_failure');
    }
    if (!Array.isArray(answers) || answers.length === 0) reject('dns_failure');
    for (const a of answers) assertPubliclyRoutable(a.address);
  }
  return normalized;
}

/**
 * Reject any IP that is not global unicast. Covers loopback, private (RFC1918),
 * unique-local, link-local (incl. cloud metadata 169.254.169.254), multicast,
 * unspecified, CGNAT, benchmarking, IPv4-mapped IPv6, 6to4/Teredo, reserved.
 */
function assertPubliclyRoutable(ipString) {
  let addr;
  try {
    addr = ipaddr.parse(ipString);
  } catch {
    reject('bad_dns_answer');
  }
  if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) addr = addr.toIPv4Address();
  if (addr.range() !== 'unicast') reject('non_public_ip');
  return true;
}

/**
 * Authorize an arbitrary-depth request URL that must stay on the scanned
 * origin (used by the HTTP engine for redirects and by the crawler gate).
 * Structural rules are identical to the target policy; the host must equal
 * the origin this scan was authorized for.
 */
function authorizeRequestUrl(rawUrl, originHost) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') reject('malformed');

  let u;
  try {
    u = new URL(rawUrl.trim());
  } catch {
    reject('malformed');
  }
  if (u.protocol !== 'https:') reject('scheme');
  if (u.username || u.password) reject('userinfo');
  if (u.port !== '') reject('port');
  if (!u.hostname) reject('malformed');
  if (u.hostname !== String(originHost).toLowerCase()) reject('out_of_scope');
  u.fragment = '';
  return u.href;
}

/**
 * Redirect policy: every hop must be re-validated and must stay on the
 * scanned origin — a redirect to another site (even a public one) leaves the
 * authorized scope and is rejected, as is any downgrade/port/userinfo hop.
 */
function assertAuthorizedRedirect(originHost, locationUrl) {
  return authorizeRequestUrl(locationUrl, originHost);
}

module.exports = {
  UnauthorizedTargetError,
  normalizeTargetUrl,
  validateTargetUrl,
  authorizeRequestUrl,
  assertAuthorizedRedirect,
  assertPubliclyRoutable,
};
