/**
 * SSRF-safe target URL validation (defense-in-depth).
 *
 * The primary authorization boundary is config/targets.js: clients can only
 * name targets by ID. This module is the second wall used by the scan service
 * and (mirrored in Python) by the scanner itself before any network request.
 *
 * Design rules (see docs/SECURITY-DESIGN.md):
 *  - Parse with the WHATWG URL parser; malformed input is rejected, never "fixed".
 *  - Exact-match hostname against the allowlist — no string tricks, no
 *    "ends with", no substring matching. Subdomains, lookalikes, trailing-dot
 *    hosts, raw IPs, localhost etc. all fail the exact match.
 *  - Only https, no explicit port, no userinfo, origin-only paths.
 *  - DNS resolution happens ONLY after allowlist success, and EVERY resolved
 *    address must be globally routable. A public hostname that resolves to a
 *    private/loopback/link-local address (DNS rebinding / pinning tricks) is
 *    rejected. Address classification uses ipaddr.js range semantics, not
 *    string matching.
 *  - Redirects must stay on the exact authorized origin.
 */

const { URL } = require('url');
const dnsPromises = require('dns').promises;
const ipaddr = require('ipaddr.js');
const { AUTHORIZED_TARGETS } = require('../config/targets');

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
 * Stage 1 — exact allowlist check. No DNS, no network, synchronous.
 * Returns the authorized target the URL corresponds to, or throws.
 */
function validateAgainstAllowlist(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') reject('malformed');

  let u;
  try {
    u = new URL(rawUrl.trim());
  } catch {
    reject('malformed');
  }

  if (u.protocol !== 'https:') reject('scheme'); // alternate schemes rejected
  if (u.username || u.password) reject('userinfo');
  if (u.port !== '') reject('port'); // alternate ports rejected (443 only)
  if (u.pathname !== '/' && u.pathname !== '') reject('path'); // origin-level authorization
  if (u.search || u.hash) reject('path');

  // Exact host equality against the allowlist. Everything else — arbitrary
  // domains, arbitrary/lookalike subdomains, IPs (any notation), localhost,
  // internal hostnames — fails here because it can never byte-match a host.
  const target = AUTHORIZED_TARGETS.find((t) => u.hostname === t.host);
  if (!target) reject('not_authorized');
  return target;
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
 * Full validation: allowlist first, then DNS -> every answer must be public.
 * @param {string} rawUrl
 * @param {{resolveDns?: boolean, resolver?: (host: string) => Promise<Array<{address: string}>>}} opts
 * @returns {Promise<object>} the authorized target
 */
async function validateTargetUrl(rawUrl, opts = {}) {
  // Allowlist gate runs BEFORE any DNS — unauthorized names never resolve.
  const target = validateAgainstAllowlist(rawUrl);

  if (opts.resolveDns !== false) {
    const lookup = opts.resolver || defaultResolver;
    let answers = [];
    try {
      answers = await lookup(target.host);
    } catch {
      reject('dns_failure');
    }
    if (!Array.isArray(answers) || answers.length === 0) reject('dns_failure');
    for (const a of answers) assertPubliclyRoutable(a.address);
  }
  return target;
}

/**
 * Redirect policy: every hop must re-validate to the SAME authorized target.
 * A redirect is rejected unless it lands byte-exactly on the allowed origin —
 * so http-downgrade, cross-target, subdomain, IP, and open-redirect hops all fail.
 */
function assertAuthorizedRedirect(currentTarget, locationUrl) {
  const next = validateAgainstAllowlist(locationUrl);
  if (next.id !== currentTarget.id) reject('unauthorized_redirect');
  return next;
}

module.exports = {
  UnauthorizedTargetError,
  validateAgainstAllowlist,
  validateTargetUrl,
  assertAuthorizedRedirect,
  assertPubliclyRoutable,
};
