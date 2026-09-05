/**
 * THE most important test suite in the project: the target authorization
 * boundary (MASTER.md §6/§7/§9/§17).
 *
 * Two layers are tested:
 *   1. urlGuard.validateAgainstAllowlist — pure logic, no network.
 *   2. urlGuard.validateTargetUrl        — DNS stage with an INJECTED resolver
 *      so SSRF classification is verified without depending on external DNS.
 *
 * The API boundary itself is covered in api.security.test.js: clients can only
 * send target IDs, so a URL can never even reach this guard via HTTP.
 */
process.env.NODE_ENV = 'test';

const {
  validateAgainstAllowlist,
  validateTargetUrl,
  assertAuthorizedRedirect,
  assertPubliclyRoutable,
  UnauthorizedTargetError,
} = require('../src/security/urlGuard');

const AUTHORIZED = 'https://manikmagar.com.np';
const AUTHORIZED_DYN = 'https://mnk.manikmagar.com.np';

const expectReject = (fn, codes) => {
  const accepted = Array.isArray(codes) ? codes : codes ? [codes] : null;
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(UnauthorizedTargetError);
    if (accepted) expect(accepted).toContain(e.code);
    return;
  }
  throw new Error(`expected rejection${codes ? ` (${accepted.join('|')})` : ''}, but call succeeded`);
};

const expectRejectAsync = async (p, code) => {
  await expect(p).rejects.toBeInstanceOf(UnauthorizedTargetError);
  if (code) await expect(p).rejects.toMatchObject({ code });
};

describe('allowlist: AUTHORIZED targets pass', () => {
  test('exact authorized origins', () => {
    expect(validateAgainstAllowlist(AUTHORIZED).id).toBe('STATIC_TARGET');
    expect(validateAgainstAllowlist(AUTHORIZED_DYN).id).toBe('DYNAMIC_TARGET');
    expect(validateAgainstAllowlist('https://manikmagar.com.np/').id).toBe('STATIC_TARGET');
  });
});

describe('allowlist: arbitrary domains/subdomains rejected', () => {
  test.each([
    ['https://example.com', 'not_authorized'],
    ['https://google.com', 'not_authorized'],
    ['https://manikmagar.com.np.evil.com', 'not_authorized'], // lookalike suffix
    ['https://evil.com/manikmagar.com.np', ['path', 'not_authorized']], // path trick
    ['https://evilmanikmagar.com.np', 'not_authorized'],
    ['https://www.manikmagar.com.np', 'not_authorized'], // unauthorized subdomain
    ['https://api.manikmagar.com.np', 'not_authorized'],
    ['https://manikmagar.com.np.', 'not_authorized'], // trailing-dot host
  ])('%s', (url, code) => expectReject(() => validateAgainstAllowlist(url), code));

  test('URL-parser normalization equivalences: uppercase host and explicit :443 are the SAME origin and pass', () => {
    // WHATWG URL lowercases hostnames and strips the default port, so these are
    // byte-identical origins to the allowlist entries — not bypasses.
    expect(validateAgainstAllowlist('https://MANIKMAGAR.COM.NP').id).toBe('STATIC_TARGET');
    expect(validateAgainstAllowlist('https://manikmagar.com.np:443').id).toBe('STATIC_TARGET');
  });
});

describe('allowlist: schemes, ports, userinfo, paths, malformed', () => {
  test.each([
    ['http://manikmagar.com.np', 'scheme'], // downgrade to http
    ['ftp://manikmagar.com.np', 'scheme'],
    ['file:///etc/passwd', 'scheme'],
    ['https://manikmagar.com.np:8443', 'port'], // alternate port
    ['https://user@manikmagar.com.np', 'userinfo'],
    ['https://user:pass@manikmagar.com.np', 'userinfo'],
    ['https://manikmagar.com.np/admin', 'path'],
    ['https://manikmagar.com.np?x=1', 'path'],
    ['https://manikmagar.com.np#frag', 'path'],
    ['not a url at all', 'malformed'],
    ['https://', 'malformed'],
    ['//manikmagar.com.np', 'malformed'],
    ['', 'malformed'],
    [null, 'malformed'],
    [undefined, 'malformed'],
    [12345, 'malformed'],
  ])('%j', (url, code) => expectReject(() => validateAgainstAllowlist(url), code));
});

describe('allowlist: IP literals & localhost rejected outright', () => {
  test.each([
    ['http://127.0.0.1', ['scheme', 'not_authorized']],
    ['http://localhost', ['scheme', 'not_authorized']],
    ['http://localhost:3000', ['scheme', 'not_authorized']],
    ['https://192.168.1.1', 'not_authorized'],
    ['https://10.0.0.1', 'not_authorized'],
    ['https://172.16.0.9', 'not_authorized'],
    ['https://169.254.169.254', 'not_authorized'], // cloud metadata
    ['https://[::1]', 'not_authorized'],
    ['https://[fe80::1]', 'not_authorized'],
    ['https://[fd00::1]', 'not_authorized'],
    ['https://93.184.216.34', 'not_authorized'], // arbitrary public IP
    ['https://2130706433', 'not_authorized'], // decimal IP encoding of 127.0.0.1
    ['https://0x7f000001', 'not_authorized'], // hex IP encoding
    ['https://0177.0.0.1', 'not_authorized'], // octal encoding
  ])('%s', (url, code) => expectReject(() => validateAgainstAllowlist(url), code));
});

describe('SSRF: IP classification (ipaddr.js semantics, not string matching)', () => {
  test.each([
    ['127.0.0.1', false], // loopback
    ['10.1.2.3', false], // private
    ['172.20.1.1', false], // private
    ['192.168.1.1', false], // private
    ['169.254.169.254', false], // link-local metadata
    ['224.0.0.1', false], // multicast
    ['0.0.0.0', false], // unspecified
    ['100.64.0.1', false], // CGNAT
    ['198.18.0.1', false], // benchmarking
    ['1.2.3.4', true],
    ['93.184.216.34', true],
  ])('IPv4 %s public=%s', (ip, pub) => {
    if (pub) expect(assertPubliclyRoutable(ip)).toBe(true);
    else expectReject(() => assertPubliclyRoutable(ip), 'non_public_ip');
  });

  test.each([
    ['::1', false], // loopback
    ['fe80::1', false], // link-local
    ['fc00::1', false], // ULA
    ['ff02::1', false], // multicast
    ['::ffff:10.0.0.1', false], // IPv4-mapped private
    ['::ffff:169.254.169.254', false], // IPv4-mapped metadata
    ['::', false], // unspecified
    ['2606:4700::1111', true], // public IPv6
  ])('IPv6 %s public=%s', (ip, pub) => {
    if (pub) expect(assertPubliclyRoutable(ip)).toBe(true);
    else expectReject(() => assertPubliclyRoutable(ip), 'non_public_ip');
  });
});

describe('SSRF: DNS stage with injected resolver (no network)', () => {
  const resolver = (answers) => async () => answers.map((address) => ({ address }));

  test('authorized host resolving to public IPs passes', async () => {
    const target = await validateTargetUrl(AUTHORIZED, { resolver: resolver(['104.21.0.5', '172.67.0.5']) });
    expect(target.id).toBe('STATIC_TARGET');
  });

  test('DNS rebinding style answer (public name -> private IP) is rejected', async () => {
    await expectRejectAsync(validateTargetUrl(AUTHORIZED, { resolver: resolver(['10.0.0.5']) }), 'non_public_ip');
  });

  test.each([
    [['127.0.0.1'], 'loopback answer'],
    [['169.254.169.254'], 'metadata answer'],
    [['::1'], 'IPv6 loopback answer'],
    [['::ffff:192.168.0.1'], 'IPv4-mapped answer'],
    [['1.2.3.4', '10.9.9.9'], 'one bad record poisons the set'],
  ])('%s rejected', (answers) => expectRejectAsync(validateTargetUrl(AUTHORIZED, { resolver: resolver(answers) }), 'non_public_ip'));

  test('DNS failure / empty answer rejected', async () => {
    await expectRejectAsync(validateTargetUrl(AUTHORIZED, { resolver: resolver([]) }), 'dns_failure');
    const throwing = async () => {
      throw new Error('NXDOMAIN');
    };
    await expectRejectAsync(validateTargetUrl(AUTHORIZED, { resolver: throwing }), 'dns_failure');
  });

  test('unauthorized host is rejected BEFORE any DNS is attempted', async () => {
    let dnsCalled = false;
    const spy = async () => {
      dnsCalled = true;
      return [];
    };
    await expectRejectAsync(validateTargetUrl('https://example.com', { resolver: spy }), 'not_authorized');
    expect(dnsCalled).toBe(false);
  });
});

describe('redirect policy', () => {
  test('redirect staying on the same authorized origin is allowed', () => {
    const t = validateAgainstAllowlist(AUTHORIZED);
    expect(assertAuthorizedRedirect(t, 'https://manikmagar.com.np').id).toBe('STATIC_TARGET');
  });
  test.each([
    ['http://manikmagar.com.np', 'scheme downgrade'],
    ['https://mnk.manikmagar.com.np', 'cross-target'],
    ['https://evil.com', 'open redirect'],
    ['https://192.168.1.1', 'internal redirect'],
  ])('%s (%s) rejected', (loc) => {
    const t = validateAgainstAllowlist(AUTHORIZED);
    expectReject(() => assertAuthorizedRedirect(t, loc));
  });
});
