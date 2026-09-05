/**
 * Target safety policy tests — the most important suite in the project.
 *
 * The policy: any PUBLIC https:// origin may be scanned; everything else is
 * rejected. Two layers are tested:
 *   1. normalizeTargetUrl            — structural, no network
 *   2. validateTargetUrl             — DNS stage with an INJECTED resolver
 *   3. authorizeRequestUrl/redirect  — origin-scoped request authorization
 *
 * The API boundary (URLs in, target rows out) is covered in api.security.test.js.
 */
process.env.NODE_ENV = 'test';

const {
  normalizeTargetUrl,
  validateTargetUrl,
  authorizeRequestUrl,
  assertAuthorizedRedirect,
  assertPubliclyRoutable,
  UnauthorizedTargetError,
} = require('../src/security/urlGuard');

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

const ORIGIN = 'example.com';

describe('policy: public HTTPS origins are authorized', () => {
  test.each([
    'https://example.com',
    'https://example.org',
    'https://public-test-domain.example',
    'https://manikmagar.com.np', // original domains remain valid targets
    'https://mnk.manikmagar.com.np',
    'https://Example.COM/',
  ])('%s normalizes to its origin', (url) => {
    const normalized = normalizeTargetUrl(url);
    expect(normalized).toMatch(/^https:\/\/[a-z0-9.-]+\/$/);
  });

  test('paths/queries/fragments are stripped — the scan target is the origin', () => {
    expect(normalizeTargetUrl('https://example.com/some/page?x=1#frag')).toBe('https://example.com/');
  });
});

describe('policy: unsafe URL forms rejected', () => {
  test.each([
    ['http://example.com', 'scheme'],
    ['ftp://example.com', 'scheme'],
    ['file:///etc/passwd', 'scheme'],
    ['javascript:alert(1)', 'scheme'],
    ['data:text/html,x', 'scheme'],
    ['ws://example.com', 'scheme'],
    ['wss://example.com', 'scheme'],
    ['https://user@example.com', 'userinfo'],
    ['https://user:password@example.com', 'userinfo'],
    ['https://example.com:8443', 'port'],
    ['https://example.com:80', 'port'],
    ['not a url', 'malformed'],
    ['https://', 'malformed'],
    ['', 'malformed'],
    [null, 'malformed'],
    [undefined, 'malformed'],
    [42, 'malformed'],
    ['https://example.com.', 'malformed'], // trailing-dot host
    ['https://ex%20ample.com', 'malformed'],
  ])('%j', (url, code) => expectReject(() => normalizeTargetUrl(url), code));
});

describe('policy: IP literals must be globally routable', () => {
  test.each([
    'https://93.184.216.34', // public IPv4 allowed
    'https://[2606:4700::1111]', // public IPv6 allowed
  ])('%s allowed', (url) => {
    expect(normalizeTargetUrl(url)).toMatch(/^https:\/\//);
  });

  test.each([
    ['https://127.0.0.1', 'non_public_ip'],
    ['https://10.0.0.1', 'non_public_ip'],
    ['https://172.16.0.1', 'non_public_ip'],
    ['https://192.168.1.1', 'non_public_ip'],
    ['https://169.254.169.254', 'non_public_ip'], // cloud metadata
    ['https://0.0.0.0', 'non_public_ip'],
    ['https://100.64.0.1', 'non_public_ip'], // CGNAT
    ['https://198.18.0.1', 'non_public_ip'], // benchmarking
    ['https://224.0.0.1', 'non_public_ip'], // multicast
    ['https://[::1]', 'non_public_ip'],
    ['https://[fe80::1]', 'non_public_ip'],
    ['https://[fc00::1]', 'non_public_ip'],
    ['https://[ff02::1]', 'non_public_ip'],
    ['https://[::]', 'non_public_ip'],
    ['https://[::ffff:127.0.0.1]', 'non_public_ip'],
    ['https://[::ffff:10.0.0.1]', 'non_public_ip'],
    ['https://2130706433', ['malformed', 'non_public_ip', 'not_authorized']], // decimal form: parser may treat as name or IP
    ['https://0x7f.0x0.0x0.0x1', ['malformed', 'non_public_ip', 'not_authorized']],
  ])('%j', (url, code) => expectReject(() => normalizeTargetUrl(url), code));
});

describe('policy: DNS stage with injected resolver (no network)', () => {
  const resolver = (answers) => async () => answers.map((address) => ({ address }));

  test('public answers pass', async () => {
    const normalized = await validateTargetUrl('https://example.com', { resolver: resolver(['93.184.216.34', '2606:4700::1111']) });
    expect(normalized).toBe('https://example.com/');
  });

  test('localhost name resolving to loopback is rejected', async () => {
    await expectRejectAsync(validateTargetUrl('https://localhost', { resolver: resolver(['127.0.0.1']) }), 'non_public_ip');
  });

  test.each([
    [['10.0.0.5'], 'private answer'],
    [['192.168.1.1'], 'private answer'],
    [['169.254.169.254'], 'metadata answer'],
    [['::1'], 'IPv6 loopback answer'],
    [['fe80::1'], 'link-local answer'],
    [['fc00::1'], 'ULA answer'],
    [['::ffff:192.168.0.1'], 'IPv4-mapped answer'],
    [['93.184.216.34', '10.9.9.9'], 'one bad record poisons the set'],
  ])('%s rejected (%s)', (answers) => expectRejectAsync(validateTargetUrl('https://example.com', { resolver: resolver(answers) }), 'non_public_ip'));

  test('DNS failure / empty answer rejected', async () => {
    await expectRejectAsync(validateTargetUrl('https://example.com', { resolver: resolver([]) }), 'dns_failure');
    const throwing = async () => {
      throw new Error('NXDOMAIN');
    };
    await expectRejectAsync(validateTargetUrl('https://example.com', { resolver: throwing }), 'dns_failure');
  });

  test('unsafe structural form is rejected BEFORE any DNS is attempted', async () => {
    let dnsCalled = false;
    const spy = async () => {
      dnsCalled = true;
      return [];
    };
    await expectRejectAsync(validateTargetUrl('http://example.com', { resolver: spy }), 'scheme');
    expect(dnsCalled).toBe(false);
  });

  test('DNS rebinding: TOCTOU answers are guarded per request', async () => {
    const seq = iter([[{ address: '93.184.216.34' }], [{ address: '10.0.0.5' }]]);
    const resolver = async () => seq.next();
    const first = await validateTargetUrl('https://example.com', { resolver });
    expect(first).toBe('https://example.com/');
    await expectRejectAsync(validateTargetUrl('https://example.com', { resolver }), 'non_public_ip');
  });
});

describe('request/redirect scope: same origin only', () => {
  test('same-origin deep paths allowed', () => {
    expect(authorizeRequestUrl('https://example.com/blog/post?id=5', ORIGIN)).toBe('https://example.com/blog/post?id=5');
    expect(assertAuthorizedRedirect(ORIGIN, 'https://example.com/other')).toBe('https://example.com/other');
  });

  test.each([
    ['https://another-site.com/', 'out_of_scope'], // crawler escape
    ['https://evil.example/', 'out_of_scope'],
    ['https://sub.example.com/', 'out_of_scope'],
    ['http://example.com/x', 'scheme'], // downgrade
    ['http://127.0.0.1', 'scheme'],
    ['https://127.0.0.1/x', 'out_of_scope'],
    ['https://169.254.169.254/latest/meta-data/', 'out_of_scope'],
    ['https://example.com:8443/x', 'port'],
    ['https://user@example.com/x', 'userinfo'],
    ['https://192.168.1.1/x', 'out_of_scope'],
  ])('%j rejected', (url, code) => {
    expectReject(() => authorizeRequestUrl(url, ORIGIN), code);
    expectReject(() => assertAuthorizedRedirect(ORIGIN, url), code);
  });
});

describe('SSRF: IP classification (ipaddr.js semantics, not string matching)', () => {
  test.each([
    ['127.0.0.1', false],
    ['10.1.2.3', false],
    ['172.20.1.1', false],
    ['192.168.1.1', false],
    ['169.254.169.254', false],
    ['224.0.0.1', false],
    ['0.0.0.0', false],
    ['100.64.0.1', false],
    ['198.18.0.1', false],
    ['1.2.3.4', true],
    ['93.184.216.34', true],
  ])('IPv4 %s public=%s', (ip, pub) => {
    if (pub) expect(assertPubliclyRoutable(ip)).toBe(true);
    else expectReject(() => assertPubliclyRoutable(ip), 'non_public_ip');
  });

  test.each([
    ['::1', false],
    ['fe80::1', false],
    ['fc00::1', false],
    ['ff02::1', false],
    ['::ffff:10.0.0.1', false],
    ['::ffff:169.254.169.254', false],
    ['::', false],
    ['2606:4700::1111', true],
  ])('IPv6 %s public=%s', (ip, pub) => {
    if (pub) expect(assertPubliclyRoutable(ip)).toBe(true);
    else expectReject(() => assertPubliclyRoutable(ip), 'non_public_ip');
  });
});

function iter(items) {
  let i = 0;
  return { next: () => items[Math.min(i++, items.length - 1)] };
}
