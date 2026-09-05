const { POLICY_REQUIREMENTS, LEGACY_TARGET_URLS } = require('../config/targets');

/**
 * The target policy is user-supplied public HTTPS origins, validated by the
 * SSRF guard in security/urlGuard.js. This endpoint describes the policy for
 * the dashboard; it is information only — there is no mutable target store.
 */
async function targetPolicy(_req, res) {
  res.json({
    policy: {
      statement: 'Any public HTTPS origin may be submitted for assessment, subject to strict URL and network safety validation.',
      requirements: POLICY_REQUIREMENTS,
      examples: Object.values(LEGACY_TARGET_URLS),
    },
  });
}

module.exports = { targetPolicy };
