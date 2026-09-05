/**
 * SINGLE AUTHORITATIVE TARGET ALLOWLIST.
 *
 * These are the ONLY targets this platform is authorized to assess.
 * The restriction is architectural, not cosmetic:
 *   - The browser/frontend only ever sees and sends target IDs.
 *   - It can never supply a URL; the backend resolves ID -> authorized URL.
 *   - The Python scanner independently re-enforces the same list
 *     (see scanner/authorized_targets.json + scanner/scanner/authorization.py),
 *     so bypassing this Node layer is not sufficient to scan anything else.
 *
 * Changing this file changes the entire platform's reach. It must never be
 * extended from user input, environment config, or the database.
 */

const AUTHORIZED_TARGETS = Object.freeze([
  Object.freeze({
    id: 'STATIC_TARGET',
    label: 'manikmagar.com.np',
    host: 'manikmagar.com.np',
    authorizedUrl: 'https://manikmagar.com.np',
    type: 'static',
    description: 'Static target — portfolio site assessed via static analysis.',
  }),
  Object.freeze({
    id: 'DYNAMIC_TARGET',
    label: 'mnk.manikmagar.com.np',
    host: 'mnk.manikmagar.com.np',
    authorizedUrl: 'https://mnk.manikmagar.com.np',
    type: 'dynamic',
    description: 'Dynamic target — live application assessed via dynamic testing.',
  }),
]);

const TARGET_IDS = AUTHORIZED_TARGETS.map((t) => t.id);

function resolveTarget(id) {
  if (typeof id !== 'string') return null;
  return AUTHORIZED_TARGETS.find((t) => t.id === id) || null;
}

/** Public shape for the API — no internals leaked. */
function toPublicTarget(t) {
  return {
    id: t.id,
    label: t.label,
    host: t.host,
    type: t.type,
    description: t.description,
    authorizedUrl: t.authorizedUrl,
  };
}

module.exports = { AUTHORIZED_TARGETS, TARGET_IDS, resolveTarget, toPublicTarget };
