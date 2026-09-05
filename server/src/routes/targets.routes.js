const router = require('express').Router();
const { targetPolicy } = require('../controllers/target.controller');
const { requireAuth } = require('../middleware/auth');

// Describes the target safety policy (user-supplied public HTTPS origins).
// Informational only — there is no mutable target store anywhere.
router.get('/', requireAuth, targetPolicy);

module.exports = router;
