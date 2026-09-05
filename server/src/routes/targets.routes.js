const router = require('express').Router();
const { listTargets } = require('../controllers/target.controller');
const { requireAuth } = require('../middleware/auth');

// Authenticated read-only view of the immutable allowlist. There is no
// create/update/delete and no URL parameter anywhere — by design.
router.get('/', requireAuth, listTargets);

module.exports = router;
