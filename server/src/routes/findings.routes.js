const router = require('express').Router();
const c = require('../controllers/finding.controller');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);
router.get('/', c.listFindings);
router.get('/:id', c.getFinding);

module.exports = router;
