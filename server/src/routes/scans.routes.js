const router = require('express').Router();
const c = require('../controllers/scan.controller');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);
router.post('/', c.createScan);
router.get('/', c.listScans);
router.get('/:id', c.getScan);
router.post('/:id/cancel', c.cancelScan);

module.exports = router;
