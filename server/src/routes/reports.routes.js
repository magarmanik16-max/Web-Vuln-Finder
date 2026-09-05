const router = require('express').Router();
const c = require('../controllers/report.controller');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);
router.post('/', c.generateReport);
router.get('/', c.listReports);
router.get('/:id', c.getReport);
router.get('/:id/pdf', c.downloadPdf);

module.exports = router;
