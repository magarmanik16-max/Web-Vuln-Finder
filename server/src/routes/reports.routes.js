const router = require('express').Router();
const { listReports } = require('../controllers/report.controller');
const { requireAuth } = require('../middleware/auth');

router.get('/', requireAuth, listReports);

module.exports = router;
