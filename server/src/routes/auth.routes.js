const router = require('express').Router();
const c = require('../controllers/auth.controller');
const { requireAuth, softAuth } = require('../middleware/auth');

router.post('/register', softAuth, c.register); // controller gates: first user bootstraps, afterwards admin-only
router.post('/login', c.login);
router.post('/logout', requireAuth, c.logout);
router.get('/me', requireAuth, c.me);

module.exports = router;
