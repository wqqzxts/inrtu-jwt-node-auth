const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth');
const authMiddleware = require('../middleware/auth');

router.post('/api/v1/auth/register', authController.register);
router.post('/api/v1/auth/login', authController.login);
router.post('/api/v1/auth/logout', authController.logout);
router.post('/api/v1/auth/register', authController.refresh);
// router.post('/api/v1/auth/logout');

module.exports = router;