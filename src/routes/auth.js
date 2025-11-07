const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { verifyToken } = require('../middleware/auth');

// Public routes - no authentication required
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/generate-otp', authController.generateOTP);
router.post('/verify-otp', authController.verifyOTP);
router.post('/reset-password', authController.resetPassword);

// VULNERABILITY: Debug endpoint for testing
router.post('/debug-login', (req, res) => {
  console.log('⚠️  DEBUG LOGIN ENDPOINT ACCESSED');
  res.json({
    success: true,
    message: 'Use bypassAuth parameter in login request',
    hint: 'bypassAuth: "vulnpay_debug_2024"'
  });
});

module.exports = router;