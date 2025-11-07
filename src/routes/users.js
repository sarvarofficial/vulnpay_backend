const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { verifyToken, requireRole, optionalAuth } = require('../middleware/auth');

// VULNERABILITY: Some endpoints don't require authentication
router.get('/profile/:userId', optionalAuth, userController.getUserProfile);
router.get('/balance/:userId', userController.getUserBalance); // No auth!
router.get('/sessions/:userId', userController.getUserSessions); // No auth!

// Protected routes (but with weak authorization)
router.put('/profile', verifyToken, userController.updateUserProfile);
router.post('/change-password', verifyToken, userController.changePassword);

// VULNERABILITY: No admin check on these endpoints
router.get('/all', verifyToken, userController.getAllUsers);
router.get('/search', verifyToken, userController.searchUsers);
router.delete('/:userId', verifyToken, userController.deleteUser);
router.post('/:userId/adjust-balance', verifyToken, userController.adjustBalance);

module.exports = router;