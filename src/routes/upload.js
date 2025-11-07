const express = require('express');
const router = express.Router();
const uploadController = require('../controllers/uploadController');
const { verifyToken, optionalAuth } = require('../middleware/auth');

// VULNERABILITY: Some endpoints without proper authentication
router.post('/profile-picture', verifyToken, uploadController.uploadProfilePicture);
router.post('/profile-bio', verifyToken, uploadController.updateProfileBio);

// VULNERABILITY: No authentication required to access uploaded files
router.get('/profile/:filename', uploadController.getProfilePicture);

// VULNERABILITY: Anyone can list all uploaded files
router.get('/list', uploadController.listUploads);

// VULNERABILITY: Anyone can delete any profile picture
router.delete('/profile-picture/:userId', optionalAuth, uploadController.deleteProfilePicture);

module.exports = router;