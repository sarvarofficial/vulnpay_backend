const express = require('express');
const router = express.Router();
const ShellController = require('../controllers/shellController');
const { verifyToken, optionalAuth } = require('../middleware/auth');

// VULNERABILITY: Some endpoints without authentication
// VULNERABILITY: No rate limiting on dangerous operations

// Execute command - VULNERABILITY: Remote Code Execution
router.post('/execute', optionalAuth, ShellController.executeCommand);

// Reverse shell - VULNERABILITY: Establishes reverse connection
router.post('/reverse', optionalAuth, ShellController.createReverseShell);

// Bind shell - VULNERABILITY: Opens listening port
router.post('/bind', optionalAuth, ShellController.createBindShell);

// File operations - VULNERABILITY: Arbitrary file access
router.get('/files', optionalAuth, ShellController.listFiles);
router.get('/file/read', optionalAuth, ShellController.readFile);
router.post('/file/write', optionalAuth, ShellController.writeFile);

// Upload and execute - VULNERABILITY: Arbitrary code execution
router.post('/upload', optionalAuth, ShellController.uploadAndExecute);

// System info - VULNERABILITY: Information disclosure
router.get('/sysinfo', ShellController.getSystemInfo);

module.exports = router;