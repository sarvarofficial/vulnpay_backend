const express = require('express');
const router = express.Router();
const transactionController = require('../controllers/transactionController');
const { verifyToken, optionalAuth } = require('../middleware/auth');

// VULNERABILITY: Mixed authentication requirements
router.get('/', verifyToken, transactionController.getTransactions);
router.post('/transfer', verifyToken, transactionController.createTransfer);
router.get('/search', verifyToken, transactionController.searchTransactions);

// VULNERABILITY: No authentication on some endpoints
router.get('/all', transactionController.getAllTransactions); // No auth!
router.get('/:transactionId', transactionController.getTransactionById); // No auth!

// VULNERABILITY: Weak authorization
router.put('/:transactionId', verifyToken, transactionController.updateTransaction);
router.post('/:transactionId/cancel', verifyToken, transactionController.cancelTransaction);

module.exports = router;