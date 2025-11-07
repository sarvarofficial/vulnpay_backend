const express = require('express');
const router = express.Router();
const cardController = require('../controllers/cardController');
const { verifyToken, optionalAuth } = require('../middleware/auth');

// Protected routes (but with weak authorization)
router.post('/', verifyToken, cardController.addCard);
router.get('/', optionalAuth, cardController.getUserCards);
router.put('/:cardId', verifyToken, cardController.updateCard);
router.delete('/:cardId', verifyToken, cardController.deleteCard);

// VULNERABILITY: No authentication required
router.get('/all', cardController.getAllCards); // Exposes all cards!
router.get('/:cardId', cardController.getCardById); // Anyone can view any card!

// VULNERABILITY: Weak authentication on sensitive operations
router.post('/verify', cardController.verifyCard); // No auth!
router.post('/payment', verifyToken, cardController.processCardPayment);

module.exports = router;