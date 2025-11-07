const db = require('../config/database');
const { CARD_TYPES } = require('../config/constants');
const { logActivity } = require('../middleware/logger');

// VULNERABILITY: Storing full card details in plaintext
const addCard = async (req, res) => {
  try {
    const userId = req.user.id;
    const { cardNumber, cardHolder, expiryDate, cvv, cardType, isPrimary } = req.body;

    // VULNERABILITY: No input validation
    if (!cardNumber || !cardHolder || !expiryDate || !cvv) {
      return res.status(400).json({
        success: false,
        message: 'All card fields are required'
      });
    }

    // VULNERABILITY: No card number validation (Luhn algorithm)
    console.log('⚠️  Storing card without validation');

    // VULNERABILITY: Logging sensitive card data
    console.log('🔍 Card Details:');
    console.log('  Card Number:', cardNumber);
    console.log('  CVV:', cvv);
    console.log('  Expiry:', expiryDate);

    // VULNERABILITY: Storing CVV (PCI-DSS violation)
    // VULNERABILITY: Storing full card number without encryption
    const result = await db.run(
      `INSERT INTO cards (user_id, card_number, card_holder, expiry_date, cvv, card_type, is_primary)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, cardNumber, cardHolder, expiryDate, cvv, cardType || 'UNKNOWN', isPrimary ? 1 : 0]
    );

    // Set other cards as non-primary if this is primary
    if (isPrimary) {
      await db.run(
        'UPDATE cards SET is_primary = 0 WHERE user_id = ? AND id != ?',
        [userId, result.id]
      );
    }

    const card = await db.get('SELECT * FROM cards WHERE id = ?', [result.id]);

    await logActivity(userId, 'CARD_ADDED', {
      cardNumber: cardNumber, // ⚠️ Logging full card number
      cardType
    }, req);

    res.status(201).json({
      success: true,
      message: 'Card added successfully',
      card: {
        id: card.id,
        card_number: card.card_number, // ⚠️ Returning full card number
        card_holder: card.card_holder,
        expiry_date: card.expiry_date,
        cvv: card.cvv, // ⚠️ Returning CVV
        card_type: card.card_type,
        is_primary: card.is_primary
      }
    });

  } catch (error) {
    console.error('❌ Add card error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add card',
      error: error.message
    });
  }
};

// VULNERABILITY: IDOR - Getting other users' cards
const getUserCards = async (req, res) => {
  try {
    // VULNERABILITY: userId from query can be manipulated
    const userId = req.query.userId || req.user.id;

    console.log(`⚠️  Fetching cards for user: ${userId}`);

    // VULNERABILITY: No authorization check
    const cards = await db.query(
      'SELECT * FROM cards WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC',
      [userId]
    );

    // VULNERABILITY: Returning all sensitive card data
    res.json({
      success: true,
      count: cards.length,
      cards: cards.map(card => ({
        id: card.id,
        card_number: card.card_number, // ⚠️ Full card number
        card_holder: card.card_holder,
        expiry_date: card.expiry_date,
        cvv: card.cvv, // ⚠️ CVV exposed
        card_type: card.card_type,
        is_primary: card.is_primary,
        created_at: card.created_at
      }))
    });

  } catch (error) {
    console.error('❌ Get cards error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch cards',
      error: error.message
    });
  }
};

// VULNERABILITY: No authorization for card details
const getCardById = async (req, res) => {
  try {
    const { cardId } = req.params;

    // VULNERABILITY: Anyone can view any card details
    const card = await db.get(
      'SELECT c.*, u.username, u.email FROM cards c JOIN users u ON c.user_id = u.id WHERE c.id = ?',
      [cardId]
    );

    if (!card) {
      return res.status(404).json({
        success: false,
        message: 'Card not found'
      });
    }

    res.json({
      success: true,
      card: {
        id: card.id,
        user_id: card.user_id,
        username: card.username,
        email: card.email,
        card_number: card.card_number, // ⚠️ Full card number
        card_holder: card.card_holder,
        expiry_date: card.expiry_date,
        cvv: card.cvv, // ⚠️ CVV exposed
        card_type: card.card_type,
        is_primary: card.is_primary,
        created_at: card.created_at
      }
    });

  } catch (error) {
    console.error('❌ Get card error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch card',
      error: error.message
    });
  }
};

// VULNERABILITY: Mass assignment in card update
const updateCard = async (req, res) => {
  try {
    const { cardId } = req.params;
    const updates = req.body;

    // VULNERABILITY: No ownership verification
    const card = await db.get('SELECT * FROM cards WHERE id = ?', [cardId]);

    if (!card) {
      return res.status(404).json({
        success: false,
        message: 'Card not found'
      });
    }

    // VULNERABILITY: User can update any field including user_id
    console.log('⚠️  Updating card with:', updates);

    const fields = Object.keys(updates);
    const values = Object.values(updates);

    if (fields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No fields to update'
      });
    }

    // VULNERABILITY: Dynamic SQL construction
    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const sql = `UPDATE cards SET ${setClause} WHERE id = ?`;

    await db.run(sql, [...values, cardId]);

    // Handle primary card
    if (updates.is_primary === 1 || updates.is_primary === true) {
      await db.run(
        'UPDATE cards SET is_primary = 0 WHERE user_id = ? AND id != ?',
        [card.user_id, cardId]
      );
    }

    const updatedCard = await db.get('SELECT * FROM cards WHERE id = ?', [cardId]);

    await logActivity(req.user.id, 'CARD_UPDATED', {
      cardId,
      updates
    }, req);

    res.json({
      success: true,
      message: 'Card updated successfully',
      card: updatedCard
    });

  } catch (error) {
    console.error('❌ Update card error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update card',
      error: error.message
    });
  }
};

// VULNERABILITY: No authorization for card deletion
const deleteCard = async (req, res) => {
  try {
    const { cardId } = req.params;

    // VULNERABILITY: Anyone can delete any card
    const card = await db.get('SELECT * FROM cards WHERE id = ?', [cardId]);

    if (!card) {
      return res.status(404).json({
        success: false,
        message: 'Card not found'
      });
    }

    await db.run('DELETE FROM cards WHERE id = ?', [cardId]);

    await logActivity(req.user.id, 'CARD_DELETED', {
      cardId,
      cardNumber: card.card_number // ⚠️ Logging card number
    }, req);

    res.json({
      success: true,
      message: 'Card deleted successfully',
      deletedCard: {
        id: card.id,
        card_number: card.card_number,
        card_type: card.card_type
      }
    });

  } catch (error) {
    console.error('❌ Delete card error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete card',
      error: error.message
    });
  }
};

// VULNERABILITY: No authorization - exposing all cards in system
const getAllCards = async (req, res) => {
  try {
    // VULNERABILITY: No admin check
    // VULNERABILITY: Exposing all cards with full details

    const cards = await db.query(
      `SELECT c.*, u.username, u.email, u.phone 
       FROM cards c 
       JOIN users u ON c.user_id = u.id 
       ORDER BY c.created_at DESC`
    );

    res.json({
      success: true,
      count: cards.length,
      cards: cards.map(card => ({
        id: card.id,
        user_id: card.user_id,
        username: card.username,
        email: card.email,
        phone: card.phone,
        card_number: card.card_number, // ⚠️ Full card numbers
        card_holder: card.card_holder,
        expiry_date: card.expiry_date,
        cvv: card.cvv, // ⚠️ All CVVs exposed
        card_type: card.card_type,
        is_primary: card.is_primary,
        created_at: card.created_at
      }))
    });

  } catch (error) {
    console.error('❌ Get all cards error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch cards',
      error: error.message
    });
  }
};

// VULNERABILITY: Card verification without proper validation
const verifyCard = async (req, res) => {
  try {
    const { cardNumber, cvv, expiryDate } = req.body;

    // VULNERABILITY: No rate limiting on card verification
    // VULNERABILITY: Allowing brute force attacks

    const card = await db.get(
      'SELECT c.*, u.* FROM cards c JOIN users u ON c.user_id = u.id WHERE c.card_number = ?',
      [cardNumber]
    );

    if (!card) {
      return res.status(404).json({
        success: false,
        message: 'Card not found',
        providedNumber: cardNumber // ⚠️ Echoing input
      });
    }

    // VULNERABILITY: Simple string comparison (timing attack)
    if (card.cvv !== cvv) {
      return res.status(401).json({
        success: false,
        message: 'Invalid CVV',
        correctCVV: card.cvv // ⚠️ Exposing correct CVV!
      });
    }

    if (card.expiry_date !== expiryDate) {
      return res.status(401).json({
        success: false,
        message: 'Invalid expiry date',
        correctExpiry: card.expiry_date // ⚠️ Exposing correct expiry
      });
    }

    await logActivity(card.user_id, 'CARD_VERIFIED', {
      cardNumber,
      cvv // ⚠️ Logging CVV
    }, req);

    res.json({
      success: true,
      message: 'Card verified successfully',
      card: {
        id: card.id,
        card_number: card.card_number,
        card_holder: card.card_holder,
        card_type: card.card_type,
        user: {
          id: card.user_id,
          username: card.username,
          email: card.email,
          balance: card.balance // ⚠️ Exposing user balance
        }
      }
    });

  } catch (error) {
    console.error('❌ Verify card error:', error);
    res.status(500).json({
      success: false,
      message: 'Card verification failed',
      error: error.message
    });
  }
};

// VULNERABILITY: No proper validation for card payment
const processCardPayment = async (req, res) => {
  try {
    const { cardId, amount, merchantId, description } = req.body;
    const userId = req.user.id;

    // VULNERABILITY: No amount validation
    const paymentAmount = parseFloat(amount);

    if (paymentAmount <= 0) {
      console.log('⚠️  Invalid payment amount:', paymentAmount);
    }

    const card = await db.get('SELECT * FROM cards WHERE id = ?', [cardId]);

    if (!card) {
      return res.status(404).json({
        success: false,
        message: 'Card not found'
      });
    }

    // VULNERABILITY: No ownership check
    console.log(`⚠️  Processing payment with card belonging to user ${card.user_id}`);

    // VULNERABILITY: No actual payment processing
    // Just simulate success

    const transactionId = 'PAY' + Date.now() + Math.random().toString(36).substr(2, 9);

    await db.run(
      `INSERT INTO transactions (transaction_id, sender_id, amount, type, status, description)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [transactionId, userId, paymentAmount, 'payment', 'completed', description]
    );

    await logActivity(userId, 'PAYMENT_PROCESSED', {
      cardId,
      cardNumber: card.card_number, // ⚠️ Logging card number
      amount: paymentAmount,
      merchantId
    }, req);

    res.json({
      success: true,
      message: 'Payment processed successfully',
      transaction: {
        id: transactionId,
        amount: paymentAmount,
        card_last_four: card.card_number.slice(-4),
        merchant_id: merchantId,
        status: 'completed'
      }
    });

  } catch (error) {
    console.error('❌ Process payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Payment processing failed',
      error: error.message
    });
  }
};

module.exports = {
  addCard,
  getUserCards,
  getCardById,
  updateCard,
  deleteCard,
  getAllCards,
  verifyCard,
  processCardPayment
};