const db = require('../config/database');
const { TRANSACTION, TRANSACTION_TYPES, TRANSACTION_STATUS } = require('../config/constants');
const { logActivity } = require('../middleware/logger');
const { v4: uuidv4 } = require('uuid');

// VULNERABILITY: IDOR - Insecure Direct Object Reference
const getTransactions = async (req, res) => {
  try {
    // VULNERABILITY: userId from query parameter (can be manipulated)
    const userId = req.query.userId || req.user.id;

    console.log(`⚠️  Fetching transactions for user: ${userId}`);

    // VULNERABILITY: No authorization check if userId is different from req.user.id
    const transactions = await db.query(
      `SELECT t.*, 
              sender.username as sender_username,
              sender.account_number as sender_account,
              recipient.username as recipient_username
       FROM transactions t
       LEFT JOIN users sender ON t.sender_id = sender.id
       LEFT JOIN users recipient ON t.recipient_id = recipient.id
       WHERE t.sender_id = ? OR t.recipient_id = ?
       ORDER BY t.created_at DESC`,
      [userId, userId]
    );

    res.json({
      success: true,
      count: transactions.length,
      transactions
    });

  } catch (error) {
    console.error('❌ Get transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch transactions',
      error: error.message
    });
  }
};

// VULNERABILITY: Race condition in money transfer
const createTransfer = async (req, res) => {
  try {
    const { recipientAccount, amount, description, pin } = req.body;
    const senderId = req.user.id;

    // VULNERABILITY: No input validation
    if (!recipientAccount || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Recipient account and amount are required'
      });
    }

    // VULNERABILITY: Accepting negative amounts
    const transferAmount = parseFloat(amount);
    
    if (transferAmount <= 0) {
      console.log('⚠️  Negative or zero amount detected:', transferAmount);
      // But still allowing it for demonstration
    }

    // VULNERABILITY: No maximum amount check
    if (transferAmount > TRANSACTION.MAX_AMOUNT) {
      console.log(`⚠️  Large transfer detected: ${transferAmount}`);
    }

    // Get sender
    const sender = await db.get('SELECT * FROM users WHERE id = ?', [senderId]);

    // VULNERABILITY: Weak PIN verification (optional)
    if (pin) {
      if (pin !== sender.pin) {
        return res.status(401).json({
          success: false,
          message: 'Invalid PIN',
          correctPin: sender.pin // ⚠️ Exposing correct PIN!
        });
      }
    } else {
      console.log('⚠️  Transfer without PIN verification');
    }

    // Get recipient
    const recipient = await db.get(
      'SELECT * FROM users WHERE account_number = ?',
      [recipientAccount]
    );

    if (!recipient) {
      return res.status(404).json({
        success: false,
        message: 'Recipient account not found',
        searchedAccount: recipientAccount
      });
    }

    // VULNERABILITY: No self-transfer check
    if (sender.id === recipient.id) {
      console.log('⚠️  Self-transfer detected');
    }

    // VULNERABILITY: Race condition - balance check and update not atomic
    if (sender.balance < transferAmount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance',
        yourBalance: sender.balance,
        requiredAmount: transferAmount,
        shortfall: transferAmount - sender.balance
      });
    }

    // VULNERABILITY: No transaction locking
    // Multiple requests can pass the balance check simultaneously

    const transactionId = 'TXN' + Date.now() + Math.random().toString(36).substr(2, 9);

    // Create transaction record
    await db.run(
      `INSERT INTO transactions (transaction_id, sender_id, recipient_id, recipient_account, amount, type, status, description)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        transactionId,
        sender.id,
        recipient.id,
        recipient.account_number,
        transferAmount,
        TRANSACTION_TYPES.TRANSFER,
        TRANSACTION_STATUS.PENDING,
        description || 'Money transfer'
      ]
    );

    // VULNERABILITY: No rollback mechanism if any step fails
    // Update sender balance
    await db.run(
      'UPDATE users SET balance = balance - ? WHERE id = ?',
      [transferAmount, sender.id]
    );

    // Update recipient balance  
    await db.run(
      'UPDATE users SET balance = balance + ? WHERE id = ?',
      [transferAmount, recipient.id]
    );

    // Update transaction status
    await db.run(
      'UPDATE transactions SET status = ? WHERE transaction_id = ?',
      [TRANSACTION_STATUS.COMPLETED, transactionId]
    );

    // Get updated transaction
    const transaction = await db.get(
      'SELECT * FROM transactions WHERE transaction_id = ?',
      [transactionId]
    );

    // Get updated balances
    const updatedSender = await db.get('SELECT balance FROM users WHERE id = ?', [sender.id]);
    const updatedRecipient = await db.get('SELECT balance FROM users WHERE id = ?', [recipient.id]);

    await logActivity(sender.id, 'TRANSFER_CREATED', {
      transactionId,
      amount: transferAmount,
      recipient: recipient.account_number
    }, req);

    res.json({
      success: true,
      message: 'Transfer completed successfully',
      transaction,
      senderBalance: updatedSender.balance,
      recipientBalance: updatedRecipient.balance // ⚠️ Exposing recipient balance
    });

  } catch (error) {
    console.error('❌ Transfer error:', error);
    res.status(500).json({
      success: false,
      message: 'Transfer failed',
      error: error.message,
      stack: error.stack
    });
  }
};

// VULNERABILITY: SQL Injection in transaction search
const searchTransactions = async (req, res) => {
  try {
    const { query, startDate, endDate, minAmount, maxAmount } = req.query;
    const userId = req.user.id;

    // VULNERABILITY: Using string concatenation for SQL
    let sql = `SELECT t.*, 
               sender.username as sender_username,
               recipient.username as recipient_username
               FROM transactions t
               LEFT JOIN users sender ON t.sender_id = sender.id
               LEFT JOIN users recipient ON t.recipient_id = recipient.id
               WHERE (t.sender_id = ${userId} OR t.recipient_id = ${userId})`;

    // VULNERABILITY: Direct injection of user input
    if (query) {
      sql += ` AND (t.description LIKE '%${query}%' OR t.transaction_id LIKE '%${query}%')`;
    }

    if (startDate) {
      sql += ` AND t.created_at >= '${startDate}'`;
    }

    if (endDate) {
      sql += ` AND t.created_at <= '${endDate}'`;
    }

    if (minAmount) {
      sql += ` AND t.amount >= ${minAmount}`;
    }

    if (maxAmount) {
      sql += ` AND t.amount <= ${maxAmount}`;
    }

    sql += ' ORDER BY t.created_at DESC';

    console.log('⚠️  Vulnerable SQL Query:', sql);

    const results = await db.rawQuery(sql);

    res.json({
      success: true,
      count: results.length,
      transactions: results,
      query: {
        search: query,
        startDate,
        endDate,
        minAmount,
        maxAmount
      }
    });

  } catch (error) {
    console.error('❌ Search error:', error);
    res.status(500).json({
      success: false,
      message: 'Search failed',
      error: error.message,
      query: req.query // ⚠️ Exposing query parameters
    });
  }
};

// VULNERABILITY: No authorization check for transaction details
const getTransactionById = async (req, res) => {
  try {
    const { transactionId } = req.params;

    // VULNERABILITY: Anyone can view any transaction
    const transaction = await db.get(
      `SELECT t.*, 
              sender.username as sender_username,
              sender.email as sender_email,
              sender.phone as sender_phone,
              sender.balance as sender_balance,
              recipient.username as recipient_username,
              recipient.email as recipient_email,
              recipient.phone as recipient_phone,
              recipient.balance as recipient_balance
       FROM transactions t
       LEFT JOIN users sender ON t.sender_id = sender.id
       LEFT JOIN users recipient ON t.recipient_id = recipient.id
       WHERE t.transaction_id = ? OR t.id = ?`,
      [transactionId, transactionId]
    );

    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }

    // VULNERABILITY: No check if req.user is involved in this transaction
    // Anyone with transaction ID can view full details

    res.json({
      success: true,
      transaction
    });

  } catch (error) {
    console.error('❌ Get transaction error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch transaction',
      error: error.message
    });
  }
};

// VULNERABILITY: Mass assignment in transaction update
const updateTransaction = async (req, res) => {
  try {
    const { transactionId } = req.params;
    const updates = req.body; // ⚠️ Accepting all fields from request

    // VULNERABILITY: No validation of what can be updated
    // User can change amount, status, sender_id, etc.

    const fields = Object.keys(updates);
    const values = Object.values(updates);

    if (fields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No fields to update'
      });
    }

    // VULNERABILITY: Building dynamic SQL without proper validation
    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const sql = `UPDATE transactions SET ${setClause} WHERE transaction_id = ?`;

    console.log('⚠️  Dynamic update SQL:', sql);
    console.log('⚠️  Values:', values);

    await db.run(sql, [...values, transactionId]);

    const updated = await db.get(
      'SELECT * FROM transactions WHERE transaction_id = ?',
      [transactionId]
    );

    await logActivity(req.user.id, 'TRANSACTION_UPDATED', {
      transactionId,
      updates
    }, req);

    res.json({
      success: true,
      message: 'Transaction updated successfully',
      transaction: updated
    });

  } catch (error) {
    console.error('❌ Update transaction error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update transaction',
      error: error.message
    });
  }
};

// VULNERABILITY: No proper authorization for cancellation
const cancelTransaction = async (req, res) => {
  try {
    const { transactionId } = req.params;

    const transaction = await db.get(
      'SELECT * FROM transactions WHERE transaction_id = ?',
      [transactionId]
    );

    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }

    // VULNERABILITY: Anyone can cancel any transaction
    // No check if req.user.id === transaction.sender_id

    if (transaction.status === TRANSACTION_STATUS.COMPLETED) {
      console.log('⚠️  Attempting to cancel completed transaction');
      
      // VULNERABILITY: Allowing cancellation of completed transactions
      // No proper refund mechanism
    }

    await db.run(
      'UPDATE transactions SET status = ? WHERE transaction_id = ?',
      [TRANSACTION_STATUS.CANCELLED, transactionId]
    );

    // VULNERABILITY: Not reversing the money transfer

    await logActivity(req.user.id, 'TRANSACTION_CANCELLED', {
      transactionId
    }, req);

    res.json({
      success: true,
      message: 'Transaction cancelled successfully'
    });

  } catch (error) {
    console.error('❌ Cancel transaction error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to cancel transaction',
      error: error.message
    });
  }
};

// VULNERABILITY: Exposing all transactions without pagination
const getAllTransactions = async (req, res) => {
  try {
    // VULNERABILITY: No admin check
    // VULNERABILITY: No pagination (can return millions of records)
    
    const transactions = await db.query(
      `SELECT t.*, 
              sender.username as sender_username,
              sender.email as sender_email,
              recipient.username as recipient_username,
              recipient.email as recipient_email
       FROM transactions t
       LEFT JOIN users sender ON t.sender_id = sender.id
       LEFT JOIN users recipient ON t.recipient_id = recipient.id
       ORDER BY t.created_at DESC`
    );

    res.json({
      success: true,
      count: transactions.length,
      transactions
    });

  } catch (error) {
    console.error('❌ Get all transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch transactions',
      error: error.message
    });
  }
};

module.exports = {
  getTransactions,
  createTransfer,
  searchTransactions,
  getTransactionById,
  updateTransaction,
  cancelTransaction,
  getAllTransactions
};