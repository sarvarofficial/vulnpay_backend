const bcrypt = require('bcrypt');
const db = require('../config/database');
const { PASSWORD } = require('../config/constants');
const { logActivity } = require('../middleware/logger');

// VULNERABILITY: IDOR - Any user can get any user's profile
const getUserProfile = async (req, res) => {
  try {
    // VULNERABILITY: userId from params can be manipulated
    const userId = req.params.userId || req.user.id;

    console.log(`⚠️  Fetching profile for user: ${userId}`);

    // VULNERABILITY: No authorization check
    const user = await db.get(
      'SELECT * FROM users WHERE id = ?',
      [userId]
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // VULNERABILITY: Returning sensitive data
    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        full_name: user.full_name,
        phone: user.phone,
        balance: user.balance,
        account_number: user.account_number,
        pin: user.pin, // ⚠️ Exposing PIN
        role: user.role,
        is_active: user.is_active,
        created_at: user.created_at,
        updated_at: user.updated_at
      }
    });

  } catch (error) {
    console.error('❌ Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile',
      error: error.message
    });
  }
};

// VULNERABILITY: Mass assignment in profile update
const updateUserProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    const updates = req.body; // ⚠️ Accepting all fields

    // VULNERABILITY: User can update any field including role, balance, etc.
    const allowedFields = ['email', 'username', 'full_name', 'phone', 'pin'];
    
    // But not enforcing it!
    console.log('⚠️  Updating user with data:', updates);

    const fields = Object.keys(updates);
    const values = Object.values(updates);

    if (fields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No fields to update'
      });
    }

    // VULNERABILITY: Dynamic SQL with user input
    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const sql = `UPDATE users SET ${setClause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;

    console.log('⚠️  Update SQL:', sql);

    await db.run(sql, [...values, userId]);

    // VULNERABILITY: User can escalate privileges
    if (updates.role) {
      console.log(`⚠️  Role changed to: ${updates.role}`);
    }

    if (updates.balance) {
      console.log(`⚠️  Balance changed to: ${updates.balance}`);
    }

    const updatedUser = await db.get('SELECT * FROM users WHERE id = ?', [userId]);

    await logActivity(userId, 'PROFILE_UPDATED', updates, req);

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        username: updatedUser.username,
        full_name: updatedUser.full_name,
        phone: updatedUser.phone,
        balance: updatedUser.balance,
        account_number: updatedUser.account_number,
        role: updatedUser.role
      }
    });

  } catch (error) {
    console.error('❌ Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile',
      error: error.message
    });
  }
};

// VULNERABILITY: No rate limiting on password change
const changePassword = async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;

    // VULNERABILITY: Weak validation
    if (!newPassword || newPassword.length < PASSWORD.MIN_LENGTH) {
      return res.status(400).json({
        success: false,
        message: `New password must be at least ${PASSWORD.MIN_LENGTH} characters`
      });
    }

    const user = await db.get('SELECT * FROM users WHERE id = ?', [userId]);

    // VULNERABILITY: Optional current password check
    if (currentPassword) {
      const isValid = await bcrypt.compare(currentPassword, user.password);
      
      if (!isValid) {
        return res.status(401).json({
          success: false,
          message: 'Current password is incorrect'
        });
      }
    } else {
      console.log('⚠️  Password changed without current password verification');
    }

    // VULNERABILITY: Using same weak bcrypt rounds
    const hashedPassword = await bcrypt.hash(newPassword, PASSWORD.BCRYPT_ROUNDS);

    await db.run(
      'UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [hashedPassword, userId]
    );

    // VULNERABILITY: Not invalidating existing sessions

    await logActivity(userId, 'PASSWORD_CHANGED', { 
      newPassword: newPassword // ⚠️ Logging new password
    }, req);

    res.json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.error('❌ Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password',
      error: error.message
    });
  }
};

// VULNERABILITY: No authorization - anyone can get user list
const getAllUsers = async (req, res) => {
  try {
    // VULNERABILITY: No admin check
    // VULNERABILITY: No pagination
    // VULNERABILITY: Returning all user data including sensitive info

    const users = await db.query(
      'SELECT * FROM users ORDER BY created_at DESC'
    );

    // VULNERABILITY: Exposing passwords (even if hashed), PINs, etc.
    res.json({
      success: true,
      count: users.length,
      users: users.map(user => ({
        id: user.id,
        email: user.email,
        username: user.username,
        full_name: user.full_name,
        phone: user.phone,
        balance: user.balance,
        account_number: user.account_number,
        pin: user.pin, // ⚠️ Exposing PINs
        role: user.role,
        is_active: user.is_active,
        password_hash: user.password, // ⚠️ Exposing password hashes
        created_at: user.created_at
      }))
    });

  } catch (error) {
    console.error('❌ Get all users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users',
      error: error.message
    });
  }
};

// VULNERABILITY: SQL Injection in user search
const searchUsers = async (req, res) => {
  try {
    const { query } = req.query;

    if (!query) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required'
      });
    }

    // VULNERABILITY: Direct string concatenation
    const sql = `SELECT * FROM users WHERE 
                 email LIKE '%${query}%' OR 
                 username LIKE '%${query}%' OR 
                 full_name LIKE '%${query}%' OR
                 phone LIKE '%${query}%' OR
                 account_number LIKE '%${query}%'`;

    console.log('⚠️  Vulnerable search SQL:', sql);

    const results = await db.rawQuery(sql);

    res.json({
      success: true,
      count: results.length,
      users: results,
      searchQuery: query
    });

  } catch (error) {
    console.error('❌ Search users error:', error);
    res.status(500).json({
      success: false,
      message: 'Search failed',
      error: error.message,
      query: req.query.query // ⚠️ Exposing query
    });
  }
};

// VULNERABILITY: No authorization for account deletion
const deleteUser = async (req, res) => {
  try {
    const { userId } = req.params;

    // VULNERABILITY: Any user can delete any account
    console.log(`⚠️  Deleting user: ${userId}`);

    const user = await db.get('SELECT * FROM users WHERE id = ?', [userId]);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // VULNERABILITY: No soft delete, permanent deletion
    // VULNERABILITY: Not deleting related data (cascade delete)
    await db.run('DELETE FROM users WHERE id = ?', [userId]);

    // Delete user's cards
    await db.run('DELETE FROM cards WHERE user_id = ?', [userId]);

    // Delete user's sessions
    await db.run('DELETE FROM sessions WHERE user_id = ?', [userId]);

    await logActivity(req.user.id, 'USER_DELETED', {
      deletedUserId: userId,
      deletedUserEmail: user.email
    }, req);

    res.json({
      success: true,
      message: 'User deleted successfully',
      deletedUser: {
        id: user.id,
        email: user.email,
        username: user.username
      }
    });

  } catch (error) {
    console.error('❌ Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete user',
      error: error.message
    });
  }
};

// VULNERABILITY: Exposing user balance without auth
const getUserBalance = async (req, res) => {
  try {
    const { userId } = req.params;

    // VULNERABILITY: Anyone can check anyone's balance
    const user = await db.get(
      'SELECT id, username, balance, account_number FROM users WHERE id = ? OR account_number = ?',
      [userId, userId]
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        account_number: user.account_number,
        balance: user.balance
      }
    });

  } catch (error) {
    console.error('❌ Get balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch balance',
      error: error.message
    });
  }
};

// VULNERABILITY: Manual balance adjustment without proper authorization
const adjustBalance = async (req, res) => {
  try {
    const { userId } = req.params;
    const { amount, operation } = req.body; // operation: 'add' or 'subtract'

    // VULNERABILITY: Anyone can adjust any user's balance
    console.log(`⚠️  Adjusting balance for user ${userId}: ${operation} ${amount}`);

    const user = await db.get('SELECT * FROM users WHERE id = ?', [userId]);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    let newBalance;
    if (operation === 'add') {
      newBalance = user.balance + parseFloat(amount);
    } else if (operation === 'subtract') {
      newBalance = user.balance - parseFloat(amount);
    } else {
      // VULNERABILITY: Default to add if invalid operation
      newBalance = user.balance + parseFloat(amount);
    }

    // VULNERABILITY: Allowing negative balance
    if (newBalance < 0) {
      console.log('⚠️  Negative balance allowed:', newBalance);
    }

    await db.run(
      'UPDATE users SET balance = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [newBalance, userId]
    );

    await logActivity(req.user.id, 'BALANCE_ADJUSTED', {
      userId,
      oldBalance: user.balance,
      newBalance,
      amount,
      operation
    }, req);

    res.json({
      success: true,
      message: 'Balance adjusted successfully',
      oldBalance: user.balance,
      newBalance: newBalance,
      adjustment: amount
    });

  } catch (error) {
    console.error('❌ Adjust balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to adjust balance',
      error: error.message
    });
  }
};

// VULNERABILITY: Exposing user sessions
const getUserSessions = async (req, res) => {
  try {
    const { userId } = req.params;

    // VULNERABILITY: No authorization check
    const sessions = await db.query(
      'SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    res.json({
      success: true,
      count: sessions.length,
      sessions: sessions.map(session => ({
        id: session.id,
        token: session.token, // ⚠️ Exposing active tokens
        device_info: session.device_info,
        ip_address: session.ip_address,
        expires_at: session.expires_at,
        created_at: session.created_at
      }))
    });

  } catch (error) {
    console.error('❌ Get sessions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch sessions',
      error: error.message
    });
  }
};

module.exports = {
  getUserProfile,
  updateUserProfile,
  changePassword,
  getAllUsers,
  searchUsers,
  deleteUser,
  getUserBalance,
  adjustBalance,
  getUserSessions
};