const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { JWT, PASSWORD, OTP, LOGGING } = require('../config/constants');
const { logActivity } = require('../middleware/logger');

// VULNERABILITY: SQL Injection in login
const login = async (req, res) => {
  try {
    const { email, password, bypassAuth } = req.body;

    // VULNERABILITY: Debug bypass for authentication
    if (bypassAuth === 'vulnpay_debug_2024') {
      console.log('⚠️  DEBUG: Authentication bypassed!');
      
      const adminUser = await db.get(
        'SELECT * FROM users WHERE role = ? LIMIT 1',
        ['admin']
      );

      const token = jwt.sign(
        { userId: adminUser.id, role: adminUser.role },
        JWT.SECRET,
        { expiresIn: JWT.EXPIRES_IN }
      );

      return res.json({
        success: true,
        message: 'Debug login successful',
        token,
        user: adminUser
      });
    }

    // VULNERABILITY: SQL Injection possible here
    if (LOGGING.LOG_SENSITIVE_DATA) {
      console.log('🔍 Login attempt - Email:', email);
      console.log('🔍 Login attempt - Password:', password);
    }

    // VULNERABILITY: Using string concatenation for SQL (SQL Injection)
    let query;
    if (process.env.ALLOW_SQL_INJECTION === 'true') {
      // Intentionally vulnerable to SQL injection
      query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
      console.log('⚠️  Using vulnerable SQL query:', query);
      
      // This won't work as password is hashed, but demonstrates SQL injection
      const userDirect = await db.rawQuery(query);
      
      if (userDirect && userDirect.length > 0) {
        console.log('⚠️  SQL Injection successful!');
      }
    }

    // Normal authentication flow
    const user = await db.get(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (!user) {
      // VULNERABILITY: Revealing which field is wrong
      await logActivity(null, 'LOGIN_FAILED', { email, reason: 'User not found' }, req);
      return res.status(401).json({
        success: false,
        message: 'User not found with this email',
        providedEmail: email // ⚠️ Leaking input
      });
    }

    // VULNERABILITY: Weak password verification
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      // VULNERABILITY: Detailed error message
      await logActivity(user.id, 'LOGIN_FAILED', { email, reason: 'Invalid password' }, req);
      return res.status(401).json({
        success: false,
        message: 'Invalid password',
        hint: 'Password must match the one used during registration' // ⚠️ Too helpful
      });
    }

    // VULNERABILITY: No account lockout after multiple failed attempts
    // VULNERABILITY: No 2FA implementation

    // Generate token
    const token = jwt.sign(
      { 
        userId: user.id,
        email: user.email,
        role: user.role // VULNERABILITY: Role in JWT can be modified
      },
      JWT.SECRET,
      { expiresIn: JWT.EXPIRES_IN }
    );

    // VULNERABILITY: Storing session without proper validation
    await db.run(
      `INSERT INTO sessions (user_id, token, device_info, ip_address, expires_at)
       VALUES (?, ?, ?, ?, datetime('now', '+30 days'))`,
      [
        user.id,
        token,
        req.headers['user-agent'],
        req.ip || req.connection.remoteAddress
      ]
    );

    // VULNERABILITY: Logging sensitive data
    await logActivity(user.id, 'LOGIN_SUCCESS', {
      email: user.email,
      ip: req.ip,
      token: LOGGING.LOG_TOKENS ? token : '[REDACTED]'
    }, req);

    // VULNERABILITY: Returning sensitive user data
    const responseData = {
      id: user.id,
      email: user.email,
      username: user.username,
      full_name: user.full_name,
      phone: user.phone,
      balance: user.balance,
      account_number: user.account_number,
      pin: user.pin, // ⚠️ NEVER return PIN!
      role: user.role,
      is_active: user.is_active
    };

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: responseData
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: error.message, // ⚠️ Exposing error details
      stack: error.stack // ⚠️ Exposing stack trace
    });
  }
};

// VULNERABILITY: Weak registration validation
const register = async (req, res) => {
  try {
    const { email, username, password, full_name, phone, pin } = req.body;

    // VULNERABILITY: No input validation
    // VULNERABILITY: Weak password policy
    if (password && password.length < PASSWORD.MIN_LENGTH) {
      return res.status(400).json({
        success: false,
        message: `Password must be at least ${PASSWORD.MIN_LENGTH} characters`
      });
    }

    // VULNERABILITY: Logging passwords
    if (LOGGING.LOG_PASSWORDS) {
      console.log('🔍 Registration - Password:', password);
      console.log('🔍 Registration - PIN:', pin);
    }

    // Check if user exists
    const existingUser = await db.get(
      'SELECT * FROM users WHERE email = ? OR username = ?',
      [email, username]
    );

    if (existingUser) {
      // VULNERABILITY: Revealing which field is duplicate
      return res.status(400).json({
        success: false,
        message: existingUser.email === email 
          ? 'Email already registered' 
          : 'Username already taken',
        existingField: existingUser.email === email ? 'email' : 'username'
      });
    }

    // VULNERABILITY: Using low bcrypt rounds
    const hashedPassword = await bcrypt.hash(password, PASSWORD.BCRYPT_ROUNDS);

    // Generate account number
    const accountNumber = 'VPN' + Math.random().toString().substr(2, 7);

    // Insert user
    const result = await db.run(
      `INSERT INTO users (email, username, password, full_name, phone, account_number, pin, balance)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [email, username, hashedPassword, full_name, phone, accountNumber, pin || '0000', 1000.00]
    );

    // VULNERABILITY: Auto-login after registration (no email verification)
    const token = jwt.sign(
      { userId: result.id, email, role: 'user' },
      JWT.SECRET,
      { expiresIn: JWT.EXPIRES_IN }
    );

    await logActivity(result.id, 'REGISTER_SUCCESS', { email, username }, req);

    // Get created user
    const newUser = await db.get('SELECT * FROM users WHERE id = ?', [result.id]);

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
        full_name: newUser.full_name,
        account_number: newUser.account_number,
        balance: newUser.balance,
        pin: newUser.pin // ⚠️ NEVER return PIN!
      }
    });

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed',
      error: error.message
    });
  }
};

// VULNERABILITY: Weak OTP generation
const generateOTP = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // VULNERABILITY: Predictable OTP (Math.random instead of crypto)
    const otp = Math.floor(Math.random() * 10000).toString().padStart(OTP.LENGTH, '0');

    // VULNERABILITY: No rate limiting on OTP generation
    await db.run(
      `INSERT INTO otps (user_id, otp, purpose, expires_at)
       VALUES (?, ?, ?, datetime('now', '+${OTP.EXPIRES_IN} seconds'))`,
      [user.id, otp, 'password_reset']
    );

    // VULNERABILITY: Returning OTP in response (should be sent via SMS/Email)
    console.log(`📱 OTP Generated for ${email}: ${otp}`);

    await logActivity(user.id, 'OTP_GENERATED', { email, otp }, req);

    res.json({
      success: true,
      message: 'OTP generated successfully',
      otp: otp, // ⚠️ NEVER return OTP in response!
      expiresIn: OTP.EXPIRES_IN,
      email: email
    });

  } catch (error) {
    console.error('❌ OTP generation error:', error);
    res.status(500).json({
      success: false,
      message: 'OTP generation failed',
      error: error.message
    });
  }
};

// VULNERABILITY: Weak OTP verification
const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // VULNERABILITY: No rate limiting on OTP attempts
    const otpRecord = await db.get(
      `SELECT * FROM otps 
       WHERE user_id = ? AND otp = ? AND is_used = 0 
       AND expires_at > datetime('now')
       ORDER BY created_at DESC LIMIT 1`,
      [user.id, otp]
    );

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP',
        providedOTP: otp // ⚠️ Leaking input
      });
    }

    // Mark OTP as used
    await db.run('UPDATE otps SET is_used = 1 WHERE id = ?', [otpRecord.id]);

    // Generate reset token
    const resetToken = jwt.sign(
      { userId: user.id, purpose: 'password_reset' },
      JWT.SECRET,
      { expiresIn: '15m' }
    );

    await logActivity(user.id, 'OTP_VERIFIED', { email }, req);

    res.json({
      success: true,
      message: 'OTP verified successfully',
      resetToken
    });

  } catch (error) {
    console.error('❌ OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'OTP verification failed',
      error: error.message
    });
  }
};

// VULNERABILITY: No proper validation for password reset
const resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    // Verify reset token
    const decoded = jwt.verify(resetToken, JWT.SECRET);

    if (decoded.purpose !== 'password_reset') {
      return res.status(400).json({
        success: false,
        message: 'Invalid reset token'
      });
    }

    // VULNERABILITY: Weak new password validation
    const hashedPassword = await bcrypt.hash(newPassword, PASSWORD.BCRYPT_ROUNDS);

    await db.run(
      'UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [hashedPassword, decoded.userId]
    );

    await logActivity(decoded.userId, 'PASSWORD_RESET', {}, req);

    res.json({
      success: true,
      message: 'Password reset successful'
    });

  } catch (error) {
    console.error('❌ Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Password reset failed',
      error: error.message
    });
  }
};

module.exports = {
  login,
  register,
  generateOTP,
  verifyOTP,
  resetPassword
};