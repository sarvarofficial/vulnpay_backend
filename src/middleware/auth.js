const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { JWT, LOGGING } = require('../config/constants');

// VULNERABILITY: Weak JWT verification
const verifyToken = async (req, res, next) => {
  try {
    // VULNERABILITY: Multiple ways to send token (insecure)
    const token = 
      req.headers.authorization?.replace('Bearer ', '') ||
      req.headers['x-access-token'] ||
      req.query.token || // ⚠️ Token in URL is dangerous
      req.body.token ||
      req.cookies?.token;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    // VULNERABILITY: Logging tokens
    if (LOGGING.LOG_TOKENS) {
      console.log('🔑 Token:', token);
    }

    // VULNERABILITY: Using weak secret
    const decoded = jwt.verify(token, JWT.SECRET);

    // VULNERABILITY: Not checking token expiration properly
    // VULNERABILITY: Not checking if token is blacklisted
    
    // Get user from database
    const user = await db.get(
      'SELECT * FROM users WHERE id = ?',
      [decoded.userId]
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    // VULNERABILITY: Not checking if user is still active
    // if (!user.is_active) { ... }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role
    };

    // VULNERABILITY: Logging user data
    if (LOGGING.LOG_SENSITIVE_DATA) {
      console.log('👤 Authenticated User:', req.user);
    }

    next();
  } catch (error) {
    // VULNERABILITY: Exposing detailed error messages
    console.error('❌ Auth Error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token',
        error: error.message // ⚠️ Exposing error details
      });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired',
        expiredAt: error.expiredAt // ⚠️ Exposing token info
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Authentication failed',
      error: error.message
    });
  }
};

// VULNERABILITY: Weak role checking
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    // VULNERABILITY: Case-sensitive role check (can be bypassed)
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        requiredRole: roles, // ⚠️ Exposing required roles
        yourRole: req.user.role
      });
    }

    next();
  };
};

// VULNERABILITY: Optional authentication (always passes)
const optionalAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (token) {
      const decoded = jwt.verify(token, JWT.SECRET);
      const user = await db.get(
        'SELECT * FROM users WHERE id = ?',
        [decoded.userId]
      );
      
      if (user) {
        req.user = {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role
        };
      }
    }
    
    // VULNERABILITY: Always continues even without valid auth
    next();
  } catch (error) {
    // VULNERABILITY: Silently fails and continues
    console.log('Optional auth failed, continuing anyway');
    next();
  }
};

// VULNERABILITY: API Key authentication (weak implementation)
const verifyApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;

  // VULNERABILITY: Hardcoded API keys
  const validKeys = [
    'vulnpay_api_key_123',
    'test_key_456',
    'admin_key_789'
  ];

  if (!apiKey) {
    return res.status(401).json({
      success: false,
      message: 'API key required'
    });
  }

  // VULNERABILITY: Simple string comparison (timing attack vulnerable)
  if (validKeys.includes(apiKey)) {
    req.apiKeyValid = true;
    next();
  } else {
    return res.status(401).json({
      success: false,
      message: 'Invalid API key',
      providedKey: apiKey // ⚠️ Exposing provided key
    });
  }
};

// VULNERABILITY: No rate limiting implementation
const rateLimit = (req, res, next) => {
  // VULNERABILITY: Rate limiting disabled
  console.log('⚠️  Rate limiting is disabled');
  next();
};

// VULNERABILITY: CORS bypass helper
const bypassCORS = (req, res, next) => {
  // VULNERABILITY: Allow all origins
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
};

module.exports = {
  verifyToken,
  requireRole,
  optionalAuth,
  verifyApiKey,
  rateLimit,
  bypassCORS
};