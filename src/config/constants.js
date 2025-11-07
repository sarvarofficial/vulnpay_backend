// VULNERABILITY: Hardcoded secrets and configuration
// Real production da bu ma'lumotlar environment variables'dan olinishi kerak

module.exports = {
  // Server config
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',

  // VULNERABILITY: Weak JWT configuration
  JWT: {
    SECRET: 'vulnpay_jwt_secret_key_123', // Juda weak secret
    EXPIRES_IN: '30d', // Juda uzoq expiration
    ALGORITHM: 'HS256'
  },

  // VULNERABILITY: Hardcoded encryption keys
  ENCRYPTION: {
    ALGORITHM: 'aes-256-cbc',
    KEY: 'hardcoded_encryption_key_32bit', // 32 bytes
    IV_LENGTH: 16
  },

  // VULNERABILITY: Weak OTP configuration
  OTP: {
    LENGTH: 4, // Juda qisqa OTP
    EXPIRES_IN: 600, // 10 minutes
    MAX_ATTEMPTS: 10 // Ko'p attempts
  },

  // VULNERABILITY: Weak PIN configuration
  PIN: {
    LENGTH: 4,
    DEFAULT: '0000', // Default PIN
    MAX_ATTEMPTS: 100 // Ko'p attempts allowed
  },

  // Transaction limits - VULNERABILITY: Juda katta limitlar
  TRANSACTION: {
    MIN_AMOUNT: 0.01,
    MAX_AMOUNT: 1000000, // 1 million
    DAILY_LIMIT: 10000000, // 10 million
    MAX_TRANSACTIONS_PER_DAY: 1000
  },

  // VULNERABILITY: Weak password policy
  PASSWORD: {
    MIN_LENGTH: 6, // Juda qisqa
    REQUIRE_UPPERCASE: false,
    REQUIRE_LOWERCASE: false,
    REQUIRE_NUMBERS: false,
    REQUIRE_SPECIAL_CHARS: false,
    BCRYPT_ROUNDS: 4 // Juda past (10+ bo'lishi kerak)
  },

  // User roles
  ROLES: {
    ADMIN: 'admin',
    USER: 'user',
    MERCHANT: 'merchant'
  },

  // Transaction types
  TRANSACTION_TYPES: {
    TRANSFER: 'transfer',
    DEPOSIT: 'deposit',
    WITHDRAWAL: 'withdrawal',
    PAYMENT: 'payment',
    REFUND: 'refund'
  },

  // Transaction statuses
  TRANSACTION_STATUS: {
    PENDING: 'pending',
    COMPLETED: 'completed',
    FAILED: 'failed',
    CANCELLED: 'cancelled'
  },

  // Card types
  CARD_TYPES: {
    VISA: 'VISA',
    MASTERCARD: 'MASTERCARD',
    AMEX: 'AMEX',
    UZCARD: 'UZCARD',
    HUMO: 'HUMO'
  },

  // VULNERABILITY: Exposed API keys
  API_KEYS: {
    STRIPE: 'sk_test_51HxRt2SdHqPXYZ123456789',
    PAYMENT_GATEWAY: 'pg_secret_key_vulnerable_123',
    SMS_GATEWAY: 'sms_api_key_12345',
    EMAIL_SERVICE: 'email_service_key_67890'
  },

  // VULNERABILITY: Weak rate limiting
  RATE_LIMIT: {
    WINDOW_MS: 60000, // 1 minute
    MAX_REQUESTS: 1000, // Juda ko'p requests
    ENABLED: false // Disabled by default
  },

  // CORS configuration - VULNERABILITY: Allow all origins
  CORS: {
    ORIGIN: '*',
    CREDENTIALS: true,
    METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    ALLOWED_HEADERS: ['Content-Type', 'Authorization', 'X-API-Key']
  },

  // Logging - VULNERABILITY: Logging sensitive data
  LOGGING: {
    LEVEL: 'debug',
    LOG_REQUESTS: true,
    LOG_RESPONSES: true,
    LOG_SENSITIVE_DATA: true, // ⚠️ NEVER do this in production
    LOG_PASSWORDS: true, // ⚠️ Extremely dangerous
    LOG_TOKENS: true
  },

  // Response messages
  MESSAGES: {
    SUCCESS: {
      LOGIN: 'Login successful',
      REGISTER: 'Registration successful',
      LOGOUT: 'Logout successful',
      TRANSFER: 'Transfer completed successfully',
      UPDATE: 'Update successful'
    },
    ERROR: {
      INVALID_CREDENTIALS: 'Invalid email or password',
      USER_NOT_FOUND: 'User not found',
      INSUFFICIENT_BALANCE: 'Insufficient balance',
      UNAUTHORIZED: 'Unauthorized access',
      SERVER_ERROR: 'Internal server error',
      VALIDATION_ERROR: 'Validation error'
    }
  },

  // VULNERABILITY: Debug endpoints enabled
  DEBUG: {
    ENABLED: true,
    SHOW_STACK_TRACE: true,
    EXPOSE_ERRORS: true,
    ALLOW_SQL_INJECTION: true // For training purposes
  }
};