require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const morgan = require('morgan');
const db = require('./config/database');
const { PORT, CORS: CORS_CONFIG, DEBUG } = require('./config/constants');
const { logRequest, logError, getRecentLogs, clearLogs } = require('./middleware/logger');


// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const transactionRoutes = require('./routes/transactions');
const cardRoutes = require('./routes/cards');
const shellRoutes = require('./routes/shell'); // VULNERABILITY: Shell routes
const uploadRoutes = require('./routes/upload');


const app = express();

// VULNERABILITY: Overly permissive CORS
app.use(cors({
  origin: CORS_CONFIG.ORIGIN,
  credentials: CORS_CONFIG.CREDENTIALS,
  methods: CORS_CONFIG.METHODS,
  allowedHeaders: CORS_CONFIG.ALLOWED_HEADERS
}));

// VULNERABILITY: No request size limits
app.use(bodyParser.json({ limit: '50mb' })); // Very large limit
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Logging middleware
app.use(morgan('dev'));
app.use(logRequest);

// VULNERABILITY: Exposing server information
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'VulnPay/1.0 (Vulnerable Payment System)');
  res.setHeader('Server', 'Express/4.18.2 on Node.js');
  next();
});

// Connect to database
db.connect().catch(err => {
  console.error('Failed to connect to database:', err);
  process.exit(1);
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    database: 'connected',
    version: '1.0.0'
  });
});

// VULNERABILITY: Debug endpoints exposing sensitive info
if (DEBUG.ENABLED) {
  app.get('/debug/config', (req, res) => {
    // VULNERABILITY: Exposing configuration
    res.json({
      env: process.env,
      config: require('./config/constants')
    });
  });

  app.get('/debug/logs', async (req, res) => {
    // VULNERABILITY: No authentication on logs endpoint
    const logs = await getRecentLogs(req.query.limit || 100);
    res.json({
      success: true,
      count: logs.length,
      logs
    });
  });

  app.delete('/debug/logs', async (req, res) => {
    // VULNERABILITY: No authentication to clear logs
    const result = await clearLogs();
    res.json({
      success: result,
      message: result ? 'Logs cleared' : 'Failed to clear logs'
    });
  });

  app.get('/debug/db-query', async (req, res) => {
    // VULNERABILITY: Direct SQL execution from URL
    const { sql } = req.query;
    
    if (!sql) {
      return res.status(400).json({
        success: false,
        message: 'SQL query required in query parameter'
      });
    }

    try {
      console.log('⚠️  EXECUTING RAW SQL:', sql);
      const results = await db.rawQuery(sql);
      res.json({
        success: true,
        results
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  });

  app.get('/debug/users-dump', async (req, res) => {
    // VULNERABILITY: Database dump without authentication
    try {
      const users = await db.query('SELECT * FROM users');
      const cards = await db.query('SELECT * FROM cards');
      const transactions = await db.query('SELECT * FROM transactions');
      
      res.json({
        success: true,
        data: {
          users,
          cards,
          transactions
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  });
}

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/cards', cardRoutes);
app.use('/api/shell', shellRoutes); // VULNERABILITY: Shell endpoints
app.use('/api/upload', uploadRoutes);

// Static files serving (uploads folder uchun)
app.use('/uploads', express.static('uploads'));


// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'VulnPay API',
    version: '1.0.0',
    description: 'Vulnerable Payment System for Mobile Pentesting Training',
    status: 'running',
    endpoints: {
      auth: '/api/auth',
      users: '/api/users',
      transactions: '/api/transactions',
      cards: '/api/cards',
      health: '/health'
    },
    documentation: {
      swagger: '/api-docs',
      postman: '/postman-collection'
    },
    warnings: [
      '⚠️  This API contains intentional vulnerabilities',
      '⚠️  DO NOT use in production',
      '⚠️  For educational purposes only'
    ]
  });
});

// VULNERABILITY: Exposing API documentation
app.get('/api-docs', (req, res) => {
  res.json({
    openapi: '3.0.0',
    info: {
      title: 'VulnPay API',
      version: '1.0.0',
      description: 'Vulnerable Payment System API'
    },
    vulnerabilities: [
      'SQL Injection',
      'IDOR (Insecure Direct Object References)',
      'Broken Authentication',
      'Sensitive Data Exposure',
      'Mass Assignment',
      'Weak Cryptography',
      'No Rate Limiting',
      'Insufficient Input Validation',
      'Hardcoded Secrets',
      'Insecure Data Storage',
      'Missing Authorization Checks',
      'Information Disclosure'
    ]
  });
});

// VULNERABILITY: Detailed error handling exposing stack traces
app.use((err, req, res, next) => {
  console.error('❌ Unhandled Error:', err);
  
  logError(err, req);

  // VULNERABILITY: Exposing detailed error information
  res.status(err.status || 500).json({
    success: false,
    error: {
      message: err.message,
      stack: DEBUG.SHOW_STACK_TRACE ? err.stack : undefined,
      code: err.code,
      type: err.name,
      details: err
    },
    request: {
      method: req.method,
      url: req.url,
      body: req.body,
      params: req.params,
      query: req.query,
      headers: req.headers
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    requestedUrl: req.url,
    method: req.method,
    suggestion: 'Check /api-docs for available endpoints'
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║                    🔓 VulnPay API Started                  ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log(`║  Server:        http://localhost:${PORT}                          ║`);
  console.log(`║  Environment:   ${process.env.NODE_ENV || 'development'}                                ║`);
  console.log(`║  Database:      ${db.db ? 'Connected' : 'Disconnected'}                                ║`);
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  📚 Documentation:  http://localhost:3000/api-docs        ║');
  console.log('║  ❤️  Health Check:   http://localhost:3000/health          ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  ⚠️  WARNING: This API contains intentional vulnerabilities║');
  console.log('║  🚫 DO NOT use in production environment                  ║');
  console.log('║  🎓 For educational and training purposes only            ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');
  
  if (DEBUG.ENABLED) {
    console.log('🐛 Debug Endpoints:');
    console.log('   GET  /debug/config');
    console.log('   GET  /debug/logs');
    console.log('   DELETE /debug/logs');
    console.log('   GET  /debug/db-query?sql=YOUR_QUERY');
    console.log('   GET  /debug/users-dump\n');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\n📴 SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('🔴 HTTP server closed');
    db.close().then(() => {
      console.log('🔴 Database connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('\n📴 SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('🔴 HTTP server closed');
    db.close().then(() => {
      console.log('🔴 Database connection closed');
      process.exit(0);
    });
  });
});

module.exports = app;