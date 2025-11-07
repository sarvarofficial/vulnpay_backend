const fs = require('fs');
const path = require('path');
const { LOGGING } = require('../config/constants');

const LOG_DIR = path.join(__dirname, '../../logs');

// Create logs directory if not exists
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

// VULNERABILITY: Logging sensitive data to files
const logRequest = (req, res, next) => {
  const timestamp = new Date().toISOString();
  const logData = {
    timestamp,
    method: req.method,
    url: req.url,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'],
    // VULNERABILITY: Logging request body (may contain passwords, etc.)
    body: LOGGING.LOG_SENSITIVE_DATA ? req.body : '[REDACTED]',
    // VULNERABILITY: Logging headers (may contain tokens)
    headers: LOGGING.LOG_TOKENS ? req.headers : '[REDACTED]',
    query: req.query
  };

  // Console log
  if (LOGGING.LOG_REQUESTS) {
    console.log('\n📥 Incoming Request:');
    console.log('──────────────────────────────────────');
    console.log(`Method: ${req.method}`);
    console.log(`URL: ${req.url}`);
    console.log(`IP: ${logData.ip}`);
    
    if (LOGGING.LOG_SENSITIVE_DATA) {
      console.log(`Body:`, JSON.stringify(req.body, null, 2));
    }
    
    if (LOGGING.LOG_TOKENS && req.headers.authorization) {
      console.log(`Authorization: ${req.headers.authorization}`);
    }
  }

  // VULNERABILITY: Writing sensitive logs to file
  const logFile = path.join(LOG_DIR, `requests-${new Date().toISOString().split('T')[0]}.log`);
  const logLine = JSON.stringify(logData) + '\n';
  
  fs.appendFile(logFile, logLine, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });

  // Log response
  const originalSend = res.send;
  res.send = function(data) {
    if (LOGGING.LOG_RESPONSES) {
      console.log('\n📤 Outgoing Response:');
      console.log('──────────────────────────────────────');
      console.log(`Status: ${res.statusCode}`);
      
      if (LOGGING.LOG_SENSITIVE_DATA) {
        try {
          const parsedData = typeof data === 'string' ? JSON.parse(data) : data;
          console.log('Data:', JSON.stringify(parsedData, null, 2));
        } catch (e) {
          console.log('Data:', data);
        }
      }
      console.log('──────────────────────────────────────\n');
    }

    // VULNERABILITY: Logging response data to file
    const responseLog = {
      timestamp: new Date().toISOString(),
      status: res.statusCode,
      data: LOGGING.LOG_SENSITIVE_DATA ? data : '[REDACTED]'
    };

    const responseFile = path.join(LOG_DIR, `responses-${new Date().toISOString().split('T')[0]}.log`);
    fs.appendFile(responseFile, JSON.stringify(responseLog) + '\n', () => {});

    originalSend.call(this, data);
  };

  next();
};

// VULNERABILITY: Activity logging with sensitive data
const logActivity = async (userId, action, details, req) => {
  const db = require('../config/database');
  
  const activityData = {
    user_id: userId,
    action: action,
    details: JSON.stringify(details),
    ip_address: req.ip || req.connection.remoteAddress,
    user_agent: req.headers['user-agent'],
    // VULNERABILITY: Storing passwords and tokens in logs
    sensitive_data: LOGGING.LOG_PASSWORDS ? JSON.stringify({
      body: req.body,
      headers: req.headers,
      query: req.query
    }) : null,
    timestamp: new Date().toISOString()
  };

  try {
    await db.run(
      `INSERT INTO activity_logs (user_id, action, details, ip_address, user_agent, sensitive_data, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        activityData.user_id,
        activityData.action,
        activityData.details,
        activityData.ip_address,
        activityData.user_agent,
        activityData.sensitive_data,
        activityData.timestamp
      ]
    );

    console.log(`✅ Activity logged: ${action} by user ${userId}`);
  } catch (error) {
    console.error('❌ Error logging activity:', error);
  }
};

// VULNERABILITY: Error logging with stack traces
const logError = (error, req) => {
  const errorData = {
    timestamp: new Date().toISOString(),
    error: error.message,
    stack: error.stack, // ⚠️ Exposing stack trace
    url: req.url,
    method: req.method,
    body: req.body,
    user: req.user || 'anonymous'
  };

  console.error('\n❌ Error Occurred:');
  console.error('──────────────────────────────────────');
  console.error('Message:', error.message);
  console.error('Stack:', error.stack);
  console.error('URL:', req.url);
  console.error('──────────────────────────────────────\n');

  // VULNERABILITY: Writing error details to file
  const errorFile = path.join(LOG_DIR, `errors-${new Date().toISOString().split('T')[0]}.log`);
  fs.appendFile(errorFile, JSON.stringify(errorData, null, 2) + '\n', () => {});
};

// VULNERABILITY: Debug endpoint to view logs
const getRecentLogs = async (limit = 100) => {
  const db = require('../config/database');
  
  try {
    // VULNERABILITY: No authentication required to view logs
    const logs = await db.query(
      `SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ?`,
      [limit]
    );

    return logs;
  } catch (error) {
    console.error('Error fetching logs:', error);
    return [];
  }
};

// VULNERABILITY: Clear logs endpoint (no authentication)
const clearLogs = async () => {
  const db = require('../config/database');
  
  try {
    await db.run('DELETE FROM activity_logs');
    console.log('✅ All activity logs cleared');
    return true;
  } catch (error) {
    console.error('❌ Error clearing logs:', error);
    return false;
  }
};

module.exports = {
  logRequest,
  logActivity,
  logError,
  getRecentLogs,
  clearLogs
};