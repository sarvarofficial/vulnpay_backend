const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../vulnpay.db');

class Database {
  constructor() {
    this.db = null;
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(DB_PATH, sqlite3.OPEN_READWRITE, (err) => {
        if (err) {
          console.error('❌ Database connection error:', err.message);
          reject(err);
        } else {
          console.log('✅ Connected to SQLite database');
          resolve(this.db);
        }
      });
    });
  }

  // VULNERABILITY: Direct query execution without parameterization
  query(sql, params = []) {
    return new Promise((resolve, reject) => {
      // VULNERABILITY: Logging queries with sensitive data
      if (process.env.DEBUG === 'true') {
        console.log('🔍 SQL Query:', sql);
        console.log('📊 Params:', params);
      }

      this.db.all(sql, params, (err, rows) => {
        if (err) {
          console.error('❌ Query error:', err.message);
          console.error('SQL:', sql);
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });
  }

  // VULNERABILITY: SQL Injection vulnerable method
  rawQuery(sql) {
    return new Promise((resolve, reject) => {
      console.log('⚠️  WARNING: Executing raw SQL query');
      console.log('SQL:', sql);
      
      this.db.all(sql, [], (err, rows) => {
        if (err) {
          console.error('❌ Raw query error:', err.message);
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });
  }

  run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) {
          console.error('❌ Run error:', err.message);
          reject(err);
        } else {
          resolve({ 
            id: this.lastID, 
            changes: this.changes 
          });
        }
      });
    });
  }

  get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) {
          console.error('❌ Get error:', err.message);
          reject(err);
        } else {
          resolve(row);
        }
      });
    });
  }

  close() {
    return new Promise((resolve, reject) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            reject(err);
          } else {
            console.log('Database connection closed');
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }
}

// Singleton instance
const dbInstance = new Database();

module.exports = dbInstance;