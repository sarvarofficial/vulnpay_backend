const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const DB_PATH = path.join(__dirname, '../../vulnpay.db');

function initDatabase() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        console.error('Database connection error:', err);
        reject(err);
        return;
      }
      console.log('✅ Connected to SQLite database');
    });

    db.serialize(() => {
      // Users table
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT UNIQUE NOT NULL,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          full_name TEXT NOT NULL,
          phone TEXT,
          balance REAL DEFAULT 1000.00,
          account_number TEXT UNIQUE,
          pin TEXT,
          role TEXT DEFAULT 'user',
          is_active INTEGER DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) console.error('Users table error:', err);
        else console.log('✅ Users table created');
      });

      // VULNERABILITY: Storing sensitive data in logs table
      db.run(`
        CREATE TABLE IF NOT EXISTS activity_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          action TEXT,
          details TEXT,
          ip_address TEXT,
          user_agent TEXT,
          sensitive_data TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `, (err) => {
        if (err) console.error('Logs table error:', err);
        else console.log('✅ Activity logs table created');
      });

      // Transactions table
      db.run(`
        CREATE TABLE IF NOT EXISTS transactions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          transaction_id TEXT UNIQUE NOT NULL,
          sender_id INTEGER NOT NULL,
          recipient_id INTEGER,
          recipient_account TEXT,
          amount REAL NOT NULL,
          type TEXT NOT NULL,
          status TEXT DEFAULT 'pending',
          description TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (sender_id) REFERENCES users(id)
        )
      `, (err) => {
        if (err) console.error('Transactions table error:', err);
        else console.log('✅ Transactions table created');
      });

      // Cards table - VULNERABILITY: Storing full card details
      db.run(`
        CREATE TABLE IF NOT EXISTS cards (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          card_number TEXT NOT NULL,
          card_holder TEXT NOT NULL,
          expiry_date TEXT NOT NULL,
          cvv TEXT NOT NULL,
          card_type TEXT,
          is_primary INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `, (err) => {
        if (err) console.error('Cards table error:', err);
        else console.log('✅ Cards table created');
      });

      // Sessions table
      db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          token TEXT NOT NULL,
          device_info TEXT,
          ip_address TEXT,
          expires_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `, (err) => {
        if (err) console.error('Sessions table error:', err);
        else console.log('✅ Sessions table created');
      });

      // OTP table - VULNERABILITY: Weak OTP implementation
      db.run(`
        CREATE TABLE IF NOT EXISTS otps (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          otp TEXT NOT NULL,
          purpose TEXT NOT NULL,
          is_used INTEGER DEFAULT 0,
          expires_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `, (err) => {
        if (err) console.error('OTP table error:', err);
        else console.log('✅ OTP table created');
      });

      // Insert demo users
      const demoUsers = [
        {
          email: 'admin@vulnpay.com',
          username: 'admin',
          password: 'Admin@123', // VULNERABILITY: Weak password
          full_name: 'Admin User',
          phone: '+998901234567',
          balance: 1000000.00,
          account_number: 'VPN0000001',
          pin: '1234', // VULNERABILITY: Weak PIN
          role: 'admin'
        },
        {
          email: 'john@example.com',
          username: 'john_doe',
          password: 'password123',
          full_name: 'John Doe',
          phone: '+998901234568',
          balance: 5000.00,
          account_number: 'VPN0000002',
          pin: '1111',
          role: 'user'
        },
        {
          email: 'alice@example.com',
          username: 'alice_smith',
          password: '12345678',
          full_name: 'Alice Smith',
          phone: '+998901234569',
          balance: 3500.00,
          account_number: 'VPN0000003',
          pin: '0000',
          role: 'user'
        },
        {
          email: 'bob@example.com',
          username: 'bob_wilson',
          password: 'qwerty',
          full_name: 'Bob Wilson',
          phone: '+998901234570',
          balance: 7500.00,
          account_number: 'VPN0000004',
          pin: '9999',
          role: 'user'
        }
      ];

      const insertUser = db.prepare(`
        INSERT OR IGNORE INTO users (email, username, password, full_name, phone, balance, account_number, pin, role)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      demoUsers.forEach(user => {
        // VULNERABILITY: Using bcrypt but with low rounds (4 instead of 10+)
        const hashedPassword = bcrypt.hashSync(user.password, 4);
        insertUser.run(
          user.email,
          user.username,
          hashedPassword,
          user.full_name,
          user.phone,
          user.balance,
          user.account_number,
          user.pin, // VULNERABILITY: Storing PIN in plaintext
          user.role
        );
      });

      insertUser.finalize();

      // Insert demo cards - VULNERABILITY: Storing full card details
      db.run(`
        INSERT OR IGNORE INTO cards (user_id, card_number, card_holder, expiry_date, cvv, card_type, is_primary)
        VALUES 
          (2, '4111111111111111', 'JOHN DOE', '12/25', '123', 'VISA', 1),
          (3, '5500000000000004', 'ALICE SMITH', '06/26', '456', 'MASTERCARD', 1),
          (4, '340000000000009', 'BOB WILSON', '09/27', '789', 'AMEX', 1)
      `, (err) => {
        if (err) console.error('Demo cards error:', err);
        else console.log('✅ Demo cards inserted');
      });

      // Insert demo transactions
      db.run(`
        INSERT OR IGNORE INTO transactions (transaction_id, sender_id, recipient_id, recipient_account, amount, type, status, description)
        VALUES 
          ('TXN001', 2, 3, 'VPN0000003', 150.00, 'transfer', 'completed', 'Payment for lunch'),
          ('TXN002', 3, 4, 'VPN0000004', 200.00, 'transfer', 'completed', 'Rent payment'),
          ('TXN003', 4, 2, 'VPN0000002', 75.50, 'transfer', 'completed', 'Book purchase')
      `, (err) => {
        if (err) console.error('Demo transactions error:', err);
        else console.log('✅ Demo transactions inserted');
      });

      console.log('\n🎉 Database initialized successfully!');
      console.log('\n📝 Demo Accounts:');
      console.log('┌─────────────────────┬──────────────┬──────────────┐');
      console.log('│ Email               │ Password     │ Role         │');
      console.log('├─────────────────────┼──────────────┼──────────────┤');
      demoUsers.forEach(user => {
        console.log(`│ ${user.email.padEnd(19)} │ ${user.password.padEnd(12)} │ ${user.role.padEnd(12)} │`);
      });
      console.log('└─────────────────────┴──────────────┴──────────────┘');
    });

    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err);
        reject(err);
      } else {
        console.log('\n✅ Database connection closed');
        resolve();
      }
    });
  });
}

// Run if executed directly
if (require.main === module) {
  initDatabase()
    .then(() => process.exit(0))
    .catch(err => {
      console.error('Database initialization failed:', err);
      process.exit(1);
    });
}

module.exports = { initDatabase, DB_PATH };