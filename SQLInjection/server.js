const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const port = 3000;

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize SQLite database
const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath);

// Initialize database with sample data
function initializeDatabase() {
  // Create users table
  db.serialize(() => {
    db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

    // Create products table
    db.run(`
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                description TEXT,
                stock INTEGER DEFAULT 0
            )
        `);

    // Create orders table
    db.run(`
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                product_id INTEGER,
                quantity INTEGER,
                total_price REAL,
                order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES products(id)
            )
        `);

    // Create sensitive_data table (for CIA demonstration)
    db.run(`
            CREATE TABLE IF NOT EXISTS sensitive_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                credit_card TEXT,
                ssn TEXT,
                secret_notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);

    // Insert sample users
    const users = [
      ['admin', 'admin123', 'admin@company.com', 'admin'],
      ['john_doe', 'password123', 'john@email.com', 'user'],
      ['jane_smith', 'secret456', 'jane@email.com', 'user'],
      ['bob_wilson', 'mypass789', 'bob@email.com', 'user'],
      ['alice_brown', 'qwerty', 'alice@email.com', 'user']
    ];

    const userStmt = db.prepare("INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)");
    users.forEach(user => userStmt.run(user));
    userStmt.finalize();

    // Insert sample products
    const products = [
      ['Laptop', 999.99, 'High-performance laptop', 10],
      ['Smartphone', 699.99, 'Latest smartphone model', 25],
      ['Tablet', 399.99, '10-inch tablet', 15],
      ['Headphones', 199.99, 'Wireless noise-cancelling headphones', 30],
      ['Mouse', 29.99, 'Optical wireless mouse', 50]
    ];

    const productStmt = db.prepare("INSERT OR IGNORE INTO products (name, price, description, stock) VALUES (?, ?, ?, ?)");
    products.forEach(product => productStmt.run(product));
    productStmt.finalize();

    // Insert sample sensitive data
    const sensitiveData = [
      [1, '1234-5678-9012-3456', '123-45-6789', 'Admin access codes: ABC123'],
      [2, '9876-5432-1098-7654', '987-65-4321', 'Personal loan approved'],
      [3, '1111-2222-3333-4444', '111-22-3333', 'VIP customer status'],
      [4, '5555-6666-7777-8888', '555-66-7777', 'Company secrets access'],
      [5, '9999-0000-1111-2222', '999-00-1111', 'Beta tester privileges']
    ];

    const sensitiveStmt = db.prepare("INSERT OR IGNORE INTO sensitive_data (user_id, credit_card, ssn, secret_notes) VALUES (?, ?, ?, ?)");
    sensitiveData.forEach(data => sensitiveStmt.run(data));
    sensitiveStmt.finalize();

    // Insert sample orders
    const orders = [
      [2, 1, 1, 999.99],
      [3, 2, 1, 699.99],
      [4, 3, 2, 799.98],
      [2, 4, 1, 199.99],
      [5, 5, 3, 89.97]
    ];

    const orderStmt = db.prepare("INSERT OR IGNORE INTO orders (user_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?)");
    orders.forEach(order => orderStmt.run(order));
    orderStmt.finalize();

    console.log('Database initialized with sample data');
  });
}

// Initialize database on startup
initializeDatabase();

// Basic route with attack examples
app.get('/', (req, res) => {
  res.send(`
    <h1>🔓 SQL Injection Vulnerability Demo</h1>
    <p><strong>⚠️ ATTENZIONE: Questo server è intenzionalmente vulnerabile per scopi educativi!</strong></p>
    
    <h2>🎯 Endpoint Vulnerabili:</h2>
    <ul>
      <li><strong>GET /users?id=X</strong> - Visualizza utenti (Vulnerabile a Tautologia)</li>
      <li><strong>POST /login</strong> - Login (Vulnerabile a Tautologia + Commenti)</li>
      <li><strong>GET /search?query=X</strong> - Ricerca prodotti (Vulnerabile a Union-based)</li>
      <li><strong>POST /update-profile</strong> - Aggiorna profilo (Vulnerabile a Piggybacked)</li>
      <li><strong>GET /info</strong> - Informazioni database</li>
    </ul>

    <h2>🔴 Esempi di Attacchi SQL Injection:</h2>
    
    <h3>1. Tautologia (Information Disclosure):</h3>
    <div style="display: flex; flex-direction: column; gap: 5px;">
    <code>GET /users?id=1 OR 1=1</code><br>
    <code>GET /users?id=1 UNION SELECT * FROM sqlite_master WHERE type='table'</code>
    </div>

    <h3>2. Commenti di fine riga (Authentication Bypass):</h3>
    <form action="/login" method="post">
      <input type="text" name="username" placeholder="Username (try: admin'--)" style="width: 200px;"><br><br>
      <input type="password" name="password" placeholder="Password (try: anything)" required style="width: 200px;"><br><br>
      <input type="submit" value="Login" style="background: #ff6b6b; color: white; padding: 8px;">
    </form>

    <h3>3. Query Piggybacked (Multiple Statements):</h3>
    <form action="/update-profile" method="post">
      <input type="text" name="username" value="test" placeholder="Username"><br><br>
      <textarea name="bio" placeholder="Bio (try: test'; DROP TABLE products; --)" style="width: 300px; height: 60px;"></textarea><br><br>
      <input type="submit" value="Update Profile" style="background: #ff6b6b; color: white; padding: 8px;">
    </form>

    <h3>4. Union-based (Data Exfiltration):</h3>
    <form action="/search" method="get">
      <input type="text" name="query" placeholder="Search (try: ' UNION SELECT credit_card,ssn,secret_notes,1,1 FROM sensitive_data --)" style="width: 400px;"><br><br>
      <input type="submit" value="Search Products" style="background: #ff6b6b; color: white; padding: 8px;">
    </form>
    
    <h2>🔍 Esplora la Struttura del Database:</h2>
    <p><code>GET /users?id=1 UNION SELECT name,sql,1,1,1,1 FROM sqlite_master WHERE type='table'</code></p>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
      code { background: #ffe6e6; padding: 4px; border-radius: 3px; }
      form { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
    </style>
  `);
});

// 🔴 VULNERABILITÀ 1: Tautologia - Information Disclosure
app.get('/users', (req, res) => {
  const userId = req.query.id;

  if (!userId) {
    return res.json({ error: 'ID parameter required', example: '/users?id=1' });
  }

  // ⚠️ VULNERABILE: Query concatenata direttamente - permette tautologie
  const query = `SELECT id, username, email, role, created_at FROM users WHERE id = ${userId}`;

  console.log(`🔍 Executing query: ${query}`);

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('❌ Database error:', err.message);
      return res.status(500).json({
        error: 'Database error',
        details: err.message,
        query: query,
        hint: 'Try: ?id=1 OR 1=1'
      });
    }

    res.json({
      success: true,
      query: query,
      results: rows,
      count: rows.length,
      vulnerability: "Tautologia - permette bypass WHERE clause"
    });
  });
});

// 🔴 VULNERABILITÀ 2: Commenti di fine riga - Authentication Bypass
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ error: 'Username and password required' });
  }

  // ⚠️ VULNERABILE: Query con stringhe concatenate - permette commenti SQL
  const query = `SELECT id, username, email, role FROM users WHERE username = '${username}' AND password = '${password}'`;

  console.log(`🔍 Executing query: ${query}`);

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('❌ Database error:', err.message);
      return res.status(500).json({
        error: 'Database error',
        details: err.message,
        query: query,
        hint: "Try username: admin'-- or admin' OR 1=1--"
      });
    }

    if (rows.length > 0) {
      res.json({
        success: true,
        message: 'Login successful!',
        user: rows[0],
        query: query,
        vulnerability: "Commenti SQL permettono bypass autenticazione"
      });
    } else {
      res.json({
        success: false,
        message: 'Invalid credentials',
        query: query,
        vulnerability: "Try: admin'-- to bypass password check"
      });
    }
  });
});

// 🔴 VULNERABILITÀ 3: Union-based - Data Exfiltration
app.get('/search', (req, res) => {
  const searchQuery = req.query.query;

  if (!searchQuery) {
    return res.json({ error: 'Query parameter required', example: '/search?query=laptop' });
  }

  // ⚠️ VULNERABILE: Permette UNION SELECT per esfiltrazione dati
  const query = `SELECT id, name, description, price, stock FROM products WHERE name LIKE '%${searchQuery}%'`;

  console.log(`🔍 Executing query: ${query}`);

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('❌ Database error:', err.message);
      return res.status(500).json({
        error: 'Database error',
        details: err.message,
        query: query,
        hint: "Try: ' UNION SELECT credit_card,ssn,secret_notes,1,1 FROM sensitive_data--"
      });
    }

    res.json({
      success: true,
      query: query,
      results: rows,
      count: rows.length,
      vulnerability: "Union-based injection per esfiltrazione dati"
    });
  });
});

// 🔴 VULNERABILITÀ 4: Piggybacked Queries - Data Modification/Destruction
app.post('/update-profile', (req, res) => {
  const { username, bio } = req.body;

  if (!username || !bio) {
    return res.json({ error: 'Username and bio required' });
  }

  // ⚠️ VULNERABILE: Permette multiple queries (piggybacked)
  const query = `UPDATE users SET email = '${bio}' WHERE username = '${username}'`;

  console.log(`🔍 Executing query: ${query}`);

  // Simula l'esecuzione di multiple queries (in SQLite3 usare exec per permettere multiple statements)
  db.exec(query, (err) => {
    if (err) {
      console.error('❌ Database error:', err.message);
      return res.status(500).json({
        error: 'Database error',
        details: err.message,
        query: query,
        hint: "Try bio: test'; DROP TABLE products; --"
      });
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      query: query,
      vulnerability: "Piggybacked queries permettono comandi multipli"
    });
  });
});

// 🔍 ENDPOINT per esplorare la struttura del database
app.get('/info', (req, res) => {
  const queries = [
    "SELECT name FROM sqlite_master WHERE type='table'",
    "SELECT sql FROM sqlite_master WHERE type='table'",
  ];

  const results = {};
  let completed = 0;

  queries.forEach((query, index) => {
    db.all(query, [], (err, rows) => {
      if (err) {
        results[`query_${index}`] = { error: err.message };
      } else {
        results[`query_${index}`] = { query, results: rows };
      }

      completed++;
      if (completed === queries.length) {
        res.json({
          message: 'Database structure information',
          data: results,
          hint: "Use this info to craft better injection attacks"
        });
      }
    });
  });
});

// 🛠️ ENDPOINT per dimostrare la compromissione CIA
app.get('/demonstrate-cia', (req, res) => {
  res.json({
    message: "Dimostrazione violazione proprietà CIA",
    examples: {
      confidentiality: {
        description: "Accesso non autorizzato a dati sensibili",
        attack: "GET /search?query=' UNION SELECT credit_card,ssn,secret_notes,1,1 FROM sensitive_data--",
        result: "Esfiltrazione di carte di credito e dati personali"
      },
      integrity: {
        description: "Modifica non autorizzata dei dati",
        attack: "POST /update-profile with bio: fake'; UPDATE users SET role='admin' WHERE username='john_doe'; --",
        result: "Escalation di privilegi modificando il ruolo utente"
      },
      availability: {
        description: "Compromissione dell'accesso al servizio",
        attack: "POST /update-profile with bio: fake'; DROP TABLE products; --",
        result: "Eliminazione di tabelle critiche del database"
      }
    },
    database_reconnaissance: {
      structure_discovery: "GET /users?id=1 UNION SELECT name,sql,1,1,1,1 FROM sqlite_master WHERE type='table'--",
      version_info: "GET /users?id=1 UNION SELECT sqlite_version(),1,1,1,1,1--",
      table_columns: "GET /users?id=1 UNION SELECT sql,1,1,1,1,1 FROM sqlite_master WHERE name='sensitive_data'--"
    }
  });
});

// 📊 ENDPOINT per visualizzare tutti i dati (per verificare modifiche)
app.get('/dump', (req, res) => {
  const tables = ['users', 'products', 'sensitive_data', 'orders'];
  const results = {};
  let completed = 0;

  tables.forEach(table => {
    db.all(`SELECT * FROM ${table}`, [], (err, rows) => {
      if (err) {
        results[table] = { error: err.message };
      } else {
        results[table] = rows;
      }

      completed++;
      if (completed === tables.length) {
        res.json({
          message: 'Database dump - verifica lo stato del database dopo gli attacchi',
          data: results,
          warning: "⚠️ In produzione questo endpoint espone dati sensibili!"
        });
      }
    });
  });
});

// 🔧 ENDPOINT per reset del database
app.post('/reset-db', (req, res) => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    }

    // Delete the database file and recreate it
    const fs = require('fs');
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }

    // Recreate database
    const newDb = new sqlite3.Database(dbPath);

    // Reinitialize
    db = newDb;  // This is not ideal, but works for demo
    setTimeout(() => {
      initializeDatabase();
      res.json({
        success: true,
        message: 'Database reset successfully',
        warning: 'Tutte le modifiche degli attacchi sono state ripristinate'
      });
    }, 1000);
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('💥 Server error:', err.stack);
  res.status(500).json({
    error: 'Internal server error',
    details: err.message,
    note: 'This might be caused by SQL injection attacks'
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('✅ Database connection closed.');
    }
    process.exit(0);
  });
});

// Start the server
app.listen(port, () => {
  console.log('\n🔓 ==========================================');
  console.log('   SQL INJECTION VULNERABILITY DEMO');
  console.log('🔓 ==========================================');
  console.log(`🌐 Server running at http://localhost:${port}`);
  console.log('⚠️  WARNING: This server is INTENTIONALLY VULNERABLE!');
  console.log('📚 For educational purposes only');
  console.log('🎯 Available attack vectors:');
  console.log('   • Tautology attacks');
  console.log('   • Comment-based bypass');
  console.log('   • Union-based data exfiltration');
  console.log('   • Piggybacked queries');
  console.log('💀 Database file: database.db');
  console.log('🔓 ==========================================\n');
});