const express = require('express');
const app = express();
const port = 3000;

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Basic route
app.get('/', (req, res) => {
  res.send(`
    <h1>SQL Injection Demo Server</h1>
    <p>This is a basic Node.js server for SQL injection testing.</p>
    <h2>Available endpoints:</h2>
    <ul>
      <li><strong>GET /</strong> - This page</li>
      <li><strong>GET /users</strong> - Get all users (vulnerable endpoint)</li>
      <li><strong>POST /login</strong> - Login endpoint (vulnerable)</li>
    </ul>
    <h3>Test the login endpoint:</h3>
    <form action="/login" method="post">
      <label for="username">Username:</label>
      <input type="text" id="username" name="username" required><br><br>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password" required><br><br>
      <input type="submit" value="Login">
    </form>
  `);
});

// Vulnerable endpoint for demonstration purposes
// In a real application, this would connect to a database
app.get('/users', (req, res) => {
  const userId = req.query.id;
  
  // This is intentionally vulnerable for educational purposes
  // In a real app, you would use parameterized queries
  const mockQuery = `SELECT * FROM users WHERE id = ${userId || 'all'}`;
  
  res.json({
    message: 'This endpoint is vulnerable to SQL injection',
    query: mockQuery,
    note: 'Try: /users?id=1 OR 1=1',
    mockUsers: [
      { id: 1, username: 'admin', email: 'admin@example.com' },
      { id: 2, username: 'user1', email: 'user1@example.com' },
      { id: 3, username: 'user2', email: 'user2@example.com' }
    ]
  });
});

// Vulnerable login endpoint for demonstration
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // This is intentionally vulnerable for educational purposes
  const mockQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  res.json({
    message: 'Login attempt processed',
    query: mockQuery,
    note: 'This is vulnerable to SQL injection. Try username: admin\' OR 1=1 --',
    submitted: { username, password }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Start the server
app.listen(port, () => {
  console.log(`SQL Injection demo server running at http://localhost:${port}`);
  console.log('This server contains intentionally vulnerable endpoints for educational purposes.');
});