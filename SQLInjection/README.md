# SQL Injection Demo Server

This is a basic Node.js server created for educational purposes to demonstrate SQL injection vulnerabilities.

## ⚠️ **WARNING**
This server contains **intentionally vulnerable** endpoints for educational purposes only. **DO NOT** use this code in production environments.

## Setup and Running

1. Navigate to the SQLInjection directory:
   ```bash
   cd SQLInjection
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the server:
   ```bash
   npm start
   ```

4. Open your browser and go to `http://localhost:3000`

## Available Endpoints

- **GET /** - Main page with information and login form
- **GET /users** - Vulnerable endpoint that demonstrates SQL injection in query parameters
  - Try: `http://localhost:3000/users?id=1 OR 1=1`
- **POST /login** - Vulnerable login endpoint
  - Try username: `admin' OR 1=1 --`

## Educational Purpose

This server is designed to help students understand:
- How SQL injection vulnerabilities occur
- The importance of input validation and parameterized queries
- Common attack patterns and payloads

## Security Note

In a real application, you should:
- Use parameterized queries/prepared statements
- Validate and sanitize all user input
- Use an ORM with built-in SQL injection protection
- Implement proper authentication and authorization