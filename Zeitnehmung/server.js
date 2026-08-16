/* ALPIN TIMING — Server (Benutzerkonten, keine PIN)
 *
 * Ein Konto = ein Rennen ("Raum"). Wer mit dem Konto angemeldet ist (Token),
 * darf den Zustand senden (Master = Ziel) und Start-Ereignisse senden (Startstation).
 * Zuschauer öffnen den öffentlichen Raum ohne Anmeldung.
 *
 * Start:  npm install  →  npm start
 * Optional: AUTH_SECRET=… (sonst wird ein Geheimnis erzeugt & in data/secret gespeichert)
 */
const http = require('http');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
/* Datenordner: per Umgebungsvariable DATA_DIR auf eine DAUERHAFTE Festplatte legen
   (z.B. Render Persistent Disk, gemountet auf /data -> DATA_DIR=/data). Sonst lokal,
   was auf Gratis-Tarifen bei Redeploy verloren gehen kann. */
const DATA = process.env.DATA_DIR || path.join(ROOT, 'data');
try { fs.mkdirSync(DATA, { recursive: true }); } catch (e) {}
/* Schreib-Selbsttest: schlaegt Persistenz fehl (z.B. DATA_DIR nicht gemountet),
   dann LAUT warnen statt Registrierungen/Lizenzen still zu verlieren. */
try { const _t = path.join(DATA, '.writetest'); fs.writeFileSync(_t, 'ok'); fs.unlinkSync(_t); }
catch (e) { console.error('!! WARNUNG: Datenordner NICHT schreibbar (' + DATA + '): ' + e.message + ' -> Konten/Lizenzen ueberleben keinen Neustart! DATA_DIR pruefen.'); }

/* Globale Absturz-Sicherung: ein einzelner kaputter Request oder ein abrupt
   getrennter Client darf NIE den ganzen Server (und damit alle Live-Clients) killen. */
process.on('uncaughtException', e => console.error('uncaughtException:', e && e.stack || e));
process.on('unhandledRejection', e => console.error('unhandledRejection:', e && e.stack || e));

/* Atomar schreiben: erst in temp, dann umbenennen -> nie halbe/kaputte Datei bei Absturz */
function writeAtomic(file, content) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, file);
}

/* --- Geheimnis (für Token-Signatur), überlebt Neustart --- */
const SECRET_FILE = path.join(DATA, 'secret');
let SECRET = process.env.AUTH_SECRET || '';
if (!SECRET) { try { SECRET = fs.readFileSync(SECRET_FILE, 'utf8'); } catch (e) {} }
if (!SECRET) { SECRET = crypto.randomBytes(32).toString('hex'); try { writeAtomic(SECRET_FILE, SECRET); } catch (e) {} }

/* --- Benutzer-Speicher --- */
const USERS_FILE = path.join(DATA, 'users.json');
let users = {};
try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) {}
function saveUsers() { try { writeAtomic(USERS_FILE, JSON.stringify(users)); } catch (e) {} }

/* --- App-Version aus der ausgelieferten HTML lesen (für Update-Hinweis) --- */
let _ver = '', _verMtime = -1;
function appVersion() {
  try { const f = path.join(ROOT, 'alpin-timing.html'); const st = fs.statSync(f);
    if (st.mtimeMs !== _verMtime) { _verMtime = st.mtimeMs; const m = fs.readFileSync(f, 'utf8').match(/const VERSION="([^"]+)"/); _ver = m ? m[1] : ''; }
  } catch (e) {}
  return _ver;
}

/* --- Passwort-Hashing (scrypt) & Token (HMAC) --- */
function hashPw(pw) { const salt = crypto.randomBytes(16); const h = crypto.scryptSync(pw, salt, 64); return salt.toString('hex') + ':' + h.toString('hex'); }
function verifyPw(pw, stored) {
  try { const [s, h] = stored.split(':'); const calc = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64);
    return crypto.timingSafeEqual(calc, Buffer.from(h, 'hex')); } catch (e) { return false; }
}
function b64u(s) { return Buffer.from(s).toString('base64url'); }
function signToken(user, days = 365) {
  const p = b64u(JSON.stringify({ u: user, exp: Date.now() + days * 86400000 }));
  const sig = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  return p + '.' + sig;
}
function verifyToken(token) {
  if (!token || token.indexOf('.') < 0) return null;
  const [p, sig] = token.split('.');
  const exp = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  try { if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return null; } catch (e) { return null; }
  let d; try { d = JSON.parse(Buffer.from(p, 'base64url').toString()); } catch (e) { return null; }
  if (!d.exp || d.exp < Date.now()) return null;
  return d.u;
}
function normUser(u) { return String(u || '').trim().toLowerCase(); }
function validUser(u) { return /^[a-z0-9_-]{3,24}$/.test(u); }

/* --- Lizenz: Konto hat optional ein Ablaufdatum (licenseExp). Ohne gueltige Lizenz
   kann das Konto kein Live-Rennen SENDEN (Master); Zuschauen bleibt frei.
   Inhaber-Konten (Env OWNER_USERS, kommagetrennt) sind IMMER voll lizenziert. --- */
const OWNERS = (process.env.OWNER_USERS || 'nico_war').split(',').map(s => normUser(s)).filter(Boolean);
function licenseInfo(u) {
  if (OWNERS.includes(u) || (users[u] && users[u].owner)) return { licensed: true, exp: null, owner: true };
  const x = users[u]; const exp = (x && x.licenseExp) || null;
  return { licensed: !!(exp && exp > Date.now()), exp: exp, owner: false };
}
/* Inhaber automatisch festlegen: das AELTESTE Konto bekommt dauerhaft die Vollversion,
   falls noch keiner markiert ist und keine OWNER_USERS-Env gesetzt wurde. So hat der
   Betreiber (= wer zuerst registriert hat) immer die volle Lizenz, ganz ohne Einrichtung. */
function ensureOwner() {
  if (OWNERS.length) return;
  const names = Object.keys(users);
  if (!names.length || names.some(u => users[u].owner)) return;
  let first = names[0];
  for (const u of names) if ((users[u].created || 0) < (users[first].created || 0)) first = u;
  users[first].owner = true; saveUsers();
  console.log('Inhaber automatisch festgelegt (Vollversion, dauerhaft): ' + first);
}
ensureOwner();

/* --- Kontakt/Support: Kunden-Nachrichten per E-Mail (SMTP) + Datei-Backup ---
   Env: SMTP_USER, SMTP_PASS (z.B. GMX), optional SMTP_HOST/SMTP_PORT, CONTACT_TO. */
const CONTACT_TO = process.env.CONTACT_TO || process.env.SMTP_USER || '';
const SMTP = { host: process.env.SMTP_HOST || 'mail.gmx.net', port: parseInt(process.env.SMTP_PORT || '587'),
  user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' };
let _mailer = null;
function mailer() {
  if (_mailer) return _mailer;
  if (!SMTP.user || !SMTP.pass) return null;
  try { const nm = require('nodemailer'); _mailer = nm.createTransport({ host: SMTP.host, port: SMTP.port, secure: SMTP.port === 465, auth: { user: SMTP.user, pass: SMTP.pass } }); } catch (e) { _mailer = null; }
  return _mailer;
}
const _contactHits = {};   // einfache Ratenbegrenzung pro IP

/* --- HTTP: statische Dateien + Auth-API --- */
const MIME = { '.html':'text/html; charset=utf-8', '.js':'text/javascript', '.css':'text/css', '.json':'application/json',
  '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif', '.svg':'image/svg+xml', '.ico':'image/x-icon',
  '.woff2':'font/woff2', '.woff':'font/woff', '.ttf':'font/ttf', '.map':'application/json', '.txt':'text/plain; charset=utf-8',
  '.webmanifest':'application/manifest+json', '.wasm':'application/wasm' };
function readBody(req) { return new Promise(resolve => { let b = ''; let done = false; const fin = () => { if (!done) { done = true; resolve(b); } };
  req.on('data', c => { b += c; if (b.length > 1e5) { b = b.slice(0, 1e5); req.destroy(); fin(); } });
  req.on('end', fin); req.on('close', fin); req.on('error', fin); }); }
function json(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

const server = http.createServer(async (req, res) => {
  let url;
  try { url = decodeURIComponent((req.url || '/').split('?')[0]); }
  catch (e) { res.writeHead(400); return res.end('bad request'); }   // kaputtes %-Encoding darf den Server nicht killen

  /* --- Optionale Zugangssperre für die ganze Seite ---
   * Nur aktiv, wenn die Umgebungsvariable ACCESS_CODE gesetzt ist (z.B. auf Render).
   * Solange du allein testest: Code setzen -> niemand sonst kann App/Links öffnen.
   * Zum Freischalten der Seite einfach die Variable wieder entfernen.
   * (Gilt nur fürs Web-Frontend; das Live-Timing-WebSocket hat eigene Konto-Auth.) */
  const ACCESS = process.env.ACCESS_CODE || '';   // Sperre AUS (offen). Code via Render-Env ACCESS_CODE oder hier '...' wieder aktivierbar.
  if (ACCESS) {
    const hdr = req.headers['authorization'] || '';
    let ok = false;
    if (hdr.startsWith('Basic ')) {
      try { const dec = Buffer.from(hdr.slice(6), 'base64').toString(); ok = dec.slice(dec.indexOf(':') + 1) === ACCESS; } catch (e) {}
    }
    if (!ok) { res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="ALPIN TIMING PRO"' }); return res.end('Zugang gesperrt'); }
  }

  if (url === '/api/version') return json(res, 200, { version: appVersion() });

  if (url === '/api/register' || url === '/api/login') {
    if (req.method !== 'POST') return json(res, 405, { error: 'method' });
    let d; try { d = JSON.parse(await readBody(req)); } catch (e) { return json(res, 400, { error: 'json' }); }
    const u = normUser(d.username), pw = String(d.password || '');
    if (!validUser(u)) return json(res, 400, { error: 'username', msg: 'Benutzername: 3–24 Zeichen, a–z 0–9 _ -' });
    if (pw.length < 6) return json(res, 400, { error: 'password', msg: 'Passwort: mindestens 6 Zeichen' });
    if (url === '/api/register') {
      if (users[u]) return json(res, 409, { error: 'exists', msg: 'Benutzername bereits vergeben' });
      users[u] = { pw: hashPw(pw), created: Date.now() }; saveUsers(); ensureOwner();
      return json(res, 200, { token: signToken(u), user: u, license: licenseInfo(u) });
    } else {
      if (!users[u] || !verifyPw(pw, users[u].pw)) return json(res, 401, { error: 'auth', msg: 'Falscher Benutzer oder Passwort' });
      return json(res, 200, { token: signToken(u), user: u, license: licenseInfo(u) });
    }
  }

  /* --- Admin: Lizenz vergeben/entziehen (per ADMIN_KEY-Header geschuetzt) ---
     Nach Zahlung freischalten:
       curl -X POST .../api/admin/grant -H "x-admin-key: DEIN_KEY" -d '{"username":"verein","days":365}'
  */
  if (url === '/api/admin/grant' || url === '/api/admin/revoke') {
    if (req.method !== 'POST') return json(res, 405, { error: 'method' });
    const ADMIN = process.env.ADMIN_KEY || '';
    if (!ADMIN || req.headers['x-admin-key'] !== ADMIN) return json(res, 403, { error: 'forbidden' });
    let d; try { d = JSON.parse(await readBody(req)); } catch (e) { return json(res, 400, { error: 'json' }); }
    const u = normUser(d.username);
    if (!users[u]) return json(res, 404, { error: 'nouser', msg: 'Konto existiert nicht' });
    if (url === '/api/admin/grant') { const days = Math.max(1, parseInt(d.days) || 365); users[u].licenseExp = Date.now() + days * 86400000; }
    else { users[u].licenseExp = null; }
    saveUsers();
    return json(res, 200, { user: u, license: licenseInfo(u) });
  }

  /* --- Admin: alle Konten + Lizenzstatus auflisten (fuer die Admin-Seite) --- */
  if (url === '/api/admin/list') {
    const ADMIN = process.env.ADMIN_KEY || '';
    if (!ADMIN || req.headers['x-admin-key'] !== ADMIN) return json(res, 403, { error: 'forbidden' });
    const list = Object.keys(users).map(u => { const li = licenseInfo(u);
      return { user: u, created: users[u].created || 0, owner: !!li.owner, licensed: !!li.licensed, exp: li.exp || null }; })
      .sort((a, b) => (a.created || 0) - (b.created || 0));
    return json(res, 200, { users: list, count: list.length });
  }

  if (url === '/api/license/status') {
    if (req.method !== 'POST') return json(res, 405, { error: 'method' });
    let d; try { d = JSON.parse(await readBody(req)); } catch (e) { return json(res, 400, { error: 'json' }); }
    const u = verifyToken(d.token || '');
    if (!u) return json(res, 401, { error: 'auth' });
    return json(res, 200, { user: u, license: licenseInfo(u) });
  }

  /* Kontakt/Frage vom Kunden -> E-Mail an Betreiber + Datei-Backup */
  if (url === '/api/contact') {
    if (req.method !== 'POST') return json(res, 405, { error: 'method' });
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const now = Date.now();
    const hits = (_contactHits[ip] || []).filter(t => now - t < 600000);
    if (hits.length >= 5) return json(res, 429, { error: 'rate', msg: 'Zu viele Anfragen – bitte später erneut.' });
    let d; try { d = JSON.parse(await readBody(req)); } catch (e) { return json(res, 400, { error: 'json' }); }
    const name = String(d.name || '').slice(0, 120).trim();
    const email = String(d.email || '').slice(0, 160).trim();
    const account = String(d.account || '').slice(0, 60).trim();
    const message = String(d.message || '').slice(0, 4000).trim();
    if (message.length < 2) return json(res, 400, { error: 'empty', msg: 'Bitte eine Nachricht eingeben.' });
    _contactHits[ip] = hits.concat(now);
    const entry = { ts: new Date().toISOString(), ip, name, email, account, message };
    try { fs.appendFileSync(path.join(DATA, 'contact.log'), JSON.stringify(entry) + '\n'); } catch (e) {}
    let mailed = false;
    const tx = mailer();
    if (tx && CONTACT_TO) {
      try {
        await tx.sendMail({
          from: '"ALPIN TIMING Kontakt" <' + SMTP.user + '>', to: CONTACT_TO, replyTo: email || undefined,
          subject: 'ALPIN TIMING – Anfrage von ' + (name || account || email || 'Kunde'),
          text: 'Name: ' + name + '\nE-Mail: ' + email + '\nKonto: ' + account + '\nIP: ' + ip + '\nZeit: ' + entry.ts + '\n\n' + message
        });
        mailed = true;
      } catch (e) { console.log('Kontakt-Mail fehlgeschlagen: ' + e.message); }
    }
    return json(res, 200, { ok: true, mailed: mailed });
  }

  const route = url === '/' ? '/alpin-timing.html' : (url === '/admin' ? '/admin.html' : (url === '/anleitung' ? '/anleitung.html' : url));
  let safe = path.normalize(route).replace(/^(\.\.[/\\])+/, '');
  const file = path.join(ROOT, safe);
  if (!file.startsWith(ROOT + path.sep)) { res.writeHead(403); return res.end('forbidden'); }
  /* Nur oeffentliche statische Dateien ausliefern. NIEMALS Server-Code, Konten
     oder das Signatur-Geheimnis. Ohne diese Sperre liefert /data/secret das
     AUTH_SECRET aus -> jeder koennte Lizenzen/Logins faelschen. */
  const rel = path.relative(ROOT, file).replace(/\\/g, '/');
  const seg = rel.split('/');
  const ALLOW_EXT = new Set(['.html', '.js', '.css', '.json', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webmanifest', '.woff', '.woff2', '.ttf', '.map', '.txt', '.wasm']);
  const DENY_FILE = new Set(['server.js', 'package.json', 'package-lock.json', 'readme.md']);
  const blocked = seg[0] === 'data' || seg[0] === 'node_modules' || seg.some(p => p.startsWith('.'))
                  || DENY_FILE.has(rel.toLowerCase()) || !ALLOW_EXT.has(path.extname(file).toLowerCase());
  if (blocked) { res.writeHead(404); return res.end('not found'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  });
});

/* --- WebSocket: Räume pro Benutzer --- */
const wss = new WebSocketServer({ server });
const rooms = {};   // username -> { state }

function broadcastRoom(room) {
  if (!room) return;
  const st = rooms[room] && rooms[room].state;
  if (st === undefined) return;
  const msg = JSON.stringify({ type:'state', data: st });
  wss.clients.forEach(c => { if (c.readyState === 1 && (c.role === 'viewer' || c.role === 'station') && c.room === room) { try { c.send(msg); } catch (e){} } });
}
function relayToRoomMasters(room, obj) {
  const msg = JSON.stringify(obj);
  wss.clients.forEach(c => { if (c.readyState === 1 && c.role === 'master' && c.room === room) { try { c.send(msg); } catch (e){} } });
}

wss.on('connection', (ws, req) => {
  let q; try { q = new URL(req.url, 'http://x').searchParams; } catch (e) { q = new URLSearchParams(); }
  const token = q.get('token'), role = q.get('role'), roomParam = normUser(q.get('room'));
  if (token) {
    const u = verifyToken(token);
    if (!u) { try { ws.send(JSON.stringify({ type:'authfail' })); } catch(e){} ws.close(); return; }
    ws.user = u; ws.room = u; ws.role = (role === 'station') ? 'station' : 'master';
    if (ws.role === 'master') { const li = licenseInfo(u); try { ws.send(JSON.stringify({ type:'license', licensed: li.licensed, exp: li.exp })); } catch(e){} }
  } else {
    ws.role = 'viewer'; ws.room = roomParam || null;
  }
  if ((ws.role === 'viewer' || ws.role === 'station') && ws.room && rooms[ws.room] && rooms[ws.room].state !== undefined) {
    try { ws.send(JSON.stringify({ type:'state', data: rooms[ws.room].state })); } catch (e){}
  }
  ws.isAlive = true; ws.on('pong', () => { ws.isAlive = true; });
  ws.on('error', () => {});   // abrupt getrennter Client darf keine uncaught exception werfen (killt sonst den Server)

  ws.on('message', (raw) => {
    let d; try { d = JSON.parse(raw.toString()); } catch (e) { return; }
    if (d.type === 'time') { try { ws.send(JSON.stringify({ type:'time', t1: d.t1, ts: Date.now() })); } catch (e){} return; }
    if (!ws.user || !ws.room) return;                 // ab hier nur authentifiziert
    if (d.type === 'state' && ws.role === 'master') {
      if (!licenseInfo(ws.user).licensed) return;   // ohne gueltige Lizenz wird nicht live gesendet
      rooms[ws.room] = { state: d.data }; broadcastRoom(ws.room);
    }
    else if (d.type === 'event') { relayToRoomMasters(ws.room, { type:'event', kind: d.kind, run: d.run, serverT: d.serverT });
      if (d.id != null) { try { ws.send(JSON.stringify({ type:'ack', id: d.id })); } catch (e) {} } }   // Quittung: Startimpuls kam an
  });
});

setInterval(() => {
  wss.clients.forEach(c => { if (c.isAlive === false) return c.terminate(); c.isAlive = false; try { c.ping(); } catch (e){} });
  const t = Date.now();   // Ratenbegrenzungs-Map nicht unbegrenzt wachsen lassen (Memory-Leak bei Dauerbetrieb)
  for (const ip in _contactHits) { if (!_contactHits[ip].some(x => t - x < 600000)) delete _contactHits[ip]; }
}, 30000);

server.listen(PORT, () => {
  console.log('ALPIN TIMING Server  http://0.0.0.0:' + PORT);
  console.log('Datenordner: ' + DATA + (process.env.DATA_DIR ? '  (dauerhaft via DATA_DIR)' : '  (lokal – auf Gratis-Tarifen evtl. fluechtig! DATA_DIR auf eine Persistent Disk setzen)'));
  console.log('AUTH_SECRET: ' + (process.env.AUTH_SECRET ? 'aus Umgebung' : 'aus Datei/zufaellig (fuer Dauerbetrieb AUTH_SECRET setzen)'));
  console.log('Konten aktiv. Registrieren/Anmelden in der App unter Vernetzung. Öffentliche Ansicht: …/?room=BENUTZER#results');
});

module.exports = { hashPw, verifyPw, signToken, verifyToken, normUser, validUser, broadcastRoom, relayToRoomMasters, rooms, wss, appVersion };
