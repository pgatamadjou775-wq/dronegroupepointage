/**
 * Sha'ah — Serveur (version hébergement en ligne)
 * -----------------------------------------------------------
 * Aucune dépendance externe : uniquement les modules intégrés à Node.js.
 *
 * Méthode de pointage : QR code dynamique + signature secrète (challenge/response)
 *  - L'employé pointe sur la tablette : un QR "challenge" temporaire est affiché.
 *  - Il scanne ce QR avec l'app "Scan" installée sur son téléphone (liée à son
 *    identité via un code secret personnel donné une seule fois par le RH).
 *  - Le téléphone signe le challenge avec le secret de l'employé (HMAC) et
 *    l'envoie au serveur. Le serveur ne valide le pointage QUE si la signature
 *    correspond exactement au secret de la personne sélectionnée sur la tablette.
 *  - Le QR expire au bout de 25 secondes : une capture d'écran ou une photo du
 *    QR par un collègue devient inutilisable presque immédiatement.
 *
 * Sécurité :
 *  - Espace RH protégé par identifiant + mot de passe (haché avec scrypt).
 *  - Tablette de pointage protégée par un jeton d'activation.
 *  - App Scan (téléphone employé) : pairing par code secret personnel, puis
 *    le secret ne quitte plus jamais l'appareil (il ne sert qu'à signer).
 *  - Le secret de chaque employé n'est JAMAIS renvoyé au RH après la création
 *    (seul le code de pairage l'est, tant qu'il n'a pas encore été utilisé).
 *  - Limitation du nombre de tentatives sur les routes sensibles.
 *
 * Variables d'environnement utiles (toutes optionnelles) :
 *   PORT              Port d'écoute (fourni automatiquement par la plupart
 *                      des hébergeurs : Render, Railway...)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_FILE = process.env.DATA_FILE || path.join(ROOT, 'data.json');
const BACKUP_DIR = path.join(ROOT, 'sauvegardes');
const CHALLENGE_TTL_MS = 25 * 1000; // durée de vie d'un QR de pointage

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// ============================================================
// SÉCURITÉ : mots de passe, jetons, sessions
// ============================================================
function makeSalt() { return crypto.randomBytes(16).toString('hex'); }

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString('hex');
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function randomPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  let s = '';
  for (let i = 0; i < 12; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

function randomKioskCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sans caractères ambigus
  let s = '';
  for (let i = 0; i < 8; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

// Code secret personnel d'un employé : sert au pairage du téléphone ET de clé
// de signature HMAC pour chaque pointage. Plus long qu'un code tablette.
function randomEmployeeSecret() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 10; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

function randomChallengeId() {
  return crypto.randomBytes(9).toString('hex'); // 18 caractères
}

function signChallenge(secret, challengeId) {
  return crypto.createHmac('sha256', String(secret)).update(String(challengeId)).digest('hex');
}

// Sessions RH en mémoire (sid -> {username, expires})
const sessions = new Map();
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

function createSession(username) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { username, expires: Date.now() + SESSION_TTL_MS });
  return sid;
}
function getSession(sid) {
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(sid); return null; }
  return s;
}
function destroySession(sid) { sessions.delete(sid); }
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) if (now > s.expires) sessions.delete(sid);
}, 60 * 60 * 1000);

// Challenges de pointage QR en mémoire (id -> {...})
const challenges = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of challenges) {
    if (now > c.expiresAt + 60 * 1000) challenges.delete(id); // nettoyage différé
  }
}, 30 * 1000);

// Anti brute-force simple (connexion RH, pairage téléphone, scan QR)
const attemptCounters = new Map(); // key(ip+scope) -> {count, resetAt}
function checkRateLimit(key, max = 8, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const rec = attemptCounters.get(key);
  if (!rec || now > rec.resetAt) {
    attemptCounters.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  rec.count++;
  return rec.count <= max;
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx < 0) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}
function setCookie(req, res, name, value, opts = {}) {
  const isHttps = req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted;
  let str = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax`;
  if (opts.maxAge) str += `; Max-Age=${opts.maxAge}`;
  if (isHttps) str += '; Secure';
  res.setHeader('Set-Cookie', str);
}
function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; Path=/; HttpOnly; Max-Age=0`);
}

// ============================================================
// DONNÉES
// ============================================================
function defaultData() {
  const salt = makeSalt();
  const initialPassword = randomPassword();
  const kioskToken = randomKioskCode();
  const data = {
    employes: [], retards: [], absences: [], lid: 0,
    settings: {
      rhUsername: 'admin',
      rhPasswordSalt: salt,
      rhPasswordHash: hashPassword(initialPassword, salt),
      kioskToken
    }
  };
  console.log('');
  console.log('======================================================');
  console.log(' Première installation — identifiants RH générés :');
  console.log('   Utilisateur       : admin');
  console.log('   Mot de passe      : ' + initialPassword);
  console.log('   Code d\'activation tablette : ' + kioskToken);
  console.log(' -> Notez-les ! Connectez-vous puis changez le mot de');
  console.log('    passe dans Employés > Sécurité.');
  console.log('======================================================');
  console.log('');
  return data;
}

function readData() {
  let d;
  try {
    d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    d = defaultData();
    writeData(d);
    return d;
  }
  let changed = false;
  if (!d.settings) d.settings = {};
  if (!d.settings.kioskToken) { d.settings.kioskToken = randomKioskCode(); changed = true; }
  if (!d.settings.rhPasswordHash) {
    // Migration depuis l'ancienne version à code PIN (réseau local)
    const salt = makeSalt();
    const pwd = randomPassword();
    d.settings.rhUsername = d.settings.rhUsername || 'admin';
    d.settings.rhPasswordSalt = salt;
    d.settings.rhPasswordHash = hashPassword(pwd, salt);
    delete d.settings.pin;
    changed = true;
    console.log('');
    console.log('======================================================');
    console.log(' Migration : nouveaux identifiants RH générés :');
    console.log('   Utilisateur       : ' + d.settings.rhUsername);
    console.log('   Mot de passe      : ' + pwd);
    console.log('   Code d\'activation tablette : ' + d.settings.kioskToken);
    console.log('======================================================');
    console.log('');
  }
  if (!Array.isArray(d.employes)) d.employes = [];
  if (!Array.isArray(d.retards)) d.retards = [];
  if (!Array.isArray(d.absences)) d.absences = [];
  if (typeof d.lid !== 'number') d.lid = 0;
  // Migration : anciens employés avec reconnaissance faciale -> secret de pointage QR
  d.employes.forEach(e => {
    if (e.faceDescriptor !== undefined) { delete e.faceDescriptor; changed = true; }
    if (!e.secret) { e.secret = randomEmployeeSecret(); e.phonePaired = false; changed = true; }
    if (typeof e.phonePaired !== 'boolean') { e.phonePaired = false; changed = true; }
  });
  if (changed) writeData(d);
  return d;
}

function writeData(obj) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, DATA_FILE);
}

function backupIfNeeded() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);
    const today = new Date().toISOString().split('T')[0];
    const dest = path.join(BACKUP_DIR, `data-${today}.json`);
    if (!fs.existsSync(dest)) fs.copyFileSync(DATA_FILE, dest);
  } catch (e) {
    console.error('Sauvegarde automatique impossible :', e.message);
  }
}

// ============================================================
// UTILITAIRES HTTP
// ============================================================
function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readBody(req, maxBytes = 60 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) { reject(new Error('PAYLOAD_TOO_LARGE')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) { resolve({}); return; }
      try { resolve(JSON.parse(raw)); } catch (e) { reject(new Error('INVALID_JSON')); }
    });
    req.on('error', reject);
  });
}

function serveStatic(req, res, urlPath) {
  const safePath = urlPath === '/' ? '/index.html' : urlPath;
  const filePath = path.join(PUBLIC_DIR, safePath);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end('Interdit'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Page introuvable : ' + urlPath);
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

function requireRH(req) {
  const cookies = parseCookies(req);
  return getSession(cookies.sid);
}
function requireKiosk(req) {
  const token = req.headers['x-kiosk-token'];
  if (!token) return false;
  const data = readData();
  return safeEqual(token, data.settings.kioskToken);
}

// Enregistre un pointage validé (utilisé par le flux QR une fois la signature vérifiée)
function recordPointage(data, emp, type) {
  const now = new Date();
  const dateStr = now.toISOString().split('T')[0];
  const h = String(now.getHours()).padStart(2, '0');
  const m = String(now.getMinutes()).padStart(2, '0');
  const timeStr = h + ':' + m;

  const deja = data.retards.find(r => r.empId === emp.id && r.date === dateStr && (r.type || 'arrivee') === type);
  if (deja) return { ok: false, error: 'Déjà pointé aujourd\'hui', already: { harr: deja.harr } };

  let hRef, diffMn, estAnomalie;
  if (type === 'depart') {
    hRef = emp.hdep || '17:30';
    const [rh, rm] = hRef.split(':').map(Number);
    diffMn = (rh * 60 + rm) - (now.getHours() * 60 + now.getMinutes());
    estAnomalie = diffMn > 0;
  } else {
    hRef = emp.href || '08:00';
    const [rh, rm] = hRef.split(':').map(Number);
    diffMn = (now.getHours() * 60 + now.getMinutes()) - (rh * 60 + rm);
    estAnomalie = diffMn > 0;
  }
  const totalMn = estAnomalie ? diffMn : 0;
  const justifie = (!estAnomalie) ? 'Oui' : 'Non';

  data.lid++;
  const rec = {
    id: 'I' + data.lid, empId: emp.id, empNom: emp.nom, date: dateStr, type,
    hprev: hRef, harr: timeStr, rh: Math.floor(totalMn / 60), rm: totalMn % 60, totalMn,
    motif: '', justifie, photo: null, ts: Date.now(), source: 'scan-qr'
  };
  data.retards.push(rec);
  writeData(data);
  return { ok: true, estAnomalie, record: { harr: rec.harr, hprev: rec.hprev, totalMn: rec.totalMn, justifie: rec.justifie } };
}

// ============================================================
// SERVEUR
// ============================================================
const server = http.createServer(async (req, res) => {
  try {
    const parsedUrl = new URL(req.url, 'http://localhost');
    const urlPath = decodeURIComponent(parsedUrl.pathname);
    const ip = req.socket.remoteAddress || 'inconnu';

    // ---------- CONNEXION RH ----------
    if (urlPath === '/api/login' && req.method === 'POST') {
      if (!checkRateLimit('login:' + ip)) return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Réessayez dans quelques minutes.' });
      const body = await readBody(req);
      const data = readData();
      const { username, password } = body || {};
      if (!username || !password) return sendJSON(res, 400, { ok: false, error: 'Identifiants manquants' });
      const validUser = safeEqual(username, data.settings.rhUsername);
      const hash = hashPassword(password, data.settings.rhPasswordSalt);
      const ok = validUser && safeEqual(hash, data.settings.rhPasswordHash);
      if (!ok) return sendJSON(res, 401, { ok: false, error: 'Identifiant ou mot de passe incorrect' });
      const sid = createSession(data.settings.rhUsername);
      setCookie(req, res, 'sid', sid, { maxAge: 12 * 60 * 60 });
      return sendJSON(res, 200, { ok: true, username: data.settings.rhUsername });
    }

    if (urlPath === '/api/logout' && req.method === 'POST') {
      const cookies = parseCookies(req);
      if (cookies.sid) destroySession(cookies.sid);
      clearCookie(res, 'sid');
      return sendJSON(res, 200, { ok: true });
    }

    if (urlPath === '/api/session' && req.method === 'GET') {
      const s = requireRH(req);
      return sendJSON(res, 200, s ? { loggedIn: true, username: s.username } : { loggedIn: false });
    }

    // ---------- RH : accès complet (authentifié) ----------
    if (urlPath === '/api/data' && req.method === 'GET') {
      if (!requireRH(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const data = readData();
      const sanitized = Object.assign({}, data, {
        employes: data.employes.map(e => {
          const copy = Object.assign({}, e);
          delete copy.secret; // le secret ne quitte jamais le serveur
          return copy;
        }),
        settings: { rhUsername: data.settings.rhUsername, kioskToken: data.settings.kioskToken }
      });
      return sendJSON(res, 200, sanitized);
    }
    if (urlPath === '/api/data' && req.method === 'POST') {
      if (!requireRH(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req, 60 * 1024 * 1024);
      const current = readData();
      // Les champs de sécurité ne se modifient JAMAIS via cette route générique,
      // uniquement via /api/settings/password et /api/settings/kiosk-token.
      body.settings = {
        rhUsername: current.settings.rhUsername,
        rhPasswordHash: current.settings.rhPasswordHash,
        rhPasswordSalt: current.settings.rhPasswordSalt,
        kioskToken: current.settings.kioskToken
      };
      // Le secret de pointage de chaque employé n'est jamais envoyé au RH : on le
      // restaure depuis les données actuelles (ou on en génère un si nouvel employé).
      const byId = new Map(current.employes.map(e => [e.id, e]));
      (body.employes || []).forEach(e => {
        const existing = byId.get(e.id);
        if (existing && existing.secret) {
          e.secret = existing.secret;
          e.phonePaired = existing.phonePaired || false;
        } else if (!e.secret) {
          e.secret = randomEmployeeSecret();
          e.phonePaired = false;
        }
      });
      backupIfNeeded();
      writeData(body);
      return sendJSON(res, 200, { ok: true });
    }

    if (urlPath === '/api/settings/password' && req.method === 'POST') {
      if (!requireRH(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      const data = readData();
      const { currentPassword, newUsername, newPassword } = body || {};
      const curHash = hashPassword(currentPassword || '', data.settings.rhPasswordSalt);
      if (!safeEqual(curHash, data.settings.rhPasswordHash)) return sendJSON(res, 401, { ok: false, error: 'Mot de passe actuel incorrect' });
      if (newUsername && newUsername.trim()) data.settings.rhUsername = newUsername.trim();
      if (newPassword) {
        if (newPassword.length < 8) return sendJSON(res, 400, { ok: false, error: 'Le nouveau mot de passe doit faire au moins 8 caractères' });
        const salt = makeSalt();
        data.settings.rhPasswordSalt = salt;
        data.settings.rhPasswordHash = hashPassword(newPassword, salt);
      }
      writeData(data);
      return sendJSON(res, 200, { ok: true, username: data.settings.rhUsername });
    }

    if (urlPath === '/api/settings/kiosk-token' && req.method === 'POST') {
      if (!requireRH(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const data = readData();
      data.settings.kioskToken = randomKioskCode();
      writeData(data);
      return sendJSON(res, 200, { ok: true, kioskToken: data.settings.kioskToken });
    }

    // RH : (re)générer le code secret de pointage d'un employé (perte de téléphone, etc.)
    if (urlPath === '/api/settings/employee-secret' && req.method === 'POST') {
      if (!requireRH(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      const { empId, secret } = body || {};
      const data = readData();
      const emp = data.employes.find(e => e.id === empId);
      if (!emp) return sendJSON(res, 404, { ok: false, error: 'Employé introuvable' });
      const clean = (secret || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
      emp.secret = clean.length >= 6 ? clean.slice(0, 16) : randomEmployeeSecret();
      emp.phonePaired = false;
      writeData(data);
      return sendJSON(res, 200, { ok: true, secret: emp.secret });
    }

    // ---------- KIOSQUE (tablette de pointage) : accès restreint ----------
    if (urlPath === '/api/employees' && req.method === 'GET') {
      if (!requireKiosk(req)) return sendJSON(res, 401, { ok: false, error: 'Tablette non activée' });
      const data = readData();
      const list = data.employes.filter(e => e.statut === 'Actif')
        .map(e => ({ id: e.id, nom: e.nom, href: e.href, hdep: e.hdep }));
      return sendJSON(res, 200, { employes: list });
    }

    if (urlPath === '/api/my-records' && req.method === 'GET') {
      if (!requireKiosk(req)) return sendJSON(res, 401, { ok: false, error: 'Tablette non activée' });
      const empId = parsedUrl.searchParams.get('empId');
      const data = readData();
      const limitDate = new Date(); limitDate.setDate(limitDate.getDate() - 30);
      const limitStr = limitDate.toISOString().split('T')[0];
      const records = data.retards
        .filter(r => r.empId === empId && r.totalMn > 0 && r.justifie !== 'Oui' && r.date >= limitStr)
        .sort((a, b) => b.date.localeCompare(a.date))
        .map(r => ({ id: r.id, type: r.type, date: r.date, hprev: r.hprev, harr: r.harr, totalMn: r.totalMn, motif: r.motif }));
      return sendJSON(res, 200, { records });
    }

    if (urlPath === '/api/justify' && req.method === 'POST') {
      if (!requireKiosk(req)) return sendJSON(res, 401, { ok: false, error: 'Tablette non activée' });
      const body = await readBody(req);
      const { recordId, motif } = body || {};
      if (!recordId || !motif || !motif.trim()) return sendJSON(res, 400, { ok: false, error: 'Motif requis' });
      const data = readData();
      const rec = data.retards.find(r => r.id === recordId);
      if (!rec) return sendJSON(res, 404, { ok: false, error: 'Introuvable' });
      rec.motif = motif.trim().slice(0, 500);
      rec.justifie = 'Oui';
      writeData(data);
      return sendJSON(res, 200, { ok: true });
    }

    // ---------- POINTAGE PAR QR (challenge / réponse) ----------

    // 1) La tablette demande un QR "challenge" pour l'employé sélectionné
    if (urlPath === '/api/pointage/challenge' && req.method === 'POST') {
      if (!requireKiosk(req)) return sendJSON(res, 401, { ok: false, error: 'Tablette non activée' });
      const body = await readBody(req);
      const { empId, type } = body || {};
      if (!empId || !['arrivee', 'depart'].includes(type)) return sendJSON(res, 400, { ok: false, error: 'Requête invalide' });
      const data = readData();
      const emp = data.employes.find(e => e.id === empId && e.statut === 'Actif');
      if (!emp) return sendJSON(res, 404, { ok: false, error: 'Employé introuvable' });
      if (!emp.phonePaired) {
        return sendJSON(res, 409, { ok: false, error: 'Cet employé n\'a pas encore jumelé son téléphone (app Scan). Voir Espace RH.' });
      }
      const already = data.retards.find(r => r.empId === empId && r.date === new Date().toISOString().split('T')[0] && (r.type || 'arrivee') === type);
      if (already) return sendJSON(res, 409, { ok: false, error: 'Déjà pointé aujourd\'hui', already: { harr: already.harr } });

      const id = randomChallengeId();
      challenges.set(id, {
        id, empId, empNom: emp.nom, type,
        createdAt: Date.now(), expiresAt: Date.now() + CHALLENGE_TTL_MS,
        status: 'pending', record: null, error: null
      });
      return sendJSON(res, 200, { ok: true, challengeId: id, expiresIn: CHALLENGE_TTL_MS / 1000 });
    }

    // 2) La tablette interroge périodiquement le statut du challenge affiché
    if (urlPath.startsWith('/api/pointage/challenge/') && req.method === 'GET') {
      if (!requireKiosk(req)) return sendJSON(res, 401, { ok: false, error: 'Tablette non activée' });
      const id = urlPath.split('/').pop();
      const c = challenges.get(id);
      if (!c) return sendJSON(res, 404, { ok: false, status: 'introuvable' });
      if (c.status === 'pending' && Date.now() > c.expiresAt) c.status = 'expired';
      return sendJSON(res, 200, {
        ok: true, status: c.status, empNom: c.empNom,
        record: c.record, error: c.error,
        remaining: Math.max(0, Math.round((c.expiresAt - Date.now()) / 1000))
      });
    }

    // 3) Le téléphone de l'employé (app Scan) confirme le challenge scanné
    if (urlPath === '/api/pointage/scan' && req.method === 'POST') {
      if (!checkRateLimit('scan:' + ip, 30, 5 * 60 * 1000)) {
        return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Patientez un instant.' });
      }
      const body = await readBody(req);
      const { challengeId, empId, signature } = body || {};
      if (!challengeId || !empId || !signature) return sendJSON(res, 400, { ok: false, error: 'Requête invalide' });

      const c = challenges.get(challengeId);
      if (!c) return sendJSON(res, 404, { ok: false, error: 'Ce QR est introuvable ou a déjà expiré.' });
      if (Date.now() > c.expiresAt) { c.status = 'expired'; return sendJSON(res, 410, { ok: false, error: 'Ce QR a expiré. Redemandez un pointage sur la tablette.' }); }
      if (c.status !== 'pending') return sendJSON(res, 409, { ok: false, error: 'Ce QR a déjà été utilisé.' });

      if (c.empId !== empId) {
        return sendJSON(res, 403, { ok: false, error: 'Ce code ne correspond pas à votre identité.' });
      }

      const data = readData();
      const emp = data.employes.find(e => e.id === empId && e.statut === 'Actif');
      if (!emp) return sendJSON(res, 404, { ok: false, error: 'Employé introuvable' });

      const expected = signChallenge(emp.secret, challengeId);
      if (!safeEqual(signature, expected)) {
        return sendJSON(res, 403, { ok: false, error: 'Signature invalide — jumelage à refaire depuis l\'Espace RH.' });
      }

      const result = recordPointage(data, emp, c.type);
      if (!result.ok) {
        c.status = 'rejected';
        c.error = result.error;
        return sendJSON(res, 409, { ok: false, error: result.error });
      }
      c.status = 'confirmed';
      c.record = result.record;
      c.estAnomalie = result.estAnomalie;
      return sendJSON(res, 200, { ok: true, empNom: emp.nom, estAnomalie: result.estAnomalie, record: result.record });
    }

    // 4) Jumelage du téléphone d'un employé (première utilisation de l'app Scan)
    if (urlPath === '/api/employee/pair' && req.method === 'POST') {
      if (!checkRateLimit('pair:' + ip, 15, 15 * 60 * 1000)) {
        return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Réessayez plus tard.' });
      }
      const body = await readBody(req);
      const code = ((body && body.secret) || '').trim().toUpperCase();
      if (!code) return sendJSON(res, 400, { ok: false, error: 'Code requis' });
      const data = readData();
      const emp = data.employes.find(e => e.statut === 'Actif' && safeEqual(e.secret, code));
      if (!emp) return sendJSON(res, 401, { ok: false, error: 'Code secret incorrect. Vérifiez-le auprès du service RH.' });
      emp.phonePaired = true;
      writeData(data);
      return sendJSON(res, 200, { ok: true, empId: emp.id, empNom: emp.nom, secret: emp.secret });
    }

    // ---------- Fichiers statiques ----------
    if (req.method === 'GET') return serveStatic(req, res, urlPath);

    res.writeHead(405);
    res.end('Méthode non autorisée');
  } catch (e) {
    if (e.message === 'PAYLOAD_TOO_LARGE') return sendJSON(res, 413, { ok: false, error: 'Fichier trop volumineux' });
    if (e.message === 'INVALID_JSON') return sendJSON(res, 400, { ok: false, error: 'Données invalides' });
    console.error(e);
    sendJSON(res, 500, { ok: false, error: 'Erreur serveur' });
  }
});

server.listen(PORT, () => {
  console.log('');
  console.log('==========================================================');
  console.log('   Sha\'ah — le serveur est démarré (port ' + PORT + ')');
  console.log('==========================================================');
  // Déclenche la génération des identifiants par défaut si besoin, dès le démarrage.
  readData();
});
