import { createServer } from 'node:http';
import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const derive = promisify(scrypt);
const sessionSeconds = 30 * 24 * 60 * 60;
const hashToken = token => createHash('sha256').update(token).digest('hex');
const passwordHash = (password, salt) =>
  derive(password, salt, 64, { N: 131072, r: 8, p: 1, maxmem: 192 * 1024 * 1024 });

export function watchlistServer({ database, origin, html }) {
  const db = new DatabaseSync(database);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  db.exec('CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, digest TEXT NOT NULL);' +
    'CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, account INTEGER NOT NULL REFERENCES accounts(id), expires INTEGER NOT NULL);' +
    'CREATE TABLE IF NOT EXISTS watched (account INTEGER NOT NULL REFERENCES accounts(id), title TEXT NOT NULL, PRIMARY KEY (account, title));');
  const secure = new URL(origin).protocol === 'https:';
  const cookieName = secure ? '__Host-watchlist' : 'watchlist';
  const cookie = (token, age) => cookieName + '=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + age + (secure ? '; Secure' : '');
  const titles = new Set([...html.matchAll(/<tr [^>]*\bdata-id="(\d+)"/g)].map(match => match[1]));
  const lookup = db.prepare('SELECT accounts.id, accounts.username FROM sessions JOIN accounts ON accounts.id = sessions.account WHERE token = ? AND expires > ?');
  const attempts = new Map();
  let hashing = false;

  function respond(res, status, body, headers = {}) {
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...headers,
    });
    res.end(JSON.stringify(body));
  }
  async function body(req) {
    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 4096) return null;
      chunks.push(chunk);
    }
    try { return JSON.parse(Buffer.concat(chunks)); } catch { return null; }
  }
  function blocked(address, username) {
    const now = Date.now();
    for (const [key, record] of attempts) {
      if (now >= record.until) attempts.delete(key);
    }
    const keys = ['ip:' + address, 'name:' + username];
    if (attempts.size >= 10000 || keys.some(key => (attempts.get(key)?.count ?? 0) >= 10)) return true;
    for (const key of keys) {
      const record = attempts.get(key) ?? { count: 0, until: now + 10 * 60 * 1000 };
      record.count++;
      attempts.set(key, record);
    }
    return false;
  }
  const server = createServer(async (req, res) => {
    try {
      const path = new URL(req.url, origin).pathname;
      if (req.method === 'GET' && (path === '/' || path === '/index.html')) {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'same-origin',
          'Content-Security-Policy': "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        });
        return res.end(html);
      }
      if (!path.startsWith('/api/')) return respond(res, 404, { error: 'Page not found.' });
      const now = Math.floor(Date.now() / 1000);
      const token = (req.headers.cookie ?? '').match(new RegExp('(?:^|;\\s*)' + cookieName + '=([a-f0-9]{64})(?:;|$)'))?.[1];
      const account = token ? lookup.get(hashToken(token), now) : undefined;
      const status = profile => ({
        username: profile?.username ?? null,
        watched: profile ? db.prepare('SELECT title FROM watched WHERE account = ?').all(profile.id).map(row => row.title) : [],
      });
      if (req.method === 'GET' && path === '/api/session') return respond(res, 200, status(account));
      if (req.method !== 'POST') return respond(res, 405, { error: 'Method unavailable.' });
      if (req.headers.origin !== origin) return respond(res, 403, { error: 'Request must come from the watchlist.' });
      if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] ?? '')) {
        return respond(res, 415, { error: 'JSON is required.' });
      }
      const data = await body(req);
      if (!data || typeof data !== 'object') return respond(res, 400, { error: 'Invalid request.' });
      if (path === '/api/login' || path === '/api/register') {
        const username = typeof data.username === 'string' ? data.username.trim().toLowerCase() : '';
        const password = typeof data.password === 'string' ? data.password : '';
        if (!/^[a-z0-9_]{3,32}$/.test(username) || password.length < 15 || password.length > 128) {
          return respond(res, 400, { error: 'Use 3–32 letters, numbers or underscores and a password of 15–128 characters.' });
        }
        if (hashing || blocked(req.socket.remoteAddress, username)) {
          return respond(res, 429, { error: 'Too many sign-in attempts. Try again later.' });
        }
        const record = db.prepare('SELECT * FROM accounts WHERE username = ?').get(username);
        const registering = path === '/api/register';
        const salt = registering ? randomBytes(16).toString('hex') : record?.salt ?? '0'.repeat(32);
        let digest;
        hashing = true;
        try { digest = await passwordHash(password, salt); } finally { hashing = false; }
        let profile = record;
        if (registering) {
          const inserted = db.prepare('INSERT OR IGNORE INTO accounts (username, salt, digest) VALUES (?, ?, ?)').run(username, salt, digest.toString('hex'));
          if (!inserted.changes) return respond(res, 409, { error: 'That username is unavailable.' });
          profile = { id: inserted.lastInsertRowid, username };
        } else if (!record || !timingSafeEqual(digest, Buffer.from(record.digest, 'hex'))) {
          return respond(res, 401, { error: 'Username or password is incorrect.' });
        }
        const nextToken = randomBytes(32).toString('hex');
        db.prepare('DELETE FROM sessions WHERE expires <= ? OR token = ?').run(now, token ? hashToken(token) : '');
        db.prepare('INSERT INTO sessions (token, account, expires) VALUES (?, ?, ?)').run(hashToken(nextToken), profile.id, now + sessionSeconds);
        return respond(res, 200, status(profile), { 'Set-Cookie': cookie(nextToken, sessionSeconds) });
      }
      if (path === '/api/logout') {
        if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(hashToken(token));
        return respond(res, 200, status(), { 'Set-Cookie': cookie('', 0) });
      }
      if (path === '/api/progress') {
        if (!account) return respond(res, 401, { error: 'Sign in to save to your account.' });
        if (!titles.has(data.title) || typeof data.watched !== 'boolean') {
          return respond(res, 400, { error: 'Invalid checklist entry.' });
        }
        if (data.watched) {
          db.prepare('INSERT OR IGNORE INTO watched (account, title) VALUES (?, ?)').run(account.id, data.title);
        } else {
          db.prepare('DELETE FROM watched WHERE account = ? AND title = ?').run(account.id, data.title);
        }
        return respond(res, 200, { saved: true });
      }
      return respond(res, 404, { error: 'Page not found.' });
    } catch {
      respond(res, 500, { error: 'The account service could not save your request. Try again.' });
    }
  });
  server.on('close', () => db.close());
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3000);
  const address = new URL(process.env.PUBLIC_ORIGIN || 'http://localhost:' + port);
  if (address.protocol !== 'https:' && address.origin !== 'http://localhost:' + port) {
    throw new Error('Use HTTPS for any public deployment.');
  }
  const directory = resolve(process.env.WATCHLIST_DATA_DIR || '.watchlist-data');
  mkdirSync(directory, { recursive: true });
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  watchlistServer({ database: resolve(directory, 'watchlist.sqlite'), origin: address.origin, html })
    .listen(port, process.env.HOST || '127.0.0.1', () => console.log('Watchlist: ' + address.origin));
}
