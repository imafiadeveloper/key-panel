import { neon } from '@neondatabase/serverless';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// ---- Neon SQL wrapper (tagged template) ----
const _neon = neon(process.env.POSTGRES_URL || process.env.DATABASE_URL);
const sql = async (strings, ...values) => {
  let q = strings[0];
  for (let i = 0; i < values.length; i++) q += '$' + (i + 1) + strings[i + 1];
  const rows = await _neon(q, values);
  return { rows };
};

// ---- helpers ----
const genKey = () => {
  const r = crypto.randomBytes(12).toString('hex').toUpperCase();
  return `KEY-${r.slice(0,4)}-${r.slice(4,8)}-${r.slice(8,12)}-${r.slice(12,16)}`;
};

const getIP = (req) => {
  const xf = req.headers['x-forwarded-for'];
  return xf ? String(xf).split(',')[0].trim() : (req.socket?.remoteAddress || 'unknown');
};

const checkAdmin = (req) => {
  const raw = req.headers.cookie || '';
  const m = raw.match(/admin_token=([^;]+)/);
  if (!m) return false;
  try { return jwt.verify(m[1], JWT_SECRET).role === 'admin'; } catch { return false; }
};

async function log(action, { key_value, hwid, message, ip } = {}) {
  try {
    await sql`INSERT INTO logs (key_value, hwid, action, message, ip)
      VALUES (${key_value||null}, ${hwid||null}, ${action}, ${message||null}, ${ip||null})`;
  } catch {}
}

let schemaReady = false;
async function ensureSchema() {
  if (schemaReady) return;
  await sql`CREATE TABLE IF NOT EXISTS keys (
    id SERIAL PRIMARY KEY, key_value VARCHAR(64) UNIQUE NOT NULL,
    max_devices INT DEFAULT 1, used_devices INT DEFAULT 0,
    expiry_at TIMESTAMP NULL, is_revoked BOOLEAN DEFAULT FALSE,
    note TEXT, created_at TIMESTAMP DEFAULT NOW())`;
  await sql`CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY, key_id INT REFERENCES keys(id) ON DELETE CASCADE,
    hwid VARCHAR(128) NOT NULL, device_model VARCHAR(128), device_brand VARCHAR(128),
    android_ver VARCHAR(32), last_ip VARCHAR(64),
    first_seen TIMESTAMP DEFAULT NOW(), last_seen TIMESTAMP DEFAULT NOW(),
    is_banned BOOLEAN DEFAULT FALSE, UNIQUE(key_id, hwid))`;
  await sql`CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY, key_value VARCHAR(64), hwid VARCHAR(128),
    action VARCHAR(32), message TEXT, ip VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW())`;
  await sql`CREATE TABLE IF NOT EXISTS config (
    id INT PRIMARY KEY DEFAULT 1, killswitch BOOLEAN DEFAULT FALSE,
    maintenance BOOLEAN DEFAULT FALSE, broadcast_msg TEXT DEFAULT '')`;
  await sql`INSERT INTO config (id) VALUES (1) ON CONFLICT DO NOTHING`;
  schemaReady = true;
}

// ---- parse body for Vercel ----
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); }
    });
    req.on('error', () => resolve({}));
  });
}

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const body = await readBody(req);
  const ip = getIP(req);

  // ---- extract path ----
  let path = (req.url || '').split('?')[0];
  path = path.replace(/^\/api\/?/, '').replace(/\/$/, '');
  if (path === 'index.js' || path === 'index') path = '';

  try {
    await ensureSchema();

    // ============ ADMIN LOGIN ============
    if (path === 'admin/login' && req.method === 'POST') {
      if (body.password !== ADMIN_PASSWORD)
        return res.status(401).json({ ok: false, error: 'wrong_password' });
      const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
      res.setHeader('Set-Cookie', `admin_token=${token}; Path=/; HttpOnly; Max-Age=${7*24*3600}; SameSite=Lax`);
      return res.json({ ok: true });
    }
    if (path === 'admin/logout') {
      res.setHeader('Set-Cookie', 'admin_token=; Path=/; Max-Age=0');
      return res.json({ ok: true });
    }

    // ============ VALIDATE (Android) ============
    if (path === 'key/validate' && req.method === 'POST') {
      const { rows: c } = await sql`SELECT * FROM config WHERE id=1`;
      const cfg = c[0] || {};
      if (cfg.killswitch) return res.json({ ok: false, error: 'killswitch_active' });
      if (cfg.maintenance) return res.json({ ok: false, error: 'maintenance' });

      const { key, hwid, device_model='', device_brand='', android_ver='' } = body;
      if (!key || !hwid) return res.json({ ok: false, error: 'missing_key_or_hwid' });

      const { rows: kr } = await sql`SELECT * FROM keys WHERE key_value=${key} LIMIT 1`;
      const k = kr[0];
      if (!k) { await log('fail', { key_value: key, hwid, message: 'invalid', ip }); return res.json({ ok: false, error: 'invalid_key' }); }
      if (k.is_revoked) { await log('fail', { key_value: key, hwid, message: 'revoked', ip }); return res.json({ ok: false, error: 'revoked' }); }
      if (k.expiry_at && new Date(k.expiry_at) < new Date()) { await log('fail', { key_value: key, hwid, message: 'expired', ip }); return res.json({ ok: false, error: 'expired' }); }

      const { rows: br } = await sql`SELECT 1 FROM devices WHERE hwid=${hwid} AND is_banned=TRUE LIMIT 1`;
      if (br[0]) { await log('fail', { key_value: key, hwid, message: 'banned', ip }); return res.json({ ok: false, error: 'banned' }); }

      const { rows: dr } = await sql`SELECT * FROM devices WHERE key_id=${k.id} AND hwid=${hwid} LIMIT 1`;
      if (dr[0]) {
        await sql`UPDATE devices SET last_seen=NOW(), last_ip=${ip}, device_model=${device_model},
          device_brand=${device_brand}, android_ver=${android_ver} WHERE id=${dr[0].id}`;
      } else {
        if (k.used_devices >= k.max_devices) {
          await log('fail', { key_value: key, hwid, message: 'device_limit', ip });
          return res.json({ ok: false, error: 'device_limit_reached' });
        }
        await sql`INSERT INTO devices (key_id, hwid, device_model, device_brand, android_ver, last_ip)
          VALUES (${k.id}, ${hwid}, ${device_model}, ${device_brand}, ${android_ver}, ${ip})`;
        await sql`UPDATE keys SET used_devices=used_devices+1 WHERE id=${k.id}`;
      }
      await log('login', { key_value: key, hwid, message: 'ok', ip });
      return res.json({ ok: true, message: 'login_success', broadcast: cfg.broadcast_msg || '' });
    }

    // ---- admin only below ----
    if (!checkAdmin(req)) return res.status(401).json({ ok: false, error: 'unauthorized' });

    // ============ GENERATE ============
    if (path === 'key/generate' && req.method === 'POST') {
      const { max_devices=1, expiry_days=30, count=1, note='' } = body;
      const expiry = expiry_days > 0 ? new Date(Date.now() + expiry_days * 86400000) : null;
      const keys = [];
      for (let i = 0; i < Math.min(count, 500); i++) {
        const k = genKey();
        await sql`INSERT INTO keys (key_value, max_devices, expiry_at, note)
          VALUES (${k}, ${max_devices}, ${expiry}, ${note})`;
        keys.push(k);
      }
      await log('generate', { message: `${keys.length} keys` });
      return res.json({ ok: true, keys });
    }

    // ============ REVOKE ============
    if (path === 'key/revoke' && req.method === 'POST') {
      await sql`UPDATE keys SET is_revoked=TRUE WHERE key_value=${body.key}`;
      await log('revoke', { key_value: body.key });
      return res.json({ ok: true });
    }

    // ============ UNREVOKE ============
    if (path === 'key/unrevoke' && req.method === 'POST') {
      await sql`UPDATE keys SET is_revoked=FALSE WHERE key_value=${body.key}`;
      await log('unrevoke', { key_value: body.key });
      return res.json({ ok: true });
    }

    // ============ EXTEND ============
    if (path === 'key/extend' && req.method === 'POST') {
      await sql`UPDATE keys SET expiry_at = COALESCE(expiry_at, NOW()) + (${body.days} || ' days')::interval
        WHERE key_value=${body.key}`;
      await log('extend', { key_value: body.key, message: `+${body.days}d` });
      return res.json({ ok: true });
    }

    // ============ REGENERATE ============
    if (path === 'key/regenerate' && req.method === 'POST') {
      const { rows } = await sql`SELECT id FROM keys WHERE key_value=${body.old_key} LIMIT 1`;
      if (!rows[0]) return res.status(404).json({ ok: false, error: 'not_found' });
      const nk = genKey();
      await sql`UPDATE keys SET key_value=${nk}, used_devices=0, is_revoked=FALSE WHERE id=${rows[0].id}`;
      await log('regenerate', { key_value: nk });
      return res.json({ ok: true, new_key: nk });
    }

    // ============ RESET HWID ============
    if (path === 'key/reset-hwid' && req.method === 'POST') {
      const { rows } = await sql`SELECT id FROM keys WHERE key_value=${body.key} LIMIT 1`;
      if (!rows[0]) return res.status(404).json({ ok: false, error: 'not_found' });
      await sql`DELETE FROM devices WHERE key_id=${rows[0].id}`;
      await sql`UPDATE keys SET used_devices=0 WHERE id=${rows[0].id}`;
      await log('reset-hwid', { key_value: body.key });
      return res.json({ ok: true });
    }

    // ============ DELETE KEY ============
    if (path === 'key/delete' && req.method === 'POST') {
      await sql`DELETE FROM keys WHERE key_value=${body.key}`;
      await log('delete', { key_value: body.key });
      return res.json({ ok: true });
    }

    // ============ DASHBOARD ============
    if (path === 'admin/dashboard') {
      const stats = {};
      stats.totalKeys    = (await sql`SELECT COUNT(*)::int c FROM keys`).rows[0].c;
      stats.activeKeys   = (await sql`SELECT COUNT(*)::int c FROM keys WHERE is_revoked=FALSE AND (expiry_at IS NULL OR expiry_at>NOW())`).rows[0].c;
      stats.expiredKeys  = (await sql`SELECT COUNT(*)::int c FROM keys WHERE expiry_at IS NOT NULL AND expiry_at<NOW()`).rows[0].c;
      stats.revokedKeys  = (await sql`SELECT COUNT(*)::int c FROM keys WHERE is_revoked=TRUE`).rows[0].c;
      stats.totalDevices = (await sql`SELECT COUNT(*)::int c FROM devices`).rows[0].c;
      stats.bannedDevices= (await sql`SELECT COUNT(*)::int c FROM devices WHERE is_banned=TRUE`).rows[0].c;
      stats.lifetimeKeys = (await sql`SELECT COUNT(*)::int c FROM keys WHERE expiry_at IS NULL`).rows[0].c;

      const keys = (await sql`SELECT * FROM keys ORDER BY created_at DESC LIMIT 200`).rows;
      const logs = (await sql`SELECT * FROM logs ORDER BY created_at DESC LIMIT 200`).rows;
      const devices = (await sql`SELECT d.*, k.key_value FROM devices d
        JOIN keys k ON k.id = d.key_id ORDER BY d.last_seen DESC LIMIT 200`).rows;
      const cfg  = (await sql`SELECT * FROM config WHERE id=1`).rows[0];

      return res.json({ ok: true, stats, keys, logs, devices, config: cfg });
    }

    // ============ KILLSWITCH ============
    if (path === 'admin/killswitch' && req.method === 'POST') {
      if (typeof body.killswitch === 'boolean')
        await sql`UPDATE config SET killswitch=${body.killswitch} WHERE id=1`;
      if (typeof body.maintenance === 'boolean')
        await sql`UPDATE config SET maintenance=${body.maintenance} WHERE id=1`;
      return res.json({ ok: true });
    }

    // ============ BROADCAST ============
    if (path === 'admin/broadcast' && req.method === 'POST') {
      await sql`UPDATE config SET broadcast_msg=${body.message || ''} WHERE id=1`;
      return res.json({ ok: true });
    }

    // ============ BAN / UNBAN ============
    if (path === 'admin/ban' && req.method === 'POST') {
      await sql`UPDATE devices SET is_banned=${!!body.ban} WHERE hwid=${body.hwid}`;
      await log(body.ban ? 'ban' : 'unban', { hwid: body.hwid });
      return res.json({ ok: true });
    }

    // ============ CLEAR LOGS ============
    if (path === 'admin/clear-logs' && req.method === 'POST') {
      await sql`DELETE FROM logs`;
      return res.json({ ok: true });
    }

    return res.status(404).json({ ok: false, error: 'not_found: ' + path });
  } catch (e) {
    console.error('API error:', e);
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
}
