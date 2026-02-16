import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { all, get, initDb, run } from './db.js';
import { config } from './config.js';

const app = express();

const noteSchema = z.object({
  title: z.string().max(240).default(''),
  content: z.string().max(50000).default(''),
  color: z.string().regex(/^#[0-9a-fA-F]{6}$/).default('#ffffff'),
  pinned: z.boolean().default(false),
  archived: z.boolean().default(false),
  tags: z.array(z.string().min(1).max(40)).max(50).default([]),
  checklist: z.array(z.object({ text: z.string().min(1).max(200), done: z.boolean().default(false) })).max(200).default([])
});

const registerSchema = z.object({ email: z.string().email().max(254), password: z.string().min(10).max(128) });
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1).max(128) });

const jsonImportSchema = z.object({ notes: z.array(noteSchema.partial()).max(5000) });
const markdownImportSchema = z.object({ files: z.array(z.object({ path: z.string().min(1), content: z.string() })).max(5000) });
const keepImportSchema = z.object({ notes: z.array(z.object({
  title: z.string().optional(),
  text: z.string().optional(),
  color: z.string().optional(),
  pinned: z.boolean().optional(),
  archived: z.boolean().optional(),
  labels: z.array(z.string()).optional(),
  checklist: z.array(z.object({ text: z.string(), checked: z.boolean().optional() })).optional()
})).max(5000) });

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || config.clientOrigin.includes(origin)) return callback(null, true);
    return callback(new Error('CORS blocked'));
  },
  credentials: true
}));
app.use(express.json({ limit: config.payloadLimit }));
app.use(cookieParser());

app.use(rateLimit({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax, standardHeaders: true, legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: config.rateLimitWindowMs, max: config.authRateLimitMax, standardHeaders: true, legacyHeaders: false });

function sanitizeNote(input = {}) {
  const parsed = noteSchema.parse(input);
  return {
    title: parsed.title,
    content: parsed.content,
    color: parsed.color,
    pinned: parsed.pinned ? 1 : 0,
    archived: parsed.archived ? 1 : 0,
    tags: JSON.stringify(parsed.tags),
    checklist: JSON.stringify(parsed.checklist)
  };
}

function rowToNote(row) {
  return {
    ...row,
    pinned: !!row.pinned,
    archived: !!row.archived,
    tags: JSON.parse(row.tags || '[]'),
    checklist: JSON.parse(row.checklist || '[]')
  };
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function issueAccessToken(user) {
  return jwt.sign({ sub: String(user.id), role: user.role, email: user.email, type: 'access' }, config.jwtAccessSecret, {
    expiresIn: config.accessTokenTtlSec
  });
}

async function issueRefreshToken(user, req, replacedByTokenId = null) {
  const tokenId = crypto.randomUUID();
  const token = jwt.sign({ sub: String(user.id), role: user.role, jti: tokenId, type: 'refresh' }, config.jwtRefreshSecret, {
    expiresIn: config.refreshTokenTtlSec
  });
  const expiresAt = new Date(Date.now() + config.refreshTokenTtlSec * 1000).toISOString();
  await run(
    `INSERT INTO sessions (user_id, token_id, token_hash, user_agent, ip_address, created_at, expires_at, replaced_by_token_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [user.id, tokenId, tokenHash(token), req.headers['user-agent'] || null, req.ip || null, new Date().toISOString(), expiresAt, replacedByTokenId]
  );
  return token;
}

async function audit(eventType, detail, userId, req) {
  await run('INSERT INTO audit_logs (user_id, event_type, detail, ip_address, created_at) VALUES (?, ?, ?, ?, ?)', [
    userId || null,
    eventType,
    detail || null,
    req?.ip || null,
    new Date().toISOString()
  ]).catch(() => undefined);
}

function setRefreshCookie(res, token) {
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: config.cookieSameSite,
    maxAge: config.refreshTokenTtlSec * 1000,
    path: '/auth'
  });
}

function clearRefreshCookie(res) {
  res.clearCookie('refresh_token', { path: '/auth' });
}

function getBearer(req) {
  const value = req.headers.authorization || '';
  if (!value.startsWith('Bearer ')) return null;
  return value.slice(7);
}

async function requireAuth(req, _res, next) {
  try {
    const token = getBearer(req);
    if (!token) throw Object.assign(new Error('Missing token'), { status: 401 });
    const payload = jwt.verify(token, config.jwtAccessSecret);
    if (payload.type !== 'access') throw Object.assign(new Error('Invalid token type'), { status: 401 });
    req.user = { id: Number(payload.sub), role: payload.role, email: payload.email };
    return next();
  } catch {
    return next(Object.assign(new Error('Unauthorized'), { status: 401 }));
  }
}

function requireRole(role) {
  return (req, _res, next) => {
    if (!req.user || req.user.role !== role) {
      return next(Object.assign(new Error('Forbidden'), { status: 403 }));
    }
    return next();
  };
}

app.get('/health', async (_req, res) => {
  const row = await get('SELECT 1 as ok');
  res.json({ ok: !!row?.ok });
});

app.post('/auth/register', authLimiter, async (req, res, next) => {
  try {
    const body = registerSchema.parse(req.body);
    const existing = await get('SELECT id FROM users WHERE email = ?', [body.email.toLowerCase()]);
    if (existing) throw Object.assign(new Error('Email already registered'), { status: 409 });
    const hash = await bcrypt.hash(body.password, config.bcryptRounds);
    const now = new Date().toISOString();
    const role = (await get('SELECT COUNT(*) as count FROM users')).count === 0 ? 'admin' : 'user';
    const result = await run('INSERT INTO users (email, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', [
      body.email.toLowerCase(), hash, role, now, now
    ]);
    const user = { id: result.id, email: body.email.toLowerCase(), role };
    const accessToken = issueAccessToken(user);
    const refreshToken = await issueRefreshToken(user, req);
    setRefreshCookie(res, refreshToken);
    await audit('auth.register', `role=${role}`, user.id, req);
    return res.status(201).json({ user, accessToken, refreshToken });
  } catch (err) {
    return next(err);
  }
});

app.post('/auth/login', authLimiter, async (req, res, next) => {
  try {
    const body = loginSchema.parse(req.body);
    const user = await get('SELECT * FROM users WHERE email = ?', [body.email.toLowerCase()]);
    if (!user) {
      await audit('auth.login.failed', 'user_not_found', null, req);
      throw Object.assign(new Error('Invalid credentials'), { status: 401 });
    }
    const ok = await bcrypt.compare(body.password, user.password_hash);
    if (!ok) {
      await audit('auth.login.failed', 'bad_password', user.id, req);
      throw Object.assign(new Error('Invalid credentials'), { status: 401 });
    }
    const safeUser = { id: user.id, email: user.email, role: user.role };
    const accessToken = issueAccessToken(safeUser);
    const refreshToken = await issueRefreshToken(safeUser, req);
    setRefreshCookie(res, refreshToken);
    await audit('auth.login.success', null, user.id, req);
    return res.json({ user: safeUser, accessToken, refreshToken });
  } catch (err) {
    return next(err);
  }
});

app.post('/auth/refresh', async (req, res, next) => {
  try {
    const token = req.cookies.refresh_token || req.body?.refreshToken;
    if (!token) throw Object.assign(new Error('Missing refresh token'), { status: 401 });
    const payload = jwt.verify(token, config.jwtRefreshSecret);
    if (payload.type !== 'refresh') throw Object.assign(new Error('Invalid token'), { status: 401 });

    const session = await get('SELECT * FROM sessions WHERE token_id = ?', [payload.jti]);
    if (!session || session.revoked_at || session.token_hash !== tokenHash(token)) {
      throw Object.assign(new Error('Session revoked'), { status: 401 });
    }

    await run('UPDATE sessions SET revoked_at = ?, replaced_by_token_id = ? WHERE token_id = ?', [
      new Date().toISOString(), 'rotated', payload.jti
    ]);

    const user = await get('SELECT id, email, role FROM users WHERE id = ?', [Number(payload.sub)]);
    if (!user) throw Object.assign(new Error('User not found'), { status: 401 });

    const accessToken = issueAccessToken(user);
    const refreshToken = await issueRefreshToken(user, req, payload.jti);
    setRefreshCookie(res, refreshToken);
    await audit('auth.refresh', null, user.id, req);
    return res.json({ user, accessToken, refreshToken });
  } catch (err) {
    return next(Object.assign(new Error('Invalid refresh token'), { status: 401 }));
  }
});

app.post('/auth/logout', requireAuth, async (req, res, next) => {
  try {
    const provided = req.cookies.refresh_token || req.body?.refreshToken;
    if (provided) {
      const decoded = jwt.decode(provided);
      if (decoded?.jti) {
        await run('UPDATE sessions SET revoked_at = ? WHERE token_id = ? AND user_id = ?', [
          new Date().toISOString(), decoded.jti, req.user.id
        ]);
      }
    } else {
      await run('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL', [new Date().toISOString(), req.user.id]);
    }
    clearRefreshCookie(res);
    await audit('auth.logout', null, req.user.id, req);
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  const user = await get('SELECT id, email, role FROM users WHERE id = ?', [req.user.id]);
  res.json({ user });
});

app.get('/admin/users', requireAuth, requireRole('admin'), async (_req, res) => {
  const users = await all('SELECT id, email, role, created_at FROM users ORDER BY created_at DESC');
  res.json({ users });
});

app.get('/notes', requireAuth, async (req, res, next) => {
  try {
    const q = (req.query.q || '').toLowerCase().trim();
    const archived = req.query.archived;
    let rows = await all('SELECT * FROM notes WHERE user_id = ? ORDER BY pinned DESC, updated_at DESC', [req.user.id]);
    rows = rows.map(rowToNote);
    if (archived === 'true') rows = rows.filter((n) => n.archived);
    if (archived === 'false') rows = rows.filter((n) => !n.archived);
    if (q) {
      rows = rows.filter((n) => `${n.title} ${n.content} ${n.tags.join(' ')} ${n.checklist.map((i) => i.text).join(' ')}`.toLowerCase().includes(q));
    }
    return res.json(rows);
  } catch (err) {
    return next(err);
  }
});

app.get('/notes/:id', requireAuth, async (req, res, next) => {
  try {
    const row = await get('SELECT * FROM notes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!row) throw Object.assign(new Error('Note not found'), { status: 404 });
    return res.json(rowToNote(row));
  } catch (err) {
    return next(err);
  }
});

app.post('/notes', requireAuth, async (req, res, next) => {
  try {
    const note = sanitizeNote(req.body);
    const now = new Date().toISOString();
    const result = await run(
      `INSERT INTO notes (user_id, title, content, color, pinned, archived, tags, checklist, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, note.title, note.content, note.color, note.pinned, note.archived, note.tags, note.checklist, now, now]
    );
    const row = await get('SELECT * FROM notes WHERE id = ? AND user_id = ?', [result.id, req.user.id]);
    return res.status(201).json(rowToNote(row));
  } catch (err) {
    return next(err);
  }
});

app.put('/notes/:id', requireAuth, async (req, res, next) => {
  try {
    const existing = await get('SELECT * FROM notes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!existing) throw Object.assign(new Error('Note not found'), { status: 404 });
    const merged = noteSchema.partial().parse({ ...rowToNote(existing), ...req.body });
    const note = sanitizeNote(merged);
    await run(
      `UPDATE notes
       SET title = ?, content = ?, color = ?, pinned = ?, archived = ?, tags = ?, checklist = ?, updated_at = ?
       WHERE id = ? AND user_id = ?`,
      [note.title, note.content, note.color, note.pinned, note.archived, note.tags, note.checklist, new Date().toISOString(), req.params.id, req.user.id]
    );
    const row = await get('SELECT * FROM notes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    return res.json(rowToNote(row));
  } catch (err) {
    return next(err);
  }
});

app.delete('/notes/:id', requireAuth, async (req, res, next) => {
  try {
    const result = await run('DELETE FROM notes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!result.changes) throw Object.assign(new Error('Note not found'), { status: 404 });
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
});

app.get('/export/json', requireAuth, async (req, res) => {
  const notes = (await all('SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC', [req.user.id])).map(rowToNote);
  res.json({ exportedAt: new Date().toISOString(), notes });
});

app.post('/import/json', requireAuth, async (req, res, next) => {
  try {
    const payload = jsonImportSchema.parse(req.body);
    let count = 0;
    for (const raw of payload.notes) {
      const note = sanitizeNote(raw);
      const now = new Date().toISOString();
      await run(
        `INSERT INTO notes (user_id, title, content, color, pinned, archived, tags, checklist, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.user.id, note.title, note.content, note.color, note.pinned, note.archived, note.tags, note.checklist, now, now]
      );
      count += 1;
    }
    res.json({ imported: count });
  } catch (err) {
    next(err);
  }
});

app.get('/export/markdown', requireAuth, async (req, res) => {
  const notes = (await all('SELECT * FROM notes WHERE user_id = ?', [req.user.id])).map(rowToNote);
  const files = notes.map((n) => ({
    path: `${slug(n.title || 'untitled')}-${n.id}.md`,
    content: `# ${n.title || 'Untitled'}\n\n${n.content}\n\n---\ncolor: ${n.color}\npinned: ${n.pinned}\narchived: ${n.archived}\ntags: ${n.tags.join(',')}\nchecklist: ${JSON.stringify(n.checklist)}`
  }));
  res.json({ adapter: 'markdown-folder', files });
});

app.post('/import/markdown', requireAuth, async (req, res, next) => {
  try {
    const payload = markdownImportSchema.parse(req.body);
    let imported = 0;
    for (const file of payload.files) {
      const [head, ...rest] = file.content.split('\n');
      const title = head.replace(/^#\s*/, '').trim() || file.path;
      const body = rest.join('\n').split('\n---\n')[0] || '';
      const note = sanitizeNote({ title, content: body });
      const now = new Date().toISOString();
      await run(
        `INSERT INTO notes (user_id, title, content, color, pinned, archived, tags, checklist, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.user.id, note.title, note.content, note.color, note.pinned, note.archived, note.tags, note.checklist, now, now]
      );
      imported += 1;
    }
    res.json({ imported });
  } catch (err) {
    next(err);
  }
});

app.post('/import/keep', requireAuth, async (req, res, next) => {
  try {
    const payload = keepImportSchema.parse(req.body);
    let imported = 0;
    for (const n of payload.notes) {
      const note = sanitizeNote({
        title: n.title || '',
        content: n.text || '',
        color: /^#[0-9a-fA-F]{6}$/.test(n.color || '') ? n.color : '#ffffff',
        pinned: !!n.pinned,
        archived: !!n.archived,
        tags: n.labels || [],
        checklist: (n.checklist || []).map((i) => ({ text: i.text, done: !!i.checked }))
      });
      const now = new Date().toISOString();
      await run(
        `INSERT INTO notes (user_id, title, content, color, pinned, archived, tags, checklist, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.user.id, note.title, note.content, note.color, note.pinned, note.archived, note.tags, note.checklist, now, now]
      );
      imported += 1;
    }
    res.json({ imported, adapter: 'keep-minimal' });
  } catch (err) {
    next(err);
  }
});

function slug(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 50) || 'note';
}

app.use((err, _req, res, _next) => {
  if (err instanceof z.ZodError) return res.status(400).json({ error: 'Validation failed', issues: err.issues.map((i) => i.path.join('.')) });
  const status = err.status || 500;
  const message = status >= 500 ? 'Internal server error' : err.message;
  return res.status(status).json({ error: message });
});

export async function createServer() {
  await initDb();
  return app;
}

if (process.env.NODE_ENV !== 'test') {
  createServer().then(() => {
    app.listen(config.port, () => {
      // eslint-disable-next-line no-console
      console.log(`Backend listening on port ${config.port}`);
    });
  });
}
