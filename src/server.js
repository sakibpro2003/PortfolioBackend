import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { z } from 'zod';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const app = express();
app.set('trust proxy', 1);

const port = Number(process.env.PORT) || 5000;
const nodeEnv = process.env.NODE_ENV || 'development';
const corsOriginRaw = process.env.CORS_ORIGIN || 'http://localhost:8080';
const adminUsername = process.env.ADMIN_USERNAME || '';
const adminPassword = process.env.ADMIN_PASSWORD || '';
const adminTokenTtlMinutes = Number(process.env.ADMIN_TOKEN_TTL_MINUTES) || 60;
const corsOrigins = corsOriginRaw
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const getDataDir = () =>
  process.env.VERCEL ? path.join('/tmp', 'data') : path.join(process.cwd(), 'data');

if (nodeEnv === 'production' && (!adminUsername || !adminPassword)) {
  throw new Error('Missing ADMIN_USERNAME or ADMIN_PASSWORD in environment');
}

app.use(helmet());
app.use(morgan(nodeEnv === 'production' ? 'combined' : 'dev'));
app.use(express.json({ limit: '10kb' }));
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || corsOrigins.includes('*') || corsOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error('CORS blocked'));
    },
    credentials: true,
  })
);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', apiLimiter);

const contactSchema = z.object({
  name: z.string().trim().min(2).max(100),
  email: z.string().trim().email().max(200),
  message: z.string().trim().min(10).max(2000),
});

const adminLoginSchema = z.object({
  username: z.string().trim().min(1).max(100),
  password: z.string().min(1).max(200),
});

const adminSessions = new Map();

const safeEqual = (left, right) => {
  const leftBuf = Buffer.from(left);
  const rightBuf = Buffer.from(right);
  if (leftBuf.length !== rightBuf.length) {
    const maxLength = Math.max(leftBuf.length, rightBuf.length);
    const paddedLeft = Buffer.alloc(maxLength);
    const paddedRight = Buffer.alloc(maxLength);
    leftBuf.copy(paddedLeft);
    rightBuf.copy(paddedRight);
    crypto.timingSafeEqual(paddedLeft, paddedRight);
    return false;
  }
  return crypto.timingSafeEqual(leftBuf, rightBuf);
};

const authenticateAdmin = (username, password) =>
  safeEqual(username, adminUsername) && safeEqual(password, adminPassword);

const requireAdminAuth = (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    res.status(401).json({ error: 'Missing admin token' });
    return;
  }

  const token = match[1];
  const session = adminSessions.get(token);
  if (!session) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  if (session.expiresAt <= Date.now()) {
    adminSessions.delete(token);
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  req.admin = { username: session.username };
  req.adminToken = token;
  next();
};

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    time: new Date().toISOString(),
    uptime: Math.round(process.uptime()),
  });
});

app.post('/api/contact', async (req, res, next) => {
  try {
    const payload = contactSchema.parse(req.body);
    const record = {
      id: crypto.randomUUID(),
      ...payload,
      createdAt: new Date().toISOString(),
    };

    const dataDir = getDataDir();
    const outPath = path.join(dataDir, 'messages.ndjson');

    await fs.mkdir(dataDir, { recursive: true });
    await fs.appendFile(outPath, `${JSON.stringify(record)}\n`);

    res.status(201).json({ ok: true, id: record.id });
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/login', (req, res, next) => {
  try {
    if (!adminUsername || !adminPassword) {
      res.status(500).json({ error: 'Admin credentials not configured' });
      return;
    }

    const { username, password } = adminLoginSchema.parse(req.body);
    if (!authenticateAdmin(username, password)) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAtMs = Date.now() + adminTokenTtlMinutes * 60 * 1000;
    adminSessions.set(token, { username, expiresAt: expiresAtMs });

    res.json({
      ok: true,
      token,
      expiresAt: new Date(expiresAtMs).toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/logout', requireAdminAuth, (req, res) => {
  adminSessions.delete(req.adminToken);
  res.json({ ok: true });
});

app.get('/api/admin/messages', requireAdminAuth, async (req, res, next) => {
  try {
    const limitRaw = Number(req.query.limit);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 500) : 200;
    const dataDir = getDataDir();
    const outPath = path.join(dataDir, 'messages.ndjson');

    let raw = '';
    try {
      raw = await fs.readFile(outPath, 'utf8');
    } catch (error) {
      if (error && error.code === 'ENOENT') {
        res.json({ ok: true, messages: [] });
        return;
      }
      throw error;
    }

    const messages = raw
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .slice(-limit)
      .reverse();

    res.json({ ok: true, messages });
  } catch (error) {
    next(error);
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((error, req, res, next) => {
  if (error instanceof z.ZodError) {
    res.status(400).json({
      error: 'Validation error',
      details: error.flatten(),
    });
    return;
  }

  if (error instanceof Error && error.message === 'CORS blocked') {
    res.status(403).json({ error: 'CORS blocked' });
    return;
  }

  console.error(error);
  res.status(500).json({ error: 'Server error' });
});

if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`API running on http://localhost:${port}`);
  });
}

export default app;
