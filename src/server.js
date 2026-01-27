import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs/promises';

import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { z } from 'zod';

dotenv.config();

const app = express();
app.set('trust proxy', 1);

const port = Number(process.env.PORT) || 5000;
const nodeEnv = process.env.NODE_ENV || 'development';
const corsOriginRaw = process.env.CORS_ORIGIN || 'http://localhost:8080';
const corsOrigins = corsOriginRaw
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

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

    const dataDir = path.join(process.cwd(), 'data');
    const outPath = path.join(dataDir, 'messages.ndjson');

    await fs.mkdir(dataDir, { recursive: true });
    await fs.appendFile(outPath, `${JSON.stringify(record)}\n`);

    res.status(201).json({ ok: true, id: record.id });
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

app.listen(port, () => {
  console.log(`API running on http://localhost:${port}`);
});
