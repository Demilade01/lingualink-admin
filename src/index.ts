import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pino from 'pino';
import swaggerUi from 'swagger-ui-express';
import swaggerJSDoc from 'swagger-jsdoc';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

// Logger
const logger = pino({ transport: process.env.NODE_ENV !== 'production' ? { target: 'pino-pretty' } : undefined });

// Env
const PORT = Number(process.env.PORT || 4000);
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const SUPABASE_URL = process.env.SUPABASE_URL as string;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY as string;
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET as string;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  logger.warn('Supabase admin env not set. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.');
}
if (!ADMIN_JWT_SECRET) {
  logger.warn('ADMIN_JWT_SECRET is not set. Admin auth will fail.');
}

// Supabase admin client
export const supabaseAdmin = createClient(SUPABASE_URL || '', SUPABASE_SERVICE_ROLE_KEY || '', {
  auth: { persistSession: false, autoRefreshToken: false },
});

// Swagger setup
const swaggerSpec = swaggerJSDoc({
  definition: {
    openapi: '3.0.3',
    info: { title: 'LinguaLink Admin API', version: '1.0.0' },
    servers: [{ url: `http://localhost:${PORT}` }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: [],
});

// Express app
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(helmet());
app.use(cors({ origin: CORS_ORIGINS.length ? CORS_ORIGINS : true }));
app.set('trust proxy', 1);

// Rate limiter
const limiter = rateLimit({ windowMs: 60_000, max: 120 });
app.use(limiter);

// Health
app.get('/health', (_req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

// Swagger UI (protect in prod if desired)
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Admin guard middleware
function adminGuard(req: express.Request, res: express.Response, next: express.NextFunction) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : undefined;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const payload = jwt.verify(token, ADMIN_JWT_SECRET) as { sub?: string; role?: string };
    if (!payload || (payload.role !== 'admin' && payload.role !== 'superadmin')) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    (req as any).admin = payload;
    next();
  } catch (e: any) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Example protected route
app.get('/admin/overview', adminGuard, async (_req, res) => {
  try {
    // Simple sanity stats (can switch to MVs later)
    const { count: usersCount } = await supabaseAdmin.from('profiles').select('id', { count: 'exact', head: true });
    res.json({ usersCount: usersCount ?? 0 });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load overview' });
  }
});

// Start
app.listen(PORT, () => {
  logger.info({ port: PORT }, 'Admin API listening');
});
