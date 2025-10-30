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
    info: {
      title: 'LinguaLink Admin API',
      version: '1.0.0',
      description: 'Admin API for LinguaLink platform management including user moderation, role management, and analytics'
    },
    servers: [{ url: `http://localhost:${PORT}` }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            username: { type: 'string' },
            email: { type: 'string', format: 'email' },
            country: { type: 'string' },
            state: { type: 'string' },
            city: { type: 'string' },
            lga: { type: 'string' },
            created_at: { type: 'string', format: 'date-time' },
            updated_at: { type: 'string', format: 'date-time' },
            referral_code: { type: 'string' },
            is_banned: { type: 'boolean' },
            admin_roles: { type: 'array', items: { type: 'string' } },
            language_roles: { type: 'object' },
            referral_count: { type: 'integer' }
          }
        },
        Pagination: {
          type: 'object',
          properties: {
            page: { type: 'integer' },
            limit: { type: 'integer' },
            total: { type: 'integer' },
            pages: { type: 'integer' }
          }
        },
        AdminAction: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            admin_id: { type: 'string', format: 'uuid' },
            action: { type: 'string' },
            target_user_id: { type: 'string', format: 'uuid' },
            details: { type: 'object' },
            created_at: { type: 'string', format: 'date-time' }
          }
        }
      }
    },
    security: [{ bearerAuth: [] }],
  },
  apis: ['./src/index.ts'],
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

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check endpoint
 *     description: Returns the health status of the API
 *     tags: [System]
 *     responses:
 *       200:
 *         description: API is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 uptime:
 *                   type: number
 */
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

// ===== USER MANAGEMENT ENDPOINTS =====

/**
 * @swagger
 * /admin/users:
 *   get:
 *     summary: Get all users with filters
 *     description: Retrieve a paginated list of users with optional filtering
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *         description: Number of users per page
 *       - in: query
 *         name: banned
 *         schema:
 *           type: boolean
 *         description: Filter by banned status
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *         description: Filter by admin role
 *       - in: query
 *         name: country
 *         schema:
 *           type: string
 *         description: Filter by country
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search by username or email
 *     responses:
 *       200:
 *         description: List of users with pagination
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 users:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/User'
 *                 pagination:
 *                   $ref: '#/components/schemas/Pagination'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
app.get('/admin/users', adminGuard, async (req, res) => {
  try {
    const { page = 1, limit = 20, banned, role, country, search } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    let query = supabaseAdmin
      .from('profiles')
      .select(`
        id,
        username,
        email,
        country,
        state,
        city,
        lga,
        created_at,
        updated_at,
        referral_code,
        is_banned,
        admin_roles,
        language_roles
      `, { count: 'exact' });

    // Apply filters
    if (banned !== undefined) {
      query = query.eq('is_banned', banned === 'true');
    }
    if (role) {
      query = query.contains('admin_roles', [role]);
    }
    if (country) {
      query = query.eq('country', country);
    }
    if (search) {
      query = query.or(`username.ilike.%${search}%,email.ilike.%${search}%`);
    }

    const { data: users, error, count } = await query
      .range(offset, offset + Number(limit) - 1)
      .order('created_at', { ascending: false });

    if (error) {
      logger.error({ err: error }, 'Error fetching users');
      return res.status(500).json({ error: 'Failed to fetch users' });
    }

    res.json({
      users: users || [],
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get specific user details
app.get('/admin/users/:id', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: user, error } = await supabaseAdmin
      .from('profiles')
      .select(`
        id,
        username,
        email,
        country,
        state,
        city,
        lga,
        created_at,
        updated_at,
        referral_code,
        is_banned,
        admin_roles,
        language_roles,
        referral_count
      `)
      .eq('id', id)
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      logger.error({ err: error }, 'Error fetching user');
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    res.json({ user });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id');
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @swagger
 * /admin/users/{id}/ban:
 *   post:
 *     summary: Ban a user
 *     description: Ban a user from the platform
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: User ID to ban
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               reason:
 *                 type: string
 *                 description: Reason for banning the user
 *     responses:
 *       200:
 *         description: User banned successfully
 *       400:
 *         description: User already banned
 *       404:
 *         description: User not found
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
app.post('/admin/users/:id/ban', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    const { data: user, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, username, is_banned')
      .eq('id', id)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    if (user.is_banned) {
      return res.status(400).json({ error: 'User is already banned' });
    }

    const { error: updateError } = await supabaseAdmin
      .from('profiles')
      .update({
        is_banned: true,
        ban_reason: reason,
        banned_at: new Date().toISOString()
      })
      .eq('id', id);

    if (updateError) {
      logger.error({ err: updateError }, 'Error banning user');
      return res.status(500).json({ error: 'Failed to ban user' });
    }

    // Log admin action
    await supabaseAdmin
      .from('admin_actions')
      .insert({
        admin_id: (req as any).admin?.sub,
        action: 'ban_user',
        target_user_id: id,
        details: { reason },
        created_at: new Date().toISOString()
      });

    res.json({ message: 'User banned successfully' });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id/ban');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Unban user
app.post('/admin/users/:id/unban', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: user, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, username, is_banned')
      .eq('id', id)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    if (!user.is_banned) {
      return res.status(400).json({ error: 'User is not banned' });
    }

    const { error: updateError } = await supabaseAdmin
      .from('profiles')
      .update({
        is_banned: false,
        ban_reason: null,
        banned_at: null
      })
      .eq('id', id);

    if (updateError) {
      logger.error({ err: updateError }, 'Error unbanning user');
      return res.status(500).json({ error: 'Failed to unban user' });
    }

    // Log admin action
    await supabaseAdmin
      .from('admin_actions')
      .insert({
        admin_id: (req as any).admin?.sub,
        action: 'unban_user',
        target_user_id: id,
        details: {},
        created_at: new Date().toISOString()
      });

    res.json({ message: 'User unbanned successfully' });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id/unban');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Promote user to admin
app.post('/admin/users/:id/promote', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { role = 'admin' } = req.body;

    if (!['admin', 'superadmin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Must be admin or superadmin' });
    }

    const { data: user, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, username, admin_roles')
      .eq('id', id)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    const currentRoles = user.admin_roles || [];
    if (currentRoles.includes(role)) {
      return res.status(400).json({ error: `User already has ${role} role` });
    }

    const { error: updateError } = await supabaseAdmin
      .from('profiles')
      .update({
        admin_roles: [...currentRoles, role]
      })
      .eq('id', id);

    if (updateError) {
      logger.error({ err: updateError }, 'Error promoting user');
      return res.status(500).json({ error: 'Failed to promote user' });
    }

    // Log admin action
    await supabaseAdmin
      .from('admin_actions')
      .insert({
        admin_id: (req as any).admin?.sub,
        action: 'promote_user',
        target_user_id: id,
        details: { role },
        created_at: new Date().toISOString()
      });

    res.json({ message: `User promoted to ${role} successfully` });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id/promote');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Demote user from admin
app.post('/admin/users/:id/demote', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { role = 'admin' } = req.body;

    const { data: user, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, username, admin_roles')
      .eq('id', id)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    const currentRoles = user.admin_roles || [];
    if (!currentRoles.includes(role)) {
      return res.status(400).json({ error: `User does not have ${role} role` });
    }

    const { error: updateError } = await supabaseAdmin
      .from('profiles')
      .update({
        admin_roles: currentRoles.filter((r: string) => r !== role)
      })
      .eq('id', id);

    if (updateError) {
      logger.error({ err: updateError }, 'Error demoting user');
      return res.status(500).json({ error: 'Failed to demote user' });
    }

    // Log admin action
    await supabaseAdmin
      .from('admin_actions')
      .insert({
        admin_id: (req as any).admin?.sub,
        action: 'demote_user',
        target_user_id: id,
        details: { role },
        created_at: new Date().toISOString()
      });

    res.json({ message: `User demoted from ${role} successfully` });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id/demote');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===== LANGUAGE ROLE MANAGEMENT ENDPOINTS =====

// Grant validator role for specific language
app.post('/admin/users/:id/roles/validator', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { language } = req.body;

    if (!language) {
      return res.status(400).json({ error: 'Language is required' });
    }

    const { data: user, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, username, language_roles')
      .eq('id', id)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    const currentRoles = user.language_roles || {};
    if (currentRoles[language]?.includes('validator')) {
      return res.status(400).json({ error: `User already has validator role for ${language}` });
    }

    const updatedRoles = {
      ...currentRoles,
      [language]: [...(currentRoles[language] || []), 'validator']
    };

    const { error: updateError } = await supabaseAdmin
      .from('profiles')
      .update({ language_roles: updatedRoles })
      .eq('id', id);

    if (updateError) {
      logger.error({ err: updateError }, 'Error granting validator role');
      return res.status(500).json({ error: 'Failed to grant validator role' });
    }

    // Log admin action
    await supabaseAdmin
      .from('admin_actions')
      .insert({
        admin_id: (req as any).admin?.sub,
        action: 'grant_validator_role',
        target_user_id: id,
        details: { language },
        created_at: new Date().toISOString()
      });

    res.json({ message: `Validator role granted for ${language} successfully` });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id/roles/validator');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Grant ambassador role for specific language
app.post('/admin/users/:id/roles/ambassador', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { language } = req.body;

    if (!language) {
      return res.status(400).json({ error: 'Language is required' });
    }

    const { data: user, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, username, language_roles')
      .eq('id', id)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    const currentRoles = user.language_roles || {};
    if (currentRoles[language]?.includes('ambassador')) {
      return res.status(400).json({ error: `User already has ambassador role for ${language}` });
    }

    const updatedRoles = {
      ...currentRoles,
      [language]: [...(currentRoles[language] || []), 'ambassador']
    };

    const { error: updateError } = await supabaseAdmin
      .from('profiles')
      .update({ language_roles: updatedRoles })
      .eq('id', id);

    if (updateError) {
      logger.error({ err: updateError }, 'Error granting ambassador role');
      return res.status(500).json({ error: 'Failed to grant ambassador role' });
    }

    // Log admin action
    await supabaseAdmin
      .from('admin_actions')
      .insert({
        admin_id: (req as any).admin?.sub,
        action: 'grant_ambassador_role',
        target_user_id: id,
        details: { language },
        created_at: new Date().toISOString()
      });

    res.json({ message: `Ambassador role granted for ${language} successfully` });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id/roles/ambassador');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Revoke validator role
app.delete('/admin/users/:id/roles/validator', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { language } = req.body;

    if (!language) {
      return res.status(400).json({ error: 'Language is required' });
    }

    const { data: user, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, username, language_roles')
      .eq('id', id)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    const currentRoles = user.language_roles || {};
    if (!currentRoles[language]?.includes('validator')) {
      return res.status(400).json({ error: `User does not have validator role for ${language}` });
    }

    const updatedRoles = {
      ...currentRoles,
      [language]: currentRoles[language].filter((role: string) => role !== 'validator')
    };

    const { error: updateError } = await supabaseAdmin
      .from('profiles')
      .update({ language_roles: updatedRoles })
      .eq('id', id);

    if (updateError) {
      logger.error({ err: updateError }, 'Error revoking validator role');
      return res.status(500).json({ error: 'Failed to revoke validator role' });
    }

    // Log admin action
    await supabaseAdmin
      .from('admin_actions')
      .insert({
        admin_id: (req as any).admin?.sub,
        action: 'revoke_validator_role',
        target_user_id: id,
        details: { language },
        created_at: new Date().toISOString()
      });

    res.json({ message: `Validator role revoked for ${language} successfully` });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id/roles/validator');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Revoke ambassador role
app.delete('/admin/users/:id/roles/ambassador', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { language } = req.body;

    if (!language) {
      return res.status(400).json({ error: 'Language is required' });
    }

    const { data: user, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, username, language_roles')
      .eq('id', id)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(500).json({ error: 'Failed to fetch user' });
    }

    const currentRoles = user.language_roles || {};
    if (!currentRoles[language]?.includes('ambassador')) {
      return res.status(400).json({ error: `User does not have ambassador role for ${language}` });
    }

    const updatedRoles = {
      ...currentRoles,
      [language]: currentRoles[language].filter((role: string) => role !== 'ambassador')
    };

    const { error: updateError } = await supabaseAdmin
      .from('profiles')
      .update({ language_roles: updatedRoles })
      .eq('id', id);

    if (updateError) {
      logger.error({ err: updateError }, 'Error revoking ambassador role');
      return res.status(500).json({ error: 'Failed to revoke ambassador role' });
    }

    // Log admin action
    await supabaseAdmin
      .from('admin_actions')
      .insert({
        admin_id: (req as any).admin?.sub,
        action: 'revoke_ambassador_role',
        target_user_id: id,
        details: { language },
        created_at: new Date().toISOString()
      });

    res.json({ message: `Ambassador role revoked for ${language} successfully` });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/users/:id/roles/ambassador');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===== STATISTICS ENDPOINTS =====

/**
 * @swagger
 * /admin/stats/overview:
 *   get:
 *     summary: Get platform overview statistics
 *     description: Retrieve general platform statistics including user counts
 *     tags: [Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Platform overview statistics
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 totalUsers:
 *                   type: integer
 *                   description: Total number of users
 *                 activeUsers:
 *                   type: integer
 *                   description: Number of active (non-banned) users
 *                 bannedUsers:
 *                   type: integer
 *                   description: Number of banned users
 *                 recentUsers:
 *                   type: integer
 *                   description: Number of users created in last 30 days
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
app.get('/admin/stats/overview', adminGuard, async (req, res) => {
  try {
    const { data: users, error: usersError } = await supabaseAdmin
      .from('profiles')
      .select('id, created_at, is_banned', { count: 'exact' });

    if (usersError) {
      logger.error({ err: usersError }, 'Error fetching user stats');
      return res.status(500).json({ error: 'Failed to fetch user statistics' });
    }

    const totalUsers = users?.length || 0;
    const bannedUsers = users?.filter(u => u.is_banned).length || 0;
    const activeUsers = totalUsers - bannedUsers;

    // Get users created in last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const recentUsers = users?.filter(u => new Date(u.created_at) > thirtyDaysAgo).length || 0;

    res.json({
      totalUsers,
      activeUsers,
      bannedUsers,
      recentUsers,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/stats/overview');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Language rankings
app.get('/admin/stats/languages', adminGuard, async (req, res) => {
  try {
    const { data: users, error } = await supabaseAdmin
      .from('profiles')
      .select('language_roles');

    if (error) {
      logger.error({ err: error }, 'Error fetching language stats');
      return res.status(500).json({ error: 'Failed to fetch language statistics' });
    }

    const languageCounts: Record<string, number> = {};

    users?.forEach(user => {
      if (user.language_roles) {
        Object.keys(user.language_roles).forEach(language => {
          languageCounts[language] = (languageCounts[language] || 0) + 1;
        });
      }
    });

    const languageRankings = Object.entries(languageCounts)
      .map(([language, count]) => ({ language, count }))
      .sort((a, b) => b.count - a.count);

    res.json({
      rankings: languageRankings,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/stats/languages');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Country rankings
app.get('/admin/stats/countries', adminGuard, async (req, res) => {
  try {
    const { data: users, error } = await supabaseAdmin
      .from('profiles')
      .select('country')
      .not('country', 'is', null);

    if (error) {
      logger.error({ err: error }, 'Error fetching country stats');
      return res.status(500).json({ error: 'Failed to fetch country statistics' });
    }

    const countryCounts: Record<string, number> = {};

    users?.forEach(user => {
      if (user.country) {
        countryCounts[user.country] = (countryCounts[user.country] || 0) + 1;
      }
    });

    const countryRankings = Object.entries(countryCounts)
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count);

    res.json({
      rankings: countryRankings,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/stats/countries');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User growth over time
app.get('/admin/stats/growth', adminGuard, async (req, res) => {
  try {
    const { period = '30d' } = req.query;

    let days = 30;
    if (period === '7d') days = 7;
    else if (period === '90d') days = 90;
    else if (period === '1y') days = 365;

    const { data: users, error } = await supabaseAdmin
      .from('profiles')
      .select('created_at')
      .gte('created_at', new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString())
      .order('created_at', { ascending: true });

    if (error) {
      logger.error({ err: error }, 'Error fetching growth stats');
      return res.status(500).json({ error: 'Failed to fetch growth statistics' });
    }

    // Group by day
    const dailyGrowth: Record<string, number> = {};
    users?.forEach(user => {
      const date = user.created_at.split('T')[0];
      dailyGrowth[date] = (dailyGrowth[date] || 0) + 1;
    });

    const growthData = Object.entries(dailyGrowth)
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date));

    res.json({
      period,
      growth: growthData,
      totalNewUsers: users?.length || 0,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/stats/growth');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===== AUDIT ENDPOINTS =====

// Get admin actions
app.get('/admin/audit/actions', adminGuard, async (req, res) => {
  try {
    const { page = 1, limit = 50, admin_id, action } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    let query = supabaseAdmin
      .from('admin_actions')
      .select(`
        id,
        admin_id,
        action,
        target_user_id,
        details,
        created_at
      `, { count: 'exact' });

    if (admin_id) {
      query = query.eq('admin_id', admin_id);
    }
    if (action) {
      query = query.eq('action', action);
    }

    const { data: actions, error, count } = await query
      .range(offset, offset + Number(limit) - 1)
      .order('created_at', { ascending: false });

    if (error) {
      logger.error({ err: error }, 'Error fetching admin actions');
      return res.status(500).json({ error: 'Failed to fetch admin actions' });
    }

    res.json({
      actions: actions || [],
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/audit/actions');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get audit trail for specific user
app.get('/admin/audit/user/:id', adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { page = 1, limit = 50 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    const { data: actions, error, count } = await supabaseAdmin
      .from('admin_actions')
      .select(`
        id,
        admin_id,
        action,
        details,
        created_at
      `, { count: 'exact' })
      .eq('target_user_id', id)
      .range(offset, offset + Number(limit) - 1)
      .order('created_at', { ascending: false });

    if (error) {
      logger.error({ err: error }, 'Error fetching user audit trail');
      return res.status(500).json({ error: 'Failed to fetch user audit trail' });
    }

    res.json({
      actions: actions || [],
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/audit/user/:id');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Example protected route (keeping original for reference)
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
