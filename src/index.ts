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

// ===== REFERRAL CODE GENERATION UTILITY =====
/**
 * Generate a unique referral code that doesn't exist in either referral_codes or waitlist tables
 * @param maxAttempts - Maximum number of attempts to generate a unique code (default: 10)
 * @returns Promise<string> - Unique referral code
 */
const generateUniqueReferralCode = async (maxAttempts: number = 10): Promise<string> => {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // exclude easily confused chars (I, O, 0, 1)

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Generate a random 6-character code
    let code = '';
    for (let i = 0; i < 6; i++) {
      code += alphabet[Math.floor(Math.random() * alphabet.length)];
    }

    // Check if code exists in referral_codes table
    const { data: existingReferralCode, error: referralError } = await supabaseAdmin
      .from('referral_codes')
      .select('code')
      .eq('code', code)
      .maybeSingle();

    if (referralError && referralError.code !== 'PGRST116') {
      logger.warn({ err: referralError, attempt }, 'Error checking referral_codes for duplicate');
      continue;
    }

    if (existingReferralCode) {
      logger.debug({ code, attempt }, 'Code exists in referral_codes, retrying');
      continue;
    }

    // Check if code exists in waitlist table
    const { data: existingWaitlistCode, error: waitlistError } = await supabaseAdmin
      .from('waitlist')
      .select('referral_code')
      .eq('referral_code', code)
      .maybeSingle();

    if (waitlistError && waitlistError.code !== 'PGRST116') {
      logger.warn({ err: waitlistError, attempt }, 'Error checking waitlist for duplicate');
      continue;
    }

    if (existingWaitlistCode) {
      logger.debug({ code, attempt }, 'Code exists in waitlist, retrying');
      continue;
    }

    // Code is unique in both tables
    logger.info({ code, attempt: attempt + 1 }, 'Generated unique referral code');
    return code;
  }

  // If we exhausted all attempts, throw an error
  throw new Error(`Failed to generate unique referral code after ${maxAttempts} attempts`);
};

/**
 * Validate if a referral code exists in either referral_codes or waitlist tables
 * @param code - Referral code to validate
 * @returns Promise<{ exists: boolean; ownerType: 'user' | 'waitlist' | null; ownerId?: string }>
 */
const validateReferralCode = async (code: string): Promise<{
  exists: boolean;
  ownerType: 'user' | 'waitlist' | null;
  ownerId?: string;
  ownerEmail?: string;
}> => {
  const normalizedCode = code.trim().toUpperCase();

  if (!normalizedCode) {
    return { exists: false, ownerType: null };
  }

  // Check in referral_codes table (for users who signed up)
  const { data: referralCode, error: referralError } = await supabaseAdmin
    .from('referral_codes')
    .select('id, owner_user_id, code')
    .ilike('code', normalizedCode)
    .maybeSingle();

  if (referralError && referralError.code !== 'PGRST116') {
    logger.warn({ err: referralError }, 'Error validating referral code in referral_codes');
  }

  if (referralCode) {
    return {
      exists: true,
      ownerType: 'user',
      ownerId: referralCode.owner_user_id
    };
  }

  // Check in waitlist table (for waitlist entries)
  const { data: waitlistEntry, error: waitlistError } = await supabaseAdmin
    .from('waitlist')
    .select('id, email, referral_code')
    .ilike('referral_code', normalizedCode)
    .maybeSingle();

  if (waitlistError && waitlistError.code !== 'PGRST116') {
    logger.warn({ err: waitlistError }, 'Error validating referral code in waitlist');
  }

  if (waitlistEntry) {
    return {
      exists: true,
      ownerType: 'waitlist',
      ownerId: waitlistEntry.id,
      ownerEmail: waitlistEntry.email
    };
  }

  return { exists: false, ownerType: null };
};

// ===== EMAIL SENDING UTILITY =====
/**
 * Send referral emails via Supabase Edge Function
 * @param type - Type of email: 'referrer' or 'referred'
 * @param recipientEmail - Email address to send to
 * @param referralCode - The referral code used
 * @param referredEmail - Email of the person who was referred (for referrer emails)
 * @returns Promise<boolean> - Returns true if email was sent successfully
 */
const sendReferralEmail = async (
  type: 'referrer' | 'referred',
  recipientEmail: string,
  referralCode: string,
  referredEmail?: string
): Promise<boolean> => {
  try {
    if (!SUPABASE_URL) {
      logger.warn('SUPABASE_URL not set, cannot send email');
      return false;
    }

    const edgeFunctionUrl = `${SUPABASE_URL}/functions/v1/send-referral-emails`;
    const payload: any = {
      type,
      recipientEmail,
      referralCode,
    };

    if (type === 'referrer' && referredEmail) {
      payload.referredEmail = referredEmail;
    }

    const response = await fetch(edgeFunctionUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      logger.error(
        {
          type,
          recipientEmail,
          status: response.status,
          error: errorText
        },
        'Failed to send referral email via Edge Function'
      );
      return false;
    }

    const result = await response.json();
    logger.info(
      { type, recipientEmail, messageId: result.messageId },
      'Referral email sent successfully'
    );
    return true;
  } catch (error) {
    logger.error(
      { err: error, type, recipientEmail },
      'Error sending referral email'
    );
    return false;
  }
};

/**
 * Get referrer's email address from validation result
 * @param validation - Validation result from validateReferralCode
 * @returns Promise<string | null> - Referrer's email address or null if not found
 */
const getReferrerEmail = async (validation: {
  exists: boolean;
  ownerType: 'user' | 'waitlist' | null;
  ownerId?: string;
  ownerEmail?: string;
}): Promise<string | null> => {
  if (!validation.exists || !validation.ownerId) {
    return null;
  }

  // If ownerType is waitlist, we already have the email
  if (validation.ownerType === 'waitlist' && validation.ownerEmail) {
    return validation.ownerEmail;
  }

  // If ownerType is user, fetch email from profiles table
  if (validation.ownerType === 'user' && validation.ownerId) {
    const { data: profile } = await supabaseAdmin
      .from('profiles')
      .select('email')
      .eq('id', validation.ownerId)
      .maybeSingle();

    return profile?.email || null;
  }

  return null;
};

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

// Stricter limiter for public waitlist endpoint
const waitlistLimiter = rateLimit({ windowMs: 60_000, max: 10 });

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

// ===== ADMIN LOGIN ENDPOINT =====
/**
 * @swagger
 * /admin/login:
 *   post:
 *     summary: Admin login
 *     description: Authenticate admin user and get JWT token
 *     tags: [System]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     email:
 *                       type: string
 *                     admin_roles:
 *                       type: array
 *                       items:
 *                         type: string
 *       401:
 *         description: Invalid credentials or not an admin
 *       500:
 *         description: Internal server error
 */
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Authenticate with Supabase Auth
    const { data: authData, error: authError } = await supabaseAdmin.auth.signInWithPassword({
      email: email.trim().toLowerCase(),
      password,
    });

    if (authError || !authData.user) {
      logger.warn({ email: email.trim().toLowerCase() }, 'Failed login attempt');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userId = authData.user.id;

    // Check if user has admin roles in profiles table
    const { data: profile, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('id, email, admin_roles')
      .eq('id', userId)
      .single();

    if (profileError || !profile) {
      logger.error({ err: profileError, userId }, 'Error fetching user profile');
      return res.status(500).json({ error: 'Failed to fetch user profile' });
    }

    const adminRoles = profile.admin_roles || [];
    if (adminRoles.length === 0) {
      return res.status(403).json({ error: 'User does not have admin privileges' });
    }

    // Determine highest role (superadmin > admin)
    const role = adminRoles.includes('superadmin') ? 'superadmin' : 'admin';

    // Generate JWT token
    const token = jwt.sign(
      {
        sub: userId,
        email: profile.email,
        role,
      },
      ADMIN_JWT_SECRET,
      { expiresIn: '7d' }
    );

    logger.info({ userId, role }, 'Admin login successful');

    res.json({
      token,
      user: {
        id: profile.id,
        email: profile.email,
        admin_roles: adminRoles,
      },
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/login');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===== PUBLIC WAITLIST ENDPOINT =====
/**
 * @swagger
 * /waitlist:
 *   post:
 *     summary: Join waitlist
 *     tags: [System]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, phoneNumber, language]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *               language:
 *                 type: string
 *               usedReferralCode:
 *                 type: string
 *                 description: Optional referral code used when joining waitlist
 *     responses:
 *       200:
 *         description: Added to waitlist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 referralCode:
 *                   type: string
 *                   description: Unique referral code assigned to this waitlist entry
 *       400:
 *         description: Validation error
 */
app.post('/waitlist', waitlistLimiter, async (req, res) => {
  try {
    const rawEmail = String((req.body?.email || '')).trim().toLowerCase();
    const rawPhone = String((req.body?.phoneNumber || '')).trim();
    const language = String((req.body?.language || '')).trim();
    const usedReferralCodeRaw = req.body?.usedReferralCode ? String(req.body.usedReferralCode).trim().toUpperCase() : null;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!rawEmail || !emailRegex.test(rawEmail)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    if (!rawPhone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }
    if (!language) {
      return res.status(400).json({ error: 'Language is required' });
    }

    // Basic E.164 normalization attempt (keep + and digits)
    const phoneNumber = rawPhone.replace(/[^+\d]/g, '');

    // Validate used_referral_code if provided
    let validatedReferralCode: string | null = null;
    let referralValidation: { exists: boolean; ownerType: 'user' | 'waitlist' | null; ownerId?: string; ownerEmail?: string } | null = null;

    if (usedReferralCodeRaw && usedReferralCodeRaw.length > 0) {
      referralValidation = await validateReferralCode(usedReferralCodeRaw);
      if (!referralValidation.exists) {
        logger.warn({ code: usedReferralCodeRaw, email: rawEmail }, 'Invalid referral code provided');
        return res.status(400).json({ error: 'Invalid referral code' });
      }

      // Don't allow self-referral
      // Check if it's a waitlist entry with the same email
      if (referralValidation.ownerType === 'waitlist' && referralValidation.ownerEmail === rawEmail) {
        logger.warn({ code: usedReferralCodeRaw, email: rawEmail }, 'Self-referral attempted (waitlist)');
        return res.status(400).json({ error: 'Cannot use your own referral code' });
      }

      // Check if it's a user referral code - verify email doesn't match
      if (referralValidation.ownerType === 'user' && referralValidation.ownerId) {
        const { data: userProfile } = await supabaseAdmin
          .from('profiles')
          .select('email')
          .eq('id', referralValidation.ownerId)
          .maybeSingle();

        if (userProfile?.email === rawEmail) {
          logger.warn({ code: usedReferralCodeRaw, email: rawEmail }, 'Self-referral attempted (user)');
          return res.status(400).json({ error: 'Cannot use your own referral code' });
        }
      }

      validatedReferralCode = usedReferralCodeRaw;
    }

    // Generate unique referral code for this waitlist entry
    let referralCode: string;
    try {
      referralCode = await generateUniqueReferralCode();
    } catch (error: any) {
      logger.error({ err: error, email: rawEmail }, 'Failed to generate unique referral code');
      return res.status(500).json({ error: 'Failed to generate referral code. Please try again.' });
    }

    // Insert into waitlist with referral codes
    const { data: waitlistEntry, error } = await supabaseAdmin
      .from('waitlist')
      .insert({
        email: rawEmail,
        phone_number: phoneNumber,
        language,
        referral_code: referralCode,
        used_referral_code: validatedReferralCode
      })
      .select('id, referral_code')
      .single();

    if (error) {
      // Unique violation => already on waitlist is OK UX-wise
      const already = error.message?.toLowerCase().includes('duplicate') ||
                     error.code === '23505'; // PostgreSQL unique violation
      if (already) {
        // If already exists, check if they have a referral code
        const { data: existing } = await supabaseAdmin
          .from('waitlist')
          .select('referral_code, used_referral_code')
          .eq('email', rawEmail)
          .maybeSingle();

        // If they don't have a referral code, generate one for them
        if (existing && !existing.referral_code) {
          try {
            const newReferralCode = await generateUniqueReferralCode();
            const { error: updateError } = await supabaseAdmin
              .from('waitlist')
              .update({ referral_code: newReferralCode })
              .eq('email', rawEmail);

            if (!updateError) {
              logger.info({ email: rawEmail, referralCode: newReferralCode }, 'Generated referral code for existing waitlist entry');
              return res.json({
                message: 'Already on waitlist',
                referralCode: newReferralCode
              });
            }
          } catch (genError) {
            logger.error({ err: genError, email: rawEmail }, 'Failed to generate referral code for existing entry');
          }
        }

        return res.json({
          message: 'Already on waitlist',
          referralCode: existing?.referral_code || null
        });
      }
      logger.error({ err: error, email: rawEmail }, 'Error inserting waitlist');
      return res.status(500).json({ error: 'Failed to add to waitlist' });
    }

    logger.info({
      email: rawEmail,
      referralCode,
      usedReferralCode: validatedReferralCode
    }, 'Waitlist entry created with referral codes');

    // Send referral emails asynchronously (don't block the response)
    if (validatedReferralCode && referralValidation) {
      // Get referrer's email from validation result (already validated earlier)
      const referrerEmail = await getReferrerEmail(referralValidation);

      if (referrerEmail) {
        // Send email to referrer (person who referred someone)
        sendReferralEmail('referrer', referrerEmail, validatedReferralCode, rawEmail)
          .catch(err => {
            logger.error({ err, referrerEmail }, 'Failed to send referrer email (async)');
          });

        // Send email to referred person
        sendReferralEmail('referred', rawEmail, referralCode)
          .catch(err => {
            logger.error({ err, referredEmail: rawEmail }, 'Failed to send referred email (async)');
          });
      } else {
        logger.warn(
          { referralCode: validatedReferralCode, email: rawEmail },
          'Could not find referrer email for referral notification'
        );
        // Still send email to referred person even if referrer email not found
        sendReferralEmail('referred', rawEmail, referralCode)
          .catch(err => {
            logger.error({ err, referredEmail: rawEmail }, 'Failed to send referred email (async)');
          });
      }
    } else {
      // No referral code used, but still send welcome email to the new waitlist entry
      sendReferralEmail('referred', rawEmail, referralCode)
        .catch(err => {
          logger.error({ err, referredEmail: rawEmail }, 'Failed to send referred email (async)');
        });
    }

    res.json({
      message: 'Added to waitlist',
      referralCode: referralCode
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /waitlist');
    res.status(500).json({ error: 'Internal server error' });
  }
});

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

/**
 * @swagger
 * /admin/users/{id}:
 *   get:
 *     summary: Get user by ID
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
 *     responses:
 *       200:
 *         description: User details
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *       404:
 *         description: User not found
 */
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

/**
 * @swagger
 * /admin/users/{id}/unban:
 *   post:
 *     summary: Unban a user
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
 *     responses:
 *       200:
 *         description: User unbanned successfully
 *       400:
 *         description: User is not banned
 *       404:
 *         description: User not found
 */
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

/**
 * @swagger
 * /admin/users/{id}/promote:
 *   post:
 *     summary: Promote user to admin/superadmin
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
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [admin, superadmin]
 *     responses:
 *       200:
 *         description: Promotion successful
 *       400:
 *         description: Invalid role or already has role
 *       404:
 *         description: User not found
 */
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

/**
 * @swagger
 * /admin/users/{id}/demote:
 *   post:
 *     summary: Demote user from admin/superadmin
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
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [admin]
 *     responses:
 *       200:
 *         description: Demotion successful
 *       400:
 *         description: User does not have role
 *       404:
 *         description: User not found
 */
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

/**
 * @swagger
 * /admin/users/{id}/roles/validator:
 *   post:
 *     summary: Grant validator role for a language
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
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [language]
 *             properties:
 *               language:
 *                 type: string
 *     responses:
 *       200:
 *         description: Validator granted
 *       400:
 *         description: Already has role or bad input
 *       404:
 *         description: User not found
 */
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

/**
 * @swagger
 * /admin/users/{id}/roles/ambassador:
 *   post:
 *     summary: Grant ambassador role for a language
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
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [language]
 *             properties:
 *               language:
 *                 type: string
 *     responses:
 *       200:
 *         description: Ambassador granted
 *       400:
 *         description: Already has role or bad input
 *       404:
 *         description: User not found
 */
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

/**
 * @swagger
 * /admin/users/{id}/roles/validator:
 *   delete:
 *     summary: Revoke validator role for a language
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
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [language]
 *             properties:
 *               language:
 *                 type: string
 *     responses:
 *       200:
 *         description: Validator revoked
 *       400:
 *         description: User does not have role
 *       404:
 *         description: User not found
 */
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

/**
 * @swagger
 * /admin/users/{id}/roles/ambassador:
 *   delete:
 *     summary: Revoke ambassador role for a language
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
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [language]
 *             properties:
 *               language:
 *                 type: string
 *     responses:
 *       200:
 *         description: Ambassador revoked
 *       400:
 *         description: User does not have role
 *       404:
 *         description: User not found
 */
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

/**
 * @swagger
 * /admin/stats/languages:
 *   get:
 *     summary: Language rankings
 *     tags: [Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Ranked list of languages with user counts
 */
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

/**
 * @swagger
 * /admin/stats/countries:
 *   get:
 *     summary: Country rankings
 *     tags: [Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Ranked list of countries with user counts
 */
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

/**
 * @swagger
 * /admin/stats/growth:
 *   get:
 *     summary: User growth
 *     tags: [Statistics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [7d, 30d, 90d, 1y]
 *           default: 30d
 *     responses:
 *       200:
 *         description: Daily signup counts
 */
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

/**
 * @swagger
 * /admin/waitlist:
 *   get:
 *     summary: List waitlist entries
 *     tags: [System]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 20 }
 *       - in: query
 *         name: language
 *         schema: { type: string }
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Paginated waitlist entries
 */
app.get('/admin/waitlist', adminGuard, async (req, res) => {
  try {
    const { page = 1, limit = 20, language, search } = req.query as any;
    const offset = (Number(page) - 1) * Number(limit);

    let query = supabaseAdmin
      .from('waitlist')
      .select('id, email, phone_number, language, referral_code, used_referral_code, created_at', { count: 'exact' })
      .order('created_at', { ascending: false });

    if (language) query = query.eq('language', language);
    if (search) query = query.or(`email.ilike.%${search}%,phone_number.ilike.%${search}%`);

    const { data, error, count } = await query.range(offset, offset + Number(limit) - 1);
    if (error) {
      logger.error({ err: error }, 'Error fetching waitlist');
      return res.status(500).json({ error: 'Failed to fetch waitlist' });
    }

    res.json({
      entries: data || [],
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/waitlist');
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @swagger
 * /admin/waitlist/export:
 *   get:
 *     summary: Export waitlist as CSV
 *     tags: [System]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: CSV export
 *         content:
 *           text/csv:
 *             schema:
 *               type: string
 */
app.get('/admin/waitlist/export', adminGuard, async (_req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('waitlist')
      .select('email, phone_number, language, referral_code, used_referral_code, created_at')
      .order('created_at', { ascending: false });

    if (error) {
      logger.error({ err: error }, 'Error exporting waitlist');
      return res.status(500).json({ error: 'Failed to export waitlist' });
    }

    const header = 'email,phone_number,language,referral_code,used_referral_code,created_at\n';
    const rows = (data || []).map(r => [
      r.email,
      r.phone_number,
      r.language,
      r.referral_code || '',
      r.used_referral_code || '',
      r.created_at
    ].join(','));
    const csv = header + rows.join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="waitlist.csv"');
    res.send(csv);
  } catch (error) {
    logger.error({ err: error }, 'Unexpected error in /admin/waitlist/export');
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @swagger
 * /admin/audit/actions:
 *   get:
 *     summary: List admin actions
 *     tags: [Audit]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 50 }
 *       - in: query
 *         name: admin_id
 *         schema: { type: string, format: uuid }
 *       - in: query
 *         name: action
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Paginated admin actions
 */
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

/**
 * @swagger
 * /admin/audit/user/{id}:
 *   get:
 *     summary: Audit trail for a user
 *     tags: [Audit]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string, format: uuid }
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 50 }
 *     responses:
 *       200:
 *         description: Paginated audit actions for target user
 */
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
