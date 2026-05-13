import { Router, Request, Response } from 'express';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { requireAuth } from '../middleware/auth.js';
import prisma from '../lib/prisma.js';

const router = Router();

// JWT secret: Same as in middleware, use env for security.
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

// Rate limiter: caps login attempts to 5 per 15-minute window per IP.
// Prevents brute-force credential stuffing without locking out legitimate users long-term.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { error: 'Too many login attempts, please try again later' },
  standardHeaders: true,  // Return rate-limit info in RateLimit-* headers
  legacyHeaders: false,   // Disable X-RateLimit-* legacy headers
});

// Zod schema for login input validation.
// .strict() rejects any extra fields to prevent parameter pollution attacks.
// .min(8) enforces a minimum password length matching creation requirements.
const loginSchema = z.object({
  email: z.string().email('Valid email required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
}).strict();

// POST /api/auth/login: Authenticates user and sets HttpOnly cookie.
// Step 1: Validate input with zod to ensure email/password are well-formed.
// Step 2: Fetch user from database by email.
// Step 3: Return the SAME generic error whether the email is unknown OR the password
//         is wrong — this prevents user enumeration (an attacker cannot tell which
//         field was incorrect from the response).
// Step 4: Check account status AFTER confirming the email exists; 403 is intentionally
//         distinct because the spec requires it and the trade-off is acceptable.
// Step 5: If valid, generate JWT with user id and role.
// Step 6: Set JWT as HttpOnly, SameSite=Strict, Secure (prod) cookie.
// Why cookies? Protects against XSS; localStorage is vulnerable to script injection.
router.post('/login', loginLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({
      where: { email },
    });

    // Anti-enumeration: respond identically whether the email doesn't exist or the
    // password is wrong so an attacker cannot determine which field failed.
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (user.status !== 'active') {
      return res.status(403).json({ error: 'Account is disabled. Please contact an administrator.' });
    }

    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      // Same message as the "user not found" branch — prevents enumeration.
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: '24h',
    });

    // Set secure cookie: HttpOnly prevents JS access, SameSite=Strict blocks CSRF,
    // secure flag ensures HTTPS-only transmission in production.
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    // Return user data without sensitive fields.
    res.json({
      id: user.id,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid input', details: error.errors });
    }
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout: Clears the auth cookie to log out.
// Setting an empty cookie with immediate expiration removes it from the client.
router.post('/logout', (req: Request, res: Response) => {
  res.cookie('token', '', {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 0, // Expire immediately
  });
  res.json({ message: 'Logged out' });
});

// GET /api/auth/me: Protected route to get current user session.
// Uses requireAuth middleware to verify token and attach user to request.
// Returns user data for frontend to check authentication state.
router.get('/me', requireAuth, (req: Request, res: Response) => {
  res.json(req.user);
});

export default router;
