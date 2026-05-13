import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// Define the user payload structure for TypeScript safety.
interface User {
  id: string;
  role: string;
}

// Extend Express Request to include user property without using 'any'.
declare module 'express' {
  interface Request {
    user?: User;
  }
}

// JWT secret: Use environment variable for production security.
// Fallback to hardcoded for dev convenience, but this is a trade-off -
// in production, always use a strong, unique secret from env to prevent leaks.
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

// Middleware to require authentication on protected routes.
// Extracts JWT from HttpOnly cookie, verifies it, and attaches user to request.
// Cookies protect against XSS because they are not accessible via JavaScript,
// unlike localStorage. HttpOnly and SameSite=Strict prevent CSRF and cookie theft.
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    // Verify JWT and decode payload.
    const decoded = jwt.verify(token, JWT_SECRET) as User;
    req.user = decoded;
    next();
  } catch (error) {
    // Invalid token: could be expired, tampered, or malformed.
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Middleware to enforce role-based access control (RBAC).
// Authentication answers "Who are you?", Authorization answers "What can you do?".
// This middleware checks if the authenticated user's role is in the allowed list.
// Returns 403 Forbidden if the user's role is not authorized.
// This prevents Insecure Direct Object Reference (IDOR) attacks by ensuring
// only users with the correct role can access sensitive endpoints like /api/users.
export function requireRole(allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

