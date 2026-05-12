# System Architecture

## Overview
This project currently contains a React/Vite frontend and is being extended with a secure Express/SQLite backend.
The backend is intentionally designed as a minimal, security-first API layer that keeps authentication state in `HttpOnly`, `SameSite=Strict` cookies and validates all input.

## Existing Frontend Structure
- `src/main.tsx` — app bootstrap and React DOM mount point.
- `src/App.tsx` — root layout, route handling, authentication state management, and high-level app shell. Fetches current user on mount via `getCurrentUser()` and passes authentication state to Navbar.
- `src/pages/EventsPage.tsx` — events-related UI and data interactions.
- `src/pages/UsersPage.tsx` — user-related UI and management pages.
- `src/pages/NotFound.tsx` — fallback route for unknown paths.
- `src/components/Navbar.tsx` — navigation with dynamic Login/Logout button based on authentication state.
- `src/components/LoginModal.tsx` — login form with error feedback and integration with backend auth.
- `src/components/WelcomeBanner.tsx` — welcome message component.
- `src/api.ts` — frontend API client layer with functions for `login`, `logout`, `getCurrentUser`, `getEvents`, and `getUsers`.

## Planned Backend Structure
- `src/server.ts` — Express server entry point with security middleware.
- `prisma/schema.prisma` — SQLite ORM schema defining the `User` model.
- `prisma/seed.ts` — Database seeding script for initial users.
- `src/middleware/auth.ts` — Authentication and authorization middleware.
- `src/routes/auth.ts` — Authentication routes for login, logout, and session check.
- `src/routes/events.ts` — Events endpoint for reading security events.
- `src/routes/users.ts` — Users endpoint (admin-only) for listing users.
- `.env` — environment configuration for the SQLite datasource and JWT secret.

## Backend Responsibilities
- enforce secure headers via `helmet`
- allow only the frontend origin via `cors` and support credentialed requests
- use `cookie-parser` for cookie-based auth handling
- protect endpoints with rate limiting via `express-rate-limit`
- define a Prisma-backed SQLite data model for users
- implement authentication middleware for JWT verification from HttpOnly cookies
- enforce role-based access control (RBAC) using `requireRole` middleware to authorize users by role
- provide auth routes for login, logout, and session validation
- serve security events via `/api/events` (authenticated users only)
- serve user management via `/api/users` (admin-only, with passwordHash excluded for data privacy)
- seed database with initial users using bcrypt for password hashing
- prevent leaking passwords, hashes, or stack traces in API responses

## Authentication & Data Flow
1. **Frontend (http://localhost:5173) to Backend (http://localhost:4000):**
   - Frontend sends login request to `POST /api/auth/login` with username/password.
   - Frontend uses `credentials: 'include'` in fetch to send HttpOnly cookies with cross-origin requests.

2. **Backend Login Processing:**
   - Backend validates input with `zod`, fetches user from Prisma, compares password with `bcrypt`.
   - If valid, generates JWT with user id/role, sets as `HttpOnly`, `SameSite=Strict` cookie.
   - Returns sanitized user data (id, username, role) — no token sent to frontend.

3. **Authenticated Requests:**
   - Subsequent requests include the HttpOnly cookie automatically (set by browser).
   - Backend verifies JWT in `requireAuth` middleware, attaches user to `req.user`.
   - Protected routes (e.g., `GET /api/events`, `GET /api/users`) check `req.user`.

4. **Authorization:**
   - `GET /api/events` uses `requireAuth` only; all authenticated users can access.
   - `GET /api/users` uses `requireAuth` + `requireRole(['admin'])`; only admin users can access.
   - Non-admin users receive a 403 Forbidden response with error message.
   - Frontend detects 403 and displays "Access Denied: Admin Only" message in UI.

5. **Logout:**
   - Frontend checks current user state via `getCurrentUser()` on app mount.
   - If user is authenticated, the Navbar displays a "Logout" button instead of "Login".
   - When "Logout" is clicked, the frontend calls `POST /api/auth/logout`.
   - Backend clears the auth cookie by setting it to empty with immediate expiration.
   - Frontend clears local user state and reloads the page to reset UI.

6. **Session Check:**
   - Frontend calls `GET /api/auth/me` to verify current user is still authenticated.
   - Returns user data if valid, 401 if not authenticated.
   - Frontend handles 401 by redirecting to login.

## Role-Based Access Control (RBAC)
RBAC in this system separates **Authentication** (who are you?) from **Authorization** (what can you do?):

- **Authentication:** Verified via JWT extracted from HttpOnly cookies in the `requireAuth` middleware.
- **Authorization:** Enforced via `requireRole` middleware, which checks `req.user.role` against allowed roles.

Examples:
- `GET /api/events` — requires `requireAuth` only; all authenticated users can view events.
- `GET /api/users` — requires `requireAuth` + `requireRole(['admin'])`; only admin users can list all users.

If a non-admin user tries to access `/api/users`, the server returns a 403 Forbidden response. This prevents Insecure Direct Object Reference (IDOR) attacks by ensuring users cannot bypass role checks.

## Security Trade-offs
- Chose SQLite for a lightweight, secure assignment-compatible database.
- Chose cookie-based authentication over localStorage to reduce XSS impact.
- Kept the server architecture minimal to satisfy the assignment's "avoid overengineering" requirement.
