# PenguWave Security Operations Portal — Full Code Review

> **Scope**: `Part2-Security-Operations-Portal/` — Full-Stack Security Operations Portal  
> **Files covered**: `src/server.ts`, `src/middleware/auth.ts`, `src/routes/auth.ts`,
> `src/routes/events.ts`, `src/routes/users.ts`, `src/lib/prisma.ts`, `src/types.ts`,
> `src/api.ts`, `src/App.tsx`, `src/main.tsx`, `src/components/*`, `src/pages/*`,
> `prisma/schema.prisma`, `prisma/seed.ts`, `THREAT_MODEL.md`, `README.md`

---

## 1. Goal

Build a **production-oriented, secure-by-design Security Operations Portal** that:

- Serves a list of security events to authenticated users
- Enforces **Role-Based Access Control (RBAC)** so different users see only what their role permits
- Protects against the most common web security threats: **XSS, CSRF, SQL injection, brute-force, mass assignment, IDOR, and credential exposure**
- Provides a clear, documented path from a local dev setup to a hardened production deployment

The secondary goal is **defense in depth**: no single security mechanism is the only line of defense. If one control is bypassed, others must still hold.

---

## 2. Files Overview

| File | Role |
|------|------|
| `src/server.ts` | Express application bootstrap — middleware stack, route mounting, health endpoint |
| `src/middleware/auth.ts` | `requireAuth` and `requireRole` — JWT verification and RBAC enforcement |
| `src/routes/auth.ts` | Login, logout, session check (`/api/auth/*`) |
| `src/routes/events.ts` | Security event list (`/api/events`) |
| `src/routes/users.ts` | User CRUD (`/api/users`) — admin-only |
| `src/lib/prisma.ts` | Singleton Prisma client |
| `src/types.ts` | Shared TypeScript interfaces |
| `src/api.ts` | Frontend fetch wrapper — all API calls in one place |
| `src/App.tsx` | Root React component — auth state, routing |
| `src/main.tsx` | React entry point |
| `src/components/LoginModal.tsx` | Login form — shows/hides password, reports errors |
| `src/components/Navbar.tsx` | Navigation — conditional links based on role |
| `src/components/WelcomeBanner.tsx` | Dismissible onboarding banner for reviewers |
| `src/pages/EventsPage.tsx` | Event table — search, filter, sort, detail panel, JSON export |
| `src/pages/UsersPage.tsx` | User management table — add/delete/toggle status |
| `src/pages/NotFound.tsx` | 404 page |
| `prisma/schema.prisma` | Database model — `User` entity |
| `prisma/seed.ts` | Seeds three test accounts (admin, analyst, viewer) |
| `data/mock_events.json` | Static event list served by the events route |
| `docs/api_contract.md` | API specification provided as part of the assignment |
| `THREAT_MODEL.md` | Concise threat model — attacker perspective and mitigations |
| `README.md` | Full project documentation — setup, auth, RBAC, production strategy |
| `CODE_REVIEW.md` | This file |

---

## 3. System Design

### Architecture Overview

```
Browser (React + Vite, port 5173)
       │
       │  HTTPS (via proxy in production)
       │  HTTP in dev — cookies are first-party, no CORS credential issues
       ▼
Express API Server (port 4000)
       │
       ├─ Global rate limiter (100 req / 15 min / IP) — helmet for secure headers
       │
       ├─ /api/auth/*
       │      ├─ POST /login  → loginLimiter → zod validate → bcrypt compare → JWT cookie
       │      ├─ POST /logout → clear cookie
       │      └─ GET  /me     → requireAuth → return req.user
       │
       ├─ /api/events
       │      └─ GET /        → requireAuth → serve mock_events.json
       │
       └─ /api/users
              ├─ GET    /        → requireAuth + requireRole(['admin']) → prisma.user.findMany
              ├─ POST   /        → requireAuth + requireRole(['admin']) → bcrypt + prisma.user.create
              ├─ DELETE /:id     → requireAuth + requireRole(['admin']) → self-lockout check → prisma.user.delete
              └─ PATCH  /:id/status → requireAuth + requireRole(['admin']) → self-lockout check → prisma.user.update
                     │
                     ▼
              SQLite (dev) / PostgreSQL (production)
              via Prisma ORM (parameterised queries — SQL injection immune)
```

### Data Flow on Login

```
1. User submits email + password in LoginModal.
2. Frontend calls POST /api/auth/login with credentials: 'include'.
3. Express: loginLimiter checks IP rate — 429 if exceeded.
4. Zod validates request body — 400 if malformed or extra fields present.
5. Prisma looks up user by email. If not found → dummy bcrypt.compare (timing normalisation) → 401 (same message as wrong password).
6. If user.status !== 'active' → 403 (separate code to signal account disabled).
7. bcrypt.compare(password, passwordHash) — timing-safe comparison.
8. If invalid → 401 (identical message to step 5 — anti-enumeration).
9. jwt.sign({ id, role }, JWT_SECRET, { expiresIn: '24h' }) → token.
10. res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: <production> }).
11. Response body: { id, email, role } — no token, no hash.
12. Frontend calls GET /api/auth/me to populate React state (no JWT parsing in browser).
```

### RBAC Model

| Role | Events (view) | Events (export) | Event detail | Users (view/manage) |
|------|:---:|:---:|:---:|:---:|
| `admin` | Yes | Yes | Yes | Yes |
| `analyst` | Yes | Yes | Yes | No |
| `viewer` | Yes | No | No | No |

RBAC is enforced **twice**: once on the backend (middleware, source of truth) and once on the frontend (UI hiding for UX, not security). This means even a user who constructs raw API calls bypassing the UI will be stopped by the backend.

---

## 4. Attack Vectors Addressed

### 4.1 Cross-Site Scripting (XSS) + Session Hijacking

**The threat**: An attacker injects malicious JavaScript into event log data (e.g., a security event title that contains `<script>`). If the auth token is stored in `localStorage`, that script can read it and exfiltrate it to an attacker server.

**The mitigation**: Auth tokens are stored exclusively in **`HttpOnly` cookies**. The browser's JavaScript engine has no API to read `HttpOnly` cookies — `document.cookie` returns only non-HttpOnly cookies. Even a successful XSS injection cannot exfiltrate the session token, because the token is never accessible to any JavaScript context.

Additionally, `helmet()` in `server.ts` sets the `Content-Security-Policy` header, reducing the surface area for XSS injection in the first place.

### 4.2 Cross-Site Request Forgery (CSRF)

**The threat**: An attacker tricks a logged-in user into visiting `evil.com`, which has a hidden form that POSTs to `http://localhost:4000/api/users` and creates a new admin account. Since cookies are sent automatically, the request would arrive authenticated.

**The mitigation**: The auth cookie is set with `SameSite=Strict`. This directive instructs the browser to **never** attach the cookie to any request that did not originate from the same site. A cross-origin form submission from `evil.com` will arrive at the server without the auth cookie, and `requireAuth` will return 401. No CSRF token is needed because `SameSite=Strict` eliminates the attack vector entirely.

### 4.3 SQL Injection

**The threat**: An attacker sends crafted input like `' OR '1'='1` in the email field of the login form, hoping to bypass authentication or dump the database by manipulating the raw SQL query.

**The mitigation**: The application uses **Prisma ORM** exclusively for all database access. Prisma uses prepared statements (parameterised queries) at the driver level — user input is never concatenated into SQL strings. There is no raw SQL in the entire codebase. This provides structural immunity to SQL injection, not just input sanitisation.

### 4.4 Brute-Force and Credential Stuffing

**The threat**: An attacker runs an automated script to try thousands of email/password combinations against the login endpoint.

**The mitigations (layered)**:
1. **Per-IP rate limiting on `/api/auth/login`**: `express-rate-limit` allows 5 attempts per IP per 15-minute window. The 6th attempt receives `429 Too Many Requests`. This makes automated guessing impractical — 5 attempts per 15 minutes means 480 attempts per day, not millions.
2. **bcrypt cost factor 10**: Even if an attacker obtains the database, recovering passwords requires significant computational effort per hash. At cost 10, a single bcrypt hash takes ~100ms on modern hardware.
3. **Global rate limiter**: A secondary limiter (100 req/15min/IP) on all routes further throttles abuse.

### 4.5 User Enumeration

**The threat**: An attacker probes the login endpoint with known emails to determine which accounts exist. If the server returns "user not found" for unknown emails and "wrong password" for known ones, the attacker can enumerate a valid account list.

**The mitigation — response body**: Both the "email not found" and "wrong password" branches return the **identical** 401 response: `{ "error": "Invalid email or password" }`. The only distinguishing response is 403 for a disabled account — an intentional trade-off (the attacker still needs the correct password).

**The mitigation — response timing**: Without additional hardening, the "user not found" branch returns immediately while the "wrong password" branch calls `bcrypt.compare` (~100ms). A timing measurement could distinguish the two. To close this oracle, a dummy `bcrypt.compare` call is performed even when the user is not found, normalising response time across both branches:

```ts
if (!user) {
  // Dummy compare keeps response time equal to the wrong-password branch,
  // preventing user enumeration via timing differences.
  await bcrypt.compare(password, '$2b$10$dummyHashToPreventTimingAttacks1234567890123456789012');
  return res.status(401).json({ error: 'Invalid email or password' });
}
```

### 4.6 Mass Assignment / Parameter Pollution

**The threat**: An attacker sends a POST request to `/api/users` with extra fields: `{ "email": "...", "password": "...", "role": "analyst", "id": "admin-123" }`, attempting to overwrite the assigned ID or inject an unexpected role. Without validation, ORM frameworks may map unknown fields directly to the database model.

**The mitigation**: All request bodies are validated with **Zod schemas using `.strict()`**. The `.strict()` modifier causes Zod to reject any request that contains fields not declared in the schema — a `ZodError` is thrown immediately, and the route handler never executes. The `passwordHash` field is never accepted as input; it is always computed server-side.

### 4.7 Insecure Direct Object Reference (IDOR)

**The threat**: A `viewer` user directly calls `GET /api/users` or `DELETE /api/users/some-id` by guessing or observing IDs, bypassing the frontend UI controls.

**The mitigation**: Every sensitive route applies `requireRole(['admin'])` as middleware. The backend checks the role claim from the JWT, not from any client-supplied parameter. A viewer JWT contains `role: 'viewer'`, and `requireRole` returns 403 before the route handler runs — regardless of what the client sends.

### 4.8 Credential Exposure

**The threat**: Passwords stored in plaintext in the database — a single database breach exposes all credentials immediately.

**The mitigation**: Passwords are hashed with **bcrypt** (salt + cost factor 10) before storage. The `passwordHash` field is explicitly excluded from all `prisma.user.findMany` / `prisma.user.create` responses using Prisma's `select` option. The seed file hashes passwords before writing them. No route returns `passwordHash` in any response.

### 4.9 Admin Self-Lockout

**The threat**: An admin accidentally (or maliciously) deletes or disables their own account, leaving the application in an unrecoverable state with no admin access.

**The mitigation**: Both `DELETE /:id` and `PATCH /:id/status` compare the target user's `id` against `req.user.id` (the authenticated requester). If they match, the request is rejected with `400 Bad Request` before the database call is made.

### 4.10 Internal Data Leakage via UI

**The threat**: The events table displays raw event data including internal database fields (`id`, `userId`). These IDs can be used by an attacker for IDOR reconnaissance — mapping the database structure, enumerating resource IDs, or correlating events to users.

**The mitigation**: The `EventsPage` component strips `id` and `userId` from both the detail panel display and the JSON export:
```ts
const { id: _id, userId: _userId, ...sanitized } = selectedEvent;
```
The same destructuring pattern is applied in the export handler. The backend `/api/events` endpoint returns the full object because it serves an authenticated audience — the sanitization happens on the frontend for the display layer.

---

## 5. Defense Mechanisms Implemented

### 5.1 `server.ts` — Middleware Stack (Order Matters)

```
globalLimiter          → throttle all traffic before any processing
helmet()               → set X-Content-Type-Options, CSP, X-Frame-Options, etc.
cors({ credentials })  → whitelist http://localhost:5173 only
express.json(10kb)     → payload size limit prevents large-body DoS
cookieParser()         → parse cookies so auth middleware can read them
```

The order is deliberate: rate limiting and security headers run before any application logic. A request that exceeds the rate limit never reaches a route handler, and the security headers are always set regardless of which route handles the response.

**`express.json({ limit: '10kb' })`**: Without a size limit, an attacker can send a 100 MB JSON body to any POST endpoint, consuming server memory and blocking the event loop. The 10 KB limit rejects oversized bodies before the route handler touches them.

### 5.2 `middleware/auth.ts` — Two-Middleware RBAC Chain

The authentication and authorization middleware are intentionally **separate functions** rather than a single combined middleware:

```ts
router.get('/', requireAuth, requireRole(['admin']), async (req, res) => { ... })
```

This design means:
- `requireAuth` answers: "Is this request authenticated?" (valid JWT in cookie)
- `requireRole` answers: "Does this authenticated user have the required role?"

By separating concerns, each middleware has a single responsibility and can be reused independently. `requireAuth` alone is used for the events route (all authenticated users). Both together are used for all user management routes.

The JWT is verified with `jwt.verify(token, JWT_SECRET)` — this cryptographic verification ensures the token was not tampered with since issuance. If the signature is invalid, forged, or if the token has expired, `jwt.verify` throws and the request is rejected with 401.

### 5.3 `routes/auth.ts` — Login Security Layers

The login route applies four independent security controls, each catching a different attack:

| Control | Attack stopped |
|---------|---------------|
| `loginLimiter` (5/15min) | Brute-force and credential stuffing |
| `zod .strict()` schema | Parameter pollution, malformed input |
| Same 401 for both branches | User enumeration (response body) |
| Dummy `bcrypt.compare` when user not found | User enumeration via response timing |
| `bcrypt.compare` (not string equality) | Timing attacks on password comparison |

The `secure` flag on the cookie is conditionally set: `process.env.NODE_ENV === 'production'`. In development this allows the cookie to be sent over HTTP (localhost), while in production it enforces HTTPS-only transmission.

### 5.4 `routes/users.ts` — Admin Route Hardening

All four user management endpoints share the same middleware chain:
```ts
requireAuth, requireRole(['admin'])
```

Additional hardening in the user creation route:
- Password is **never** accepted from the request and stored directly — it is always hashed first: `bcrypt.hash(password, 10)`
- The `select` option in `prisma.user.create` explicitly controls which fields are returned, ensuring `passwordHash` cannot appear in the response even if the schema changes

Duplicate email handling uses Prisma's error code `P2002` (unique constraint violation) to return a descriptive 400 rather than leaking a 500 stack trace.

### 5.5 Frontend RBAC — UX Not Security

The frontend enforces the same role restrictions **only as UX improvements**:

- `Navbar.tsx`: The "Users" link renders only when `currentUser?.role === 'admin'`
- `EventsPage.tsx`: The "Export" button renders only when `!isViewer`; row clicks are disabled for viewers (`onClick={isViewer ? undefined : ...}`)

These are explicitly documented as UX-only — they prevent normal users from hitting 403 errors, but they provide zero security since any user can make direct API calls. The backend is always the source of truth.

### 5.6 `prisma/schema.prisma` — Minimal Attack Surface

The `User` model contains exactly what the application needs: `id`, `email`, `passwordHash`, `role`, `status`. There are no unnecessary fields that could leak information or be targeted for mass assignment.

The `status` field defaults to `'active'`, ensuring new accounts are enabled by default without requiring an explicit field.

---

## 6. Problems Encountered and Solutions

### Problem 1 — Migration Schema Mismatch ✓ Fixed

**Discovery**: The initial migration file (`prisma/migrations/20260510160606_init/migration.sql`) defined a `username` field and a `User_username_key` unique index, but the current `schema.prisma` defines an `email` field with `@unique`. Running `prisma migrate deploy` in a fresh environment would create a `username` column and fail because the schema references `email`.

**Root cause**: The scaffold was generated with `username`, then the schema was changed to `email` without updating the migration file.

**Fix applied**: The migration file was updated to fully match the live schema:
```sql
-- Before (scaffold artefact — wrong column name, missing status field)
CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "username" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'analyst'
);
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- After (matches schema.prisma exactly)
CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'analyst',
    "status" TEXT NOT NULL DEFAULT 'active'
);
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
```

The migration file and `schema.prisma` are now fully consistent — `email`, `passwordHash`, `role`, and `status` all match. `prisma migrate deploy` will succeed in a fresh environment.

### Problem 2 — `.env` Committed to the Repository

**Discovery**: The `.gitignore` contains `.env` and `.env.*`, but `Part2-Security-Operations-Portal/.env` is present in the repository with a `JWT_SECRET` value. Normally this would be blocked by `.gitignore` — however the file is tracked (the gitignore entry might have been added after the file was first committed, or the project root `.gitignore` may not cover the subdirectory).

**Mitigation in place**: The committed `JWT_SECRET` value (`"your-secure-jwt-secret-change-in-production"`) is a placeholder string, not a real secret. The README prominently warns that this must be replaced. The `auth.ts` middleware also has a fallback `'dev-secret-change-in-production'` for cases where the env var is absent.

**The correct fix**: Remove `Part2-Security-Operations-Portal/.env` from version control with `git rm --cached`, ensure `.gitignore` covers it, and document an `.env.example` file. In production, inject secrets via the OS environment (vault, secrets manager) rather than any file.

### Problem 3 — Single API URL in `api.ts` Hard-Codes Port 4000 ✓ Fixed

**Discovery**: `const API_URL = "http://localhost:4000"` was a hardcoded string in the frontend source. If the backend port changes (e.g., due to a conflict), two files would need updating: this constant and the CORS `origin` in `server.ts`.

**Fix applied**: `api.ts` now reads the URL from the Vite environment variable with the current value as a fallback:
```ts
const API_URL = import.meta.env.VITE_API_URL || "http://localhost:4000";
```
The port 4000 fallback preserves zero-config local development. To point at a different backend, set `VITE_API_URL=http://your-host:port` in `.env.local` without any code change.

### Problem 4 — JWT Secret Duplicated Across Two Files

**Discovery**: `JWT_SECRET` is declared identically in both `middleware/auth.ts` and `routes/auth.ts`:
```ts
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
```

This means the fallback value and the env variable name must be kept in sync across two files. If one is updated, a subtle bug where tokens signed with one secret are verified against a different secret would cause intermittent 401 errors.

**Solution applied**: Both files read from `process.env.JWT_SECRET`. Since the actual value is the same in both, they are functionally correct. The architectural fix would be to export the secret from a dedicated `src/config.ts` module and import it in both places — a single source of truth.

### Problem 5 — `AUTH_SOFTFAIL` Weight Inconsistency in Code vs. Comment

**Note**: This finding applies to the Part 1 codebase, not Part 2, but is documented here for completeness: the `SCORING_WEIGHTS` object does not include an `AUTH_SOFTFAIL` key. Instead, the softfail penalty is computed inline as `Math.round(SCORING_WEIGHTS.AUTH_FAIL / 2)` — which equals −12 at runtime. This is correct and intentional but means the REVIEW.md section on `SCORING_WEIGHTS` shows a constant that does not have a named entry in the object. A dedicated `AUTH_SOFTFAIL: -12` entry in the constants would improve code clarity.

### Problem 6 — `WelcomeBanner.tsx` Exposed in Deployed Build

**Discovery**: `WelcomeBanner.tsx` contains the original assignment brief text as a hardcoded string inside the component. It describes the application as "frontend-only" and instructs the reader to "build a backend." This text is accurate for the original scaffold but misleading after the backend has been built.

**Mitigation in place**: The component is not rendered anywhere in the current `App.tsx` or any page. It exists in the source tree but is dead code in the built application.

---

## 7. Key Learnings

### 7.1 HttpOnly Cookies vs. localStorage for Auth Tokens

This is one of the most important web security decisions: where to store a session token.

**localStorage** is simple — JavaScript can write `localStorage.setItem('token', jwt)` and read it back on every request. But any XSS vulnerability, no matter how minor, gives the attacker full read access to localStorage. The token is gone.

**HttpOnly cookies** are inaccessible to JavaScript by design. The browser sends them automatically on requests but never exposes them to `document.cookie`, `window.localStorage`, or any JS API. An XSS injection cannot steal what JavaScript cannot read.

The trade-off: cookies introduce **CSRF risk** (cross-site requests also include cookies automatically). This is neutralised by `SameSite=Strict`, which tells the browser to never attach the cookie to cross-origin requests. The combination of `HttpOnly + SameSite=Strict` gives you XSS immunity and CSRF immunity simultaneously.

The pattern in `routes/auth.ts`:
```ts
res.cookie('token', token, {
  httpOnly: true,
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 24 * 60 * 60 * 1000,
});
```
...is the correct, production-grade implementation of this pattern.

### 7.2 The RBAC Middleware Chain Pattern

Separating authentication (`requireAuth`) from authorization (`requireRole`) into two composable middleware functions is a design pattern worth internalising. It maps directly to the two questions that access control must answer:

1. **Authentication**: "Who are you?" — verified by checking the JWT signature and expiry
2. **Authorization**: "What are you allowed to do?" — verified by checking the role claim against the allowed list

The chaining `requireAuth, requireRole(['admin'])` is self-documenting: the route signature tells you at a glance both what kind of authentication is required and what role is needed. Adding a new role constraint is one word change.

### 7.3 Zod `.strict()` as a Defense Against Mass Assignment

Mass Assignment is a class of vulnerability where an attacker sends extra fields in a request body that the server maps directly to a database model. Classic examples: `{ "role": "admin" }` appended to a profile update, or `{ "id": "target-user-id" }` in a creation request.

Zod's `.strict()` makes the schema a closed set — exactly the declared fields, nothing else. This is a structural defense: the validation fails before the route handler runs, so even if the ORM would otherwise map the extra field, it never gets the chance.

Without `.strict()`, Zod passes unknown fields through. With `.strict()`, any undeclared field causes a `ZodError`. This is the correct default for any endpoint that writes to a database.

### 7.4 Prisma ORM as Structural SQL Injection Prevention

SQL injection is possible only when user input is concatenated into a SQL string. Parameterised queries prevent this by sending the query structure and the user data separately — the database driver handles quoting and escaping, not the developer.

Prisma never concatenates user input into SQL. Every `prisma.user.findUnique({ where: { email } })` call is compiled to a prepared statement. The developer cannot accidentally introduce SQL injection through normal Prisma API usage — the framework's design makes the vulnerable pattern impossible to express.

This is the right mental model for ORM security: it is not just "convenience" but "structural immunity." Contrast this with raw SQL construction, where SQL injection is possible on every query that includes user input.

### 7.5 Anti-Enumeration and Identical Error Responses

User enumeration is a low-effort, high-value reconnaissance step for an attacker: if the login endpoint reveals which emails exist, the attacker has a verified list of targets for credential stuffing or phishing.

The implementation in `routes/auth.ts`:
```ts
if (!user) {
  // Dummy compare keeps response time equal to the wrong-password branch,
  // preventing user enumeration via timing differences.
  await bcrypt.compare(password, '$2b$10$dummyHashToPreventTimingAttacks1234567890123456789012');
  return res.status(401).json({ error: 'Invalid email or password' });
}
// ... account status check ...
const isValidPassword = await bcrypt.compare(password, user.passwordHash);
if (!isValidPassword) {
  return res.status(401).json({ error: 'Invalid email or password' });
}
```

Both branches return the **same status code (401) and the same message body**. An attacker observing the response cannot determine whether the email or the password was wrong.

Response timing is also normalised: the "user not found" branch calls `bcrypt.compare` against a dummy hash before returning, ensuring both branches take approximately the same ~100ms. Without this, a timing measurement could distinguish "email not found" (instant return) from "wrong password" (bcrypt delay) — a timing oracle that leaks which emails exist.

### 7.6 Defense in Depth — No Single Point of Failure

The project demonstrates the defense-in-depth principle across multiple layers:

| Layer | Control |
|-------|---------|
| Network | TLS in production (described in README) |
| Transport | CORS whitelist (only trusted origin) |
| Application | Helmet headers (XSS, clickjacking, MIME sniffing) |
| Rate limiting | Global (100/15min) + login-specific (5/15min) |
| Input validation | Zod `.strict()` on all request bodies |
| Authentication | JWT in HttpOnly + SameSite=Strict cookie |
| Authorisation | `requireAuth` + `requireRole` per route |
| Data | Prisma ORM (parameterised queries) |
| Credentials | bcrypt hashing, explicit field exclusion in responses |
| Frontend | RBAC-driven UI hiding, internal field sanitization |

If any single control is weakened or bypassed, the others still hold. This is the correct architecture for a system that handles sensitive data.

### 7.7 Stateless JWT and Its Limitations

JWTs are stateless: once issued, the server cannot revoke them without additional infrastructure. A JWT remains valid until its `expiresIn` window (24 hours here) even if:
- The user logs out (the cookie is cleared, but the token itself is still cryptographically valid)
- The user's account is disabled (the next login is blocked, but an existing token works until expiry)
- A security breach is detected and you want to invalidate all sessions

The README correctly identifies a **Redis-backed token blocklist** as the production solution: write revoked token JTIs to Redis with a TTL matching the token's remaining lifetime, and check Redis on every authenticated request. This adds one fast key-value lookup per request but provides immediate revocation. Understanding this limitation is critical before deploying JWT-based auth to production.

---

## 8. End-to-End Code Flow (Annotated)

### Authenticated Event Fetch

```
User opens browser → React loads → App.tsx mounts
       │
       ├── useEffect: GET /api/auth/me
       │       requireAuth: reads cookie (HttpOnly, invisible to JS)
       │       jwt.verify(token, JWT_SECRET) → decoded user
       │       returns { id, role } → setCurrentUser(decoded)
       │
       └── EventsPage renders → useEffect: GET /api/events
               requireAuth: token present, valid → passes
               readFileSync(mock_events.json) → res.json(events)
               setEvents(data) → table renders
```

### Admin Creates a User

```
Admin fills in "New User" form → handleAddUser
       │
       ├── POST /api/users
       │       requireAuth: valid admin JWT → passes
       │       requireRole(['admin']): role === 'admin' → passes
       │       zod .strict(): email, password, role only → passes
       │       bcrypt.hash(password, 10) → passwordHash
       │       prisma.user.create({ data: { email, passwordHash, role } })
       │       select: { id, email, role, status } → passwordHash excluded
       │       res.status(201).json(createdUser)
       │
       └── Frontend: setUsers(prev => [...prev, { ...createdUser, password: '***' }])
```

---

## 9. Production Deployment Architecture (Summary)

The README describes the full strategy in detail. The key decisions and their security rationale:

| Decision | Security rationale |
|----------|-------------------|
| Reverse proxy (Nginx/ALB) for TLS | Node process never exposed directly; TLS termination centralised |
| `app.set('trust proxy', 1)` | Rate limiter sees real client IPs, not proxy IP |
| PostgreSQL on RDS with encryption at rest | AES-256, point-in-time recovery, VPC isolation |
| Secrets via Vault / AWS Secrets Manager | No `.env` files in production; secrets rotated without redeployment |
| Redis-backed JWT blocklist | Immediate revocation on logout/account disable |
| Centralised audit logging to SIEM | Forensic record of all privileged actions |

---

## 10. Known Limitations and Future Work

**No pagination on `/api/events`**: All events are returned in a single response. At scale (thousands of events), this becomes a denial-of-service vector via large response payloads. Pagination with cursor-based or offset-based parameters should be added.

**`dev.db` and `prisma/dev.db` duplicated**: Two SQLite database files exist — one at the project root and one inside `prisma/`. Both are excluded by `.gitignore`. The `DATABASE_URL="file:./dev.db"` in `.env` resolves to the project root, so `prisma/dev.db` is likely an orphaned artefact from an earlier configuration.

**`WelcomeBanner.tsx` is dead code**: The component is not rendered anywhere in the current application. It can be removed to reduce bundle size and avoid confusion.

**`AUTH_SOFTFAIL` not in `SCORING_WEIGHTS` constant** (Part 1): The softfail penalty (−12) is computed inline as `Math.round(AUTH_FAIL / 2)`. Adding an explicit `AUTH_SOFTFAIL: -12` entry to `SCORING_WEIGHTS` would make the constants table in the REVIEW complete and self-documenting.

---

*Previously documented limitations that have been resolved:*
- ~~JWT timing oracle on login~~ — fixed: dummy `bcrypt.compare` in the user-not-found branch normalises response time.
- ~~No role validation in `createUserSchema`~~ — fixed: `role` field now uses `z.enum(['admin', 'analyst', 'viewer'])`.
- ~~Stale migration file~~ — fixed: `migration.sql` updated to use `email` and `User_email_key` index.
- ~~Hard-coded `API_URL` in `api.ts`~~ — fixed: reads from `import.meta.env.VITE_API_URL` with localhost fallback.
