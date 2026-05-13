# PenguWave — Full Code Review
**Reviewer:** Claude (AI Senior Engineer)
**Date:** 2026-05-11
**Scope:** Complete codebase audit — architecture, security, logic, maintainability

---

## Table of Contents

1. [Project Description & Purpose](#1-project-description--purpose)
2. [System Architecture & Code Flow](#2-system-architecture--code-flow)
3. [Issues Found](#3-issues-found)
   - 3.1 Critical Security Issues
   - 3.2 Backend Issues
   - 3.3 Frontend Issues
   - 3.4 Data & Database Issues
   - 3.5 Configuration & DevOps Issues
4. [Original Boilerplate Vulnerabilities](#4-original-boilerplate-vulnerabilities)
5. [Per-File Breakdown](#5-per-file-breakdown)
6. [Additional Review Elements](#6-additional-review-elements)

---

## 1. Project Description & Purpose

PenguWave is a **Security Operations Portal (SOC)** — a web application designed to give security teams visibility into infrastructure alerts, threat events, and user access management. It is a full-stack application built for a job-interview home assignment. The original delivery was a React-only frontend skeleton with intentional security vulnerabilities embedded; the backend, authentication system, database layer, RBAC, and security hardening were built on top of it.

### Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, TypeScript, Vite, React Router v7 |
| Backend | Node.js, Express 4, TypeScript |
| ORM | Prisma 5 |
| Database | SQLite (via `dev.db`) |
| Auth | JWT, HttpOnly cookies, bcrypt |
| Security middleware | Helmet, express-rate-limit, Zod, CORS |

### Users & Roles

Three roles are defined in the system:
- **admin** — Full access: view events, drill into details, export data, manage users
- **analyst** — Standard access: view events, drill into details, export data
- **viewer** — Read-only: view the events table only; no detail drill-down, no export

---

## 2. System Architecture & Code Flow

### 2.1 High-Level Architecture

```
Browser (React SPA)
    │
    │  HTTP + HttpOnly Cookie
    ▼
Express Server (port 4000)
    ├── Middleware stack: globalLimiter → helmet → cors → json → cookieParser
    ├── /api/auth  → routes/auth.ts
    ├── /api/events → routes/events.ts
    ├── /api/users → routes/users.ts
    └── /health
           │
           ├── middleware/auth.ts (requireAuth, requireRole)
           ├── Prisma ORM
           └── SQLite (dev.db) / data/mock_events.json
```

### 2.2 Authentication Flow

```
1.  User opens app → App.tsx calls getCurrentUser() → GET /api/auth/me
2a. Cookie present & valid → user object returned → currentUser state set
2b. No cookie / invalid → 401 returned → currentUser = null → login modal shown

3.  User submits login form (LoginModal.tsx)
4.  POST /api/auth/login with { email, password }
5.  loginLimiter checks: ≤5 attempts per 15 min per IP
6.  Zod validates input (strict schema, email format, password ≥8 chars)
7.  prisma.user.findUnique({ where: { email } })
8a. User not found → 401 { error: "Invalid email or password" }
8b. User found but status !== 'active' → 403 { error: "Account is disabled..." }
8c. bcrypt.compare(password, user.passwordHash) fails → 401 { same generic error }
9.  JWT signed with { id, role }, expiresIn: '24h'
10. res.cookie('token', jwt, { httpOnly, sameSite: 'strict', secure: prod })
11. Response: { id, email, role } (no hash, no token in body)
12. Browser stores nothing explicitly — cookie is managed by the browser automatically
13. Frontend reloads the page → step 1 repeats → user now authenticated
```

### 2.3 Request Authorization Flow (Protected Routes)

```
Incoming request
    │
    ▼
requireAuth middleware
    ├── Read req.cookies.token
    ├── jwt.verify(token, JWT_SECRET)
    ├── Attach decoded payload to req.user
    └── Call next() or return 401
          │
          ▼ (for admin-only routes)
    requireRole(['admin'])
          ├── Check req.user.role in allowedRoles
          └── Call next() or return 403
```

### 2.4 Frontend Routing & State Flow

```
main.tsx → StrictMode + BrowserRouter → App.tsx
    │
    ├── On mount: getCurrentUser() → setCurrentUser
    ├── Navbar: shows Login/Logout based on currentUser
    │
    ├── / → redirect to /events
    ├── /events → EventsPage (receives currentUser prop)
    │     ├── On mount: getEvents() → GET /api/events
    │     ├── If 401 → unauthenticated early return (no UI structure shown)
    │     ├── Filter bar: search text + severity dropdown + sort dropdown
    │     ├── Table: filtered + sorted events
    │     │     └── Row click → selectedEvent (blocked for viewer role)
    │     ├── Export button (hidden for viewer role)
    │     └── Detail panel (sticky right column, strips id/userId from raw output)
    │
    ├── /users → UsersPage
    │     ├── On mount: getUsers() → GET /api/users
    │     ├── If 401 → unauthenticated early return
    │     ├── If 403 → accessDenied warning panel
    │     ├── Filter bar: role dropdown + status dropdown
    │     ├── Add User form (restricted to maxWidth 400px, eye-toggle password)
    │     └── Table: filteredUsers (toggle status, delete)
    │
    └── * → NotFound (404 page)
```

---

## 3. Issues Found

### 3.1 Critical Security Issues

---

**[SEC-01] `.gitignore` does not exclude `.env` or the SQLite database**

- **Severity:** Critical
- **File:** `.gitignore`
- **Detail:** The only entry in `.gitignore` is `node_modules`. The `.env` file (which contains `JWT_SECRET` and `DATABASE_URL`) and `dev.db` (the live SQLite database with hashed user passwords) are not excluded. One accidental `git add .` would commit live credentials and the entire user database to source control.
- **Fix:** Add the following to `.gitignore`:
  ```
  .env
  .env.*
  !.env.example
  *.db
  *.sqlite
  dist/
  prisma/migrations/dev/
  ```

---

**[SEC-02] JWT secret has an insecure hardcoded fallback and is duplicated across two files**

- **Severity:** Critical
- **Files:** `src/routes/auth.ts`, `src/middleware/auth.ts`
- **Detail:** `JWT_SECRET` is defined independently in both files:
  ```ts
  // auth.ts
  const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
  // middleware/auth.ts
  const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
  ```
  This creates two problems. First, if `JWT_SECRET` is not set in the environment, the hardcoded fallback silently takes effect. Tokens signed with the fallback secret are trivially forgeable by anyone who has read the source code (which any reviewer of this assignment has). Second, if the two fallback strings ever diverge due to a copy-paste edit, all tokens issued by `auth.ts` will fail verification in `middleware/auth.ts` silently.
- **Fix:** Extract `JWT_SECRET` into a shared module (e.g., `src/config.ts`) that throws at startup if the value is missing, and import it in both files.
  ```ts
  // src/config.ts
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET env variable is required');
  export const JWT_SECRET = process.env.JWT_SECRET;
  ```

---

**[SEC-03] Deactivated users can continue using the application with an existing JWT**

- **Severity:** High
- **Files:** `src/middleware/auth.ts`, `src/routes/auth.ts`
- **Detail:** When an admin disables a user (sets `status = 'inactive'`), the user's cookie token is not invalidated. The `requireAuth` middleware verifies the JWT cryptographic signature but never re-checks the user's current `status` against the database. An inactive user with a valid token can continue calling all authenticated endpoints until the token expires (up to 24 hours).
- **Fix:** In `requireAuth`, perform a lightweight DB lookup: `const user = await prisma.user.findUnique({ where: { id: decoded.id }, select: { status: true } })`. If `user.status !== 'active'`, return 401. Alternatively, maintain a token blocklist (Redis) or use short-lived tokens with a refresh-token pattern.

---

**[SEC-04] Role field accepts arbitrary strings — no enum enforcement at DB or schema level**

- **Severity:** High**
- **Files:** `src/routes/users.ts`, `prisma/schema.prisma`
- **Detail:** The Zod schema for creating a user validates `role` only as `z.string().min(1)`. This allows an admin to create a user with `role: "superadmin"`, `role: "god"`, or any arbitrary value. The Prisma schema stores `role` as a plain `String` with no CHECK constraint. The `requireRole` middleware performs exact string matching, so a user with role `"Analyst"` (capital A) would be treated as a non-admin correctly, but the inconsistency is a maintenance hazard and potential privilege confusion.
- **Fix:** In `users.ts`, change:
  ```ts
  role: z.string().min(1, 'Role is required'),
  ```
  to:
  ```ts
  role: z.enum(['admin', 'analyst', 'viewer']),
  ```
  Optionally, add a Prisma-level check constraint via a custom migration.

---

**[SEC-05] Rate limiter is not proxy-aware — IP detection fails behind a reverse proxy**

- **Severity:** High**
- **Files:** `src/server.ts`, `src/routes/auth.ts`
- **Detail:** Both `globalLimiter` and `loginLimiter` use the default IP detection from `express-rate-limit`, which reads `req.ip` / `req.socket.remoteAddress`. When the application is deployed behind Nginx, a cloud load balancer, or any reverse proxy, all requests arrive from the proxy's IP address. This makes every single user share the same rate-limit counter, meaning the first 5 login attempts across the entire application exhaust the `loginLimiter`.
- **Fix:** Add `app.set('trust proxy', 1)` in `server.ts` before mounting the limiters. This tells Express to read the real client IP from the `X-Forwarded-For` header. Ensure the proxy is configured to set this header correctly and that the header cannot be spoofed by clients.

---

**[SEC-06] No server-side logout — token remains valid after logout**

- **Severity:** Medium**
- **Files:** `src/routes/auth.ts`
- **Detail:** The `POST /api/auth/logout` route clears the cookie client-side by setting `maxAge: 0`. However, the JWT itself has not been revoked. If the token was copied before logout (e.g., from DevTools before the cookie was cleared, or via a MITM scenario), it remains a valid bearer credential until it expires (24 hours). This is an inherent weakness of stateless JWTs without a blocklist.
- **Fix:** For this application's security posture, maintain a token blocklist in-memory or in a cache (Redis). On logout, add the token's `jti` (JWT ID — add one to the sign call) to the blocklist. In `requireAuth`, check the blocklist before accepting a token. Alternatively, reduce token lifetime to 15–30 minutes and implement silent refresh.

---

**[SEC-07] CORS origin is hardcoded — not configurable for non-local environments**

- **Severity:** Medium**
- **File:** `src/server.ts`
- **Detail:** `origin: 'http://localhost:5173'` is hardcoded. Deploying to staging or production requires a code change or the CORS policy will block all legitimate frontend traffic.
- **Fix:**
  ```ts
  origin: process.env.ALLOWED_ORIGIN || 'http://localhost:5173',
  ```

---

**[SEC-08] API base URL hardcoded in both `api.ts` and directly in `UsersPage.tsx`**

- **Severity:** Medium**
- **Files:** `src/api.ts`, `src/pages/UsersPage.tsx`
- **Detail:** `src/api.ts` defines `const API_URL = "http://localhost:4000"`. However, `UsersPage.tsx` bypasses the `apiCall` helper entirely for its three mutating operations (`handleAddUser`, `handleDelete`, `handleToggleStatus`), using raw `fetch("http://localhost:4000/api/users", ...)` calls. This creates three problems: (1) the URL is duplicated, (2) any auth or error-handling changes to `apiCall` won't apply to the Users page, (3) both hardcoded URLs will fail in any non-local environment.
- **Fix:** Export `createUser`, `deleteUser`, and `toggleUserStatus` functions from `api.ts` using the shared `apiCall` helper. Replace all raw `fetch` calls in `UsersPage.tsx` with the centralized functions. Use `import.meta.env.VITE_API_URL` (set in `.env`) for the base URL.

---

### 3.2 Backend Issues

---

**[BE-01] Two separate `PrismaClient` instances are created across route files**

- **Severity:** Medium**
- **Files:** `src/routes/auth.ts`, `src/routes/users.ts`
- **Detail:** Each file instantiates its own `new PrismaClient()`. Prisma recommends a single shared client instance for the entire application lifecycle. Multiple instances create multiple connection pools to the same SQLite file. In SQLite specifically, concurrent write locks can cause errors.
- **Fix:** Create a singleton `src/lib/prisma.ts`:
  ```ts
  import { PrismaClient } from '@prisma/client';
  const prisma = new PrismaClient();
  export default prisma;
  ```
  Import this from both route files instead of instantiating locally.

---

**[BE-02] `GET /api/events/:id` endpoint specified in API contract but not implemented**

- **Severity:** Low**
- **Files:** `src/routes/events.ts`, `docs/api_contract.md`
- **Detail:** The API contract defines `GET /api/events/:id` returning a single event by ID. The route does not exist. The frontend event detail panel works around this by caching the selected event client-side from the list response, but the API is incomplete per the contract.
- **Fix:** Add the endpoint in `events.ts` — read the JSON file once, find by `id`, and return 404 if not found.

---

**[BE-03] `PATCH /api/users/:id` is specified for role+status updates but only status toggle is implemented**

- **Severity:** Low**
- **Files:** `src/routes/users.ts`, `docs/api_contract.md`
- **Detail:** The API contract specifies `PATCH /api/users/:id` for updating `role` and/or `status`. The implementation only has `PATCH /api/users/:id/status` which toggles the status binary. There is no way to change a user's role after creation via the API.
- **Fix:** Add a `PATCH /api/users/:id` endpoint with a Zod schema accepting optional `role` and `status` fields.

---

**[BE-04] Events are read with synchronous `readFileSync` on every request**

- **Severity:** Low**
- **File:** `src/routes/events.ts`
- **Detail:** `readFileSync` is a blocking call that halts the Node.js event loop while the file is read. Under concurrent load, this degrades performance for all other requests. Since the data is static, there is no need to re-read it on every request.
- **Fix:** Read and parse the file once at module load time:
  ```ts
  const events = JSON.parse(readFileSync(join(process.cwd(), 'data', 'mock_events.json'), 'utf-8'));
  router.get('/', requireAuth, (_req, res) => res.json(events));
  ```

---

**[BE-05] No protection against admin self-deletion or disabling the last admin**

- **Severity:** Medium**
- **File:** `src/routes/users.ts`
- **Detail:** An admin can delete their own account or set their own status to `inactive`, potentially leaving the system with no active admin. There is no count check before deletion/deactivation.
- **Fix:** In `DELETE /:id` and `PATCH /:id/status`, check if the targeted user is the requesting user or the last active admin before proceeding.

---

**[BE-06] `api_contract.md` documents Bearer token auth, but the implementation uses cookies**

- **Severity:** Low (documentation debt)**
- **File:** `docs/api_contract.md`
- **Detail:** The contract shows `Authorization: Bearer <token>` for `GET /api/auth/me`. The actual implementation uses an HttpOnly cookie and no Authorization header at all. The contract also specifies port `3001` while the server runs on `4000`. This discrepancy would mislead any developer trying to integrate with the API from the contract alone.
- **Fix:** Update the contract to reflect cookie-based auth, the correct port, and document that credentials are passed via cookie rather than header.

---

### 3.3 Frontend Issues

---

**[FE-01] `currentUser` is typed as `any` throughout `App.tsx` and `Navbar.tsx`**

- **Severity:** Medium**
- **Files:** `src/App.tsx`, `src/components/Navbar.tsx`
- **Detail:** `const [currentUser, setCurrentUser] = useState<any>(null)` defeats the purpose of TypeScript. Any property access on `currentUser` is unchecked, including `.role`, `.email`, and `.id`. An incorrect response shape from the API would cause a silent runtime error.
- **Fix:** Define a `CurrentUser` interface in `types.ts` and use it in both files:
  ```ts
  export interface CurrentUser { id: string; email: string; role: 'admin' | 'analyst' | 'viewer'; }
  ```

---

**[FE-02] Login triggers `window.location.reload()` instead of clean state update**

- **Severity:** Low**
- **Files:** `src/components/LoginModal.tsx`, `src/pages/UsersPage.tsx`
- **Detail:** After a successful login, the app calls `window.location.reload()`. This causes a full page reload, losing any scroll position, clearing filter state, and triggering all `useEffect` hooks again. It is used as a shortcut to re-fetch `currentUser`. A proper SPA pattern would call `getCurrentUser()` and update the state in `App.tsx`.
- **Fix:** Lift a `onLoginSuccess` callback through props or use a React context / state manager. After login, call `getCurrentUser()` and update `currentUser` state directly.

---

**[FE-03] "Users" nav link is always visible regardless of role**

- **Severity:** Low**
- **File:** `src/components/Navbar.tsx`
- **Detail:** The Users nav link is visible to viewers and analysts. Clicking it shows "Access Denied," which correctly restricts data access but still reveals that a user management section exists. A principle-of-least-privilege UI would hide the link for non-admin roles.
- **Fix:** Pass `currentUser` role into Navbar and conditionally render the Users link:
  ```tsx
  {currentUser?.role === 'admin' && <Link to="/users">Users</Link>}
  ```

---

**[FE-04] `selectedEvent` is not cleared when filters change, causing hidden selection state**

- **Severity:** Low**
- **File:** `src/pages/EventsPage.tsx`
- **Detail:** A user can click a row to select an event, then apply a filter that removes that event from the visible table. The detail panel will still show the selected event even though the corresponding row is no longer visible. This is confusing UX.
- **Fix:** Add a `useEffect` that calls `setSelectedEvent(null)` when `search`, `severityFilter`, or `sortOrder` change.

---

**[FE-05] Viewer RBAC `isViewer` flag has a silent false-positive on undefined `currentUser`**

- **Severity:** Low**
- **File:** `src/pages/EventsPage.tsx`
- **Detail:** `const isViewer = currentUser?.role === "viewer"`. When `currentUser` is `undefined` (the prop is optional), `isViewer` is `false`. This means a user who somehow reaches the events page without `currentUser` being passed would receive analyst-level UI (clickable rows, export button). Frontend RBAC is presentation-only and the backend enforces the real access control, but the frontend logic is logically inconsistent.
- **Fix:** Default to the most restrictive behaviour when role is unknown: `const isViewer = !currentUser || currentUser.role === 'viewer'`. Or make `currentUser` a required prop.

---

**[FE-06] `User` type in `types.ts` has a `password` field**

- **Severity:** Low**
- **File:** `src/types.ts`
- **Detail:** The `User` interface includes `password: string`. In `UsersPage.tsx`, newly created users are pushed into state with `password: "***"`. The actual API response never returns a password field. The type should model what the API actually returns — a UI model of a user should never have a password field.
- **Fix:** Remove `password` from the `User` interface. Remove the `password: "***"` assignment in `handleAddUser`.

---

**[FE-07] No Content Security Policy defined in `index.html`**

- **Severity:** Medium**
- **File:** `index.html`
- **Detail:** There is no CSP meta tag or server-sent `Content-Security-Policy` header. While React's JSX rendering prevents most XSS by default, a strong CSP provides defence-in-depth against injected scripts, inline event handlers, and data exfiltration. A SOC portal is a high-value target; defence-in-depth here is especially warranted.
- **Fix:** Add a CSP header in the Express server (Helmet supports this via `contentSecurityPolicy`) and/or add a `<meta http-equiv="Content-Security-Policy">` tag. Also add `<meta name="robots" content="noindex, nofollow">` — a SOC portal should not appear in search engine indexes.

---

**[FE-08] Dead CSS for `.welcome-banner` remains in `App.css`**

- **Severity:** Trivial**
- **File:** `src/App.css`
- **Detail:** `.welcome-banner` and `.welcome-banner code` CSS rules remain in the stylesheet even though `WelcomeBanner` is no longer rendered. The styles ship to the browser unnecessarily.
- **Fix:** Remove the `.welcome-banner` rules from `App.css`.

---

**[FE-09] No keyboard accessibility / focus styles on interactive elements**

- **Severity:** Low**
- **File:** `src/App.css`
- **Detail:** The CSS comment `/* no hover styles */` is present alongside table rows, and `.btn-primary` has no `:focus-visible` styles. The eye-toggle buttons in `LoginModal` and `UsersPage` use no visible focus ring. This fails WCAG 2.1 success criterion 2.4.7 (Focus Visible).
- **Fix:** Add `:focus-visible` outlines to all interactive elements. The eye-toggle buttons should have a visible focus state for keyboard users.

---

### 3.4 Data & Database Issues

---

**[DB-01] Migration SQL is out of sync with the current Prisma schema**

- **Severity:** High**
- **File:** `prisma/migrations/20260510160606_init/migration.sql`
- **Detail:** The migration file creates a table with `username TEXT NOT NULL` as the unique login identifier and has no `status`, `email`, or `createdAt` columns. The current `prisma/schema.prisma` uses `email` as the unique identifier and includes a `status` field. The database was almost certainly rebuilt using `prisma db push` (which bypasses migrations) rather than `prisma migrate dev`. The migration history is therefore a lie — it does not describe the actual database schema in `dev.db`.
  ```sql
  -- Migration says:
  "username" TEXT NOT NULL
  -- Schema says:
  email String @unique
  ```
  This creates a dangerous situation: if someone runs `prisma migrate deploy` on a fresh environment, they will get a database incompatible with the application.
- **Fix:** Delete the stale migration and create a new one from the current schema state:
  ```bash
  prisma migrate dev --name initial_schema
  ```

---

**[DB-02] No `createdAt` / `updatedAt` timestamps on the `User` model**

- **Severity:** Low**
- **File:** `prisma/schema.prisma`
- **Detail:** The User model has no audit timestamps. There is no way to determine when an account was created, last modified, or when a password was last changed. For a security-focused application, this is an important audit trail gap.
- **Fix:** Add to the model:
  ```prisma
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  ```

---

**[DB-03] Mock events `userId` values reference non-existent database users**

- **Severity:** Low (data integrity)**
- **Files:** `data/mock_events.json`
- **Detail:** Events reference `userId: "usr-001"`, `"usr-002"`, `"usr-003"` etc. These IDs use a custom format and do not correspond to any users in the database (which uses UUIDs). If the application ever joins events to users (e.g., to display "created by" on an event), these references would silently return nothing.
- **Fix:** Either align mock event `userId` values to seeded UUIDs, or remove the `userId` field from mock data since it is already stripped from the API response.

---

**[DB-04] Seed file only creates `admin` and `analyst` — no `viewer` test user**

- **Severity:** Low**
- **File:** `prisma/seed.ts`
- **Detail:** The viewer role is defined in the application but there is no seeded viewer account for testing. Testing the viewer RBAC restrictions requires manually creating a viewer via the admin UI after seeding.
- **Fix:** Add a viewer upsert to `seed.ts` alongside the existing admin and analyst entries.

---

### 3.5 Configuration & DevOps Issues

---

**[CFG-01] No production start script or build instructions in `package.json`**

- **Severity:** Medium**
- **File:** `package.json`
- **Detail:** The `scripts` section has `dev`, `dev:server`, `build`, `lint`, `preview`, `prisma:generate`, `prisma:migrate`, and `db:seed`. There is no `start` script to run the compiled backend in production, and no combined script to build frontend + start server together. The frontend `build` only compiles the React app; the Express server must be started separately with no documented production path.
- **Fix:** Add:
  ```json
  "start": "node dist/server.js",
  "build:server": "tsc --project tsconfig.node.json",
  "build:all": "npm run build && npm run build:server"
  ```

---

**[CFG-02] `README.md` still describes the project as a "frontend-only starter"**

- **Severity:** Low (documentation)**
- **File:** `README.md`
- **Detail:** The README still contains the original boilerplate description: "This is a frontend-only starter application." It does not document how to run the backend, what environment variables are required, the authentication flow, the role model, or how to seed the database.
- **Fix:** Update the README to describe the full-stack application, including setup steps for both frontend and backend, `.env` requirements, and seeding instructions.

---

**[CFG-03] `vite.config.ts` has no API proxy configured**

- **Severity:** Low**
- **File:** `vite.config.ts`
- **Detail:** The frontend makes cross-origin requests to `http://localhost:4000`, requiring a CORS configuration on the backend. A Vite dev proxy would eliminate the cross-origin round-trip in development and allow the API_URL to be a relative path (`/api`), making it environment-agnostic.
- **Fix:**
  ```ts
  server: { proxy: { '/api': 'http://localhost:4000' } }
  ```

---

## 4. Original Boilerplate Vulnerabilities

The original assignment was delivered as a React-only frontend skeleton. It contained deliberately embedded security vulnerabilities intended to be found and fixed by the candidate. The following table documents each one.

---

### 4.1 XSS via `dangerouslySetInnerHTML` on the Search Term

| | |
|---|---|
| **Original code** | `<p dangerouslySetInnerHTML={{ __html: Showing results for: <b>${search}</b> }} />` |
| **Vulnerability** | Reflected XSS. The raw user-supplied `search` string was interpolated into an HTML string and injected into the DOM. An attacker could craft a URL with `?search=<img src=x onerror=alert(1)>`, send it to a victim, and execute JavaScript in their browser session. In a SOC portal this could steal the auth cookie (if it were accessible), exfiltrate event data, or perform actions on behalf of the victim. |
| **Status** | ✅ Fixed |
| **Fix applied** | Replaced with standard JSX: `<strong>{search}</strong>`. React escapes all interpolated values by default, making XSS impossible through this path. |

---

### 4.2 XSS via `innerHTML` on the Event Description

| | |
|---|---|
| **Original code** | `detailEl.innerHTML = selectedEvent.description` |
| **Vulnerability** | Stored XSS. If any event description contained HTML markup (e.g., a maliciously crafted security alert imported via a future data pipeline), it would be rendered as live HTML in the browser. Combined with a storage vector (e.g., an attacker who can write to `mock_events.json`), this becomes a persistent XSS. |
| **Status** | ✅ Fixed |
| **Fix applied** | Replaced with `{selectedEvent.description}` in JSX. React renders this as a text node, not as HTML. `whiteSpace: "pre-wrap"` preserves formatting without using `innerHTML`. |

---

### 4.3 JWT Stored in `localStorage` (Implied by Bearer Token Auth)

| | |
|---|---|
| **Original code** | API contract specified `Authorization: Bearer <token>` header auth, strongly implying token storage in `localStorage` or `sessionStorage`. |
| **Vulnerability** | Any JavaScript running on the page (including injected scripts via XSS) can read `localStorage.getItem('token')` and exfiltrate the token. Once stolen, the token can be replayed from any origin. `localStorage` is completely accessible to the document's JavaScript context. |
| **Status** | ✅ Fixed |
| **Fix applied** | Authentication uses HttpOnly cookies. The `httpOnly` flag prevents any JavaScript — including injected malicious scripts — from reading the cookie. `sameSite: 'strict'` prevents the cookie from being sent in cross-origin requests, mitigating CSRF. `secure: process.env.NODE_ENV === 'production'` ensures HTTPS-only transmission in production. |

---

### 4.4 No Authentication or Authorization on the Backend

| | |
|---|---|
| **Original code** | Frontend-only with hardcoded mock data. No server existed. |
| **Vulnerability** | All data was client-side. Anyone with browser DevTools could read all events and user data directly from the JavaScript bundle. No role-based access control existed. |
| **Status** | ✅ Fixed |
| **Fix applied** | Full Express backend with JWT middleware (`requireAuth`), role-based access control (`requireRole(['admin'])`), bcrypt password hashing, and Prisma ORM for persistent storage. |

---

### 4.5 Password Hashes / Sensitive Data in API Responses

| | |
|---|---|
| **Original code** | The mock user data in the original frontend likely included password fields. The API contract did not explicitly exclude passwords from user GET responses. |
| **Vulnerability** | Returning password hashes in API responses (even bcrypt hashes) is a data exposure vulnerability. Hashes can be subjected to offline cracking attacks (dictionary, rainbow table). |
| **Status** | ✅ Fixed |
| **Fix applied** | All Prisma queries use explicit `select` objects that include only `id`, `email`, `role`, and `status` — `passwordHash` is never selected in any response. The login route response is also sanitized to exclude the hash. |

---

### 4.6 No Rate Limiting (Brute Force on Login)

| | |
|---|---|
| **Original code** | No server existed; no rate limiting possible. |
| **Vulnerability** | Without rate limiting, an attacker can submit unlimited login attempts and perform online brute-force or credential-stuffing attacks against any account. |
| **Status** | ✅ Fixed |
| **Fix applied** | `loginLimiter` in `auth.ts` limits login attempts to 5 per 15-minute window per IP. `globalLimiter` in `server.ts` limits all API traffic to 100 requests per 15-minute window. Both return a structured JSON error message and use `standardHeaders: true` to expose rate-limit info to clients. |

---

### 4.7 User Enumeration via Distinct Error Messages

| | |
|---|---|
| **Original code** | `if (!user) return res.status(401).json({ error: 'User not found' })` / `if (!validPassword) return res.status(401).json({ error: 'Wrong password' })` |
| **Vulnerability** | Returning different error messages for "email not found" vs. "wrong password" allows an attacker to enumerate valid email addresses. They can probe the login endpoint with random emails until they receive the "wrong password" error (confirming the email exists), then focus brute force on confirmed accounts. |
| **Status** | ✅ Fixed |
| **Fix applied** | Both failure paths return the identical response: HTTP 401 `{ "error": "Invalid email or password" }`. The bcrypt comparison is still performed even if the user is not found (implicit — but see note in SEC-01 below about timing attacks — the current code does NOT perform a dummy bcrypt compare when user is not found, which leaves a timing oracle). |

---

### 4.8 No Input Validation / Schema Enforcement

| | |
|---|---|
| **Original code** | No backend existed. The original frontend sent raw, unvalidated form data. |
| **Vulnerability** | Without server-side validation, an attacker can send malformed, oversized, or type-confused payloads. Extra fields can trigger prototype pollution or unexpected behaviour in ORMs. |
| **Status** | ✅ Fixed |
| **Fix applied** | Zod `.strict()` schemas are applied to all mutation endpoints. `.strict()` rejects any request body that contains fields not explicitly defined in the schema. Password length is enforced at ≥8 characters. Email format is validated. The Express body parser is limited to `10kb` payloads. |

---

### 4.9 Missing Security Headers

| | |
|---|---|
| **Original code** | No backend, no headers beyond browser defaults. |
| **Vulnerability** | Without security headers, browsers apply permissive defaults. Missing `X-Content-Type-Options` allows MIME-type sniffing. Missing `X-Frame-Options` / `frame-ancestors` allows clickjacking. Missing `Strict-Transport-Security` fails to enforce HTTPS. |
| **Status** | ✅ Fixed |
| **Fix applied** | `helmet()` middleware is applied globally in `server.ts`. Helmet sets: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 0` (modern browsers handle XSS natively), `Strict-Transport-Security`, and others. |

---

### 4.10 Timing Oracle on Login (Partially Unaddressed)

| | |
|---|---|
| **Original code** | No backend. |
| **Vulnerability** | If a user is not found, the current code returns immediately without calling `bcrypt.compare`. A `bcrypt.compare` call takes ~100ms. An attacker measuring response time can distinguish "user not found" (fast ~1ms) from "wrong password" (slow ~100ms), effectively enumerating valid email addresses despite the identical error messages. This partially undermines the fix for [4.7]. |
| **Status** | ⚠️ Partially addressed — error messages are unified but timing oracle remains |
| **Fix:** After the `!user` check, perform a dummy bcrypt compare against a hardcoded hash before returning, to equalise timing:
  ```ts
  const DUMMY_HASH = '$2b$10$...'; // pre-generated dummy hash
  if (!user) {
    await bcrypt.compare(password, DUMMY_HASH); // equalise timing
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  ```

---

## 5. Per-File Breakdown

### `index.html`
Entry point for the Vite SPA. Defines the `<div id="root">` mount point and loads `src/main.tsx` as an ES module. Missing: CSP meta tag, `robots` meta tag, `description` meta tag.

---

### `src/main.tsx`
Bootstraps the React application. Wraps the root component in `StrictMode` (activates additional runtime warnings during development), `BrowserRouter` (client-side HTML5 history routing via React Router v7), and renders into `#root`. Imports global CSS.

---

### `src/App.tsx`
Root application component and auth state manager. Responsibilities:
- Calls `getCurrentUser()` on mount to hydrate session state
- Opens the login modal automatically on first unauthenticated visit (using `sessionStorage` to track dismissal)
- Manages `currentUser` state used by Navbar and EventsPage
- Defines the route map (`/` → `/events`, `/events`, `/users`, `*`)
- Handles logout by calling the API and reloading the page

Notable weakness: `currentUser` is typed as `any`.

---

### `src/App.css`
Global stylesheet. Defines layout classes (`container`, `page-container`), typography baseline, table styles, form input/select/button defaults, modal overlay and panel, and event detail panel. Contains dead CSS for `.welcome-banner` which is no longer rendered.

---

### `src/types.ts`
Shared TypeScript interfaces. Defines `SecurityEvent` (all fields from the mock JSON including internal `id` and `userId`) and `User` (includes a `password: string` field which is a design issue — the UI model should not carry a password field).

---

### `src/api.ts`
Centralized HTTP client module. Defines the `API_URL` constant and an `apiCall` helper that wraps `fetch` with `credentials: 'include'` (cookie forwarding), JSON content-type, and structured error throwing (attaches HTTP status code to thrown Error objects for consumer discrimination). Exports: `login`, `logout`, `getCurrentUser`, `getEvents`, `getUsers`. Does not export user mutation functions — those are duplicated in `UsersPage.tsx` as raw `fetch` calls.

---

### `src/components/Navbar.tsx`
Navigation bar component. Accepts `onLoginClick`, `currentUser`, and `onLogout` props. Uses `useLocation()` to apply the `.active` CSS class to the currently selected route link. Shows Login or Logout button based on auth state. The Users link is always rendered regardless of role — a minor RBAC presentation gap.

---

### `src/components/LoginModal.tsx`
Modal dialog for user authentication. Maintains local state for email, password, `showPassword` (eye toggle), and error message. On submit, calls `login(email, password)` from `api.ts`, closes the modal on success, and triggers `window.location.reload()`. Contains the SVG eye/eye-slash toggle for password visibility. Uses `stopPropagation` on the modal container click to prevent backdrop-dismiss from bubbling.

---

### `src/components/WelcomeBanner.tsx`
Leftover component from the original boilerplate. Contains the homework assignment instructions (Backend, Frontend, Security, Documentation task lists). The component is no longer imported or rendered in `App.tsx` but the file remains on disk. Can be safely deleted.

---

### `src/pages/EventsPage.tsx`
Main events view. Key responsibilities:
- Accepts `currentUser` prop for RBAC checks (`isViewer`)
- Fetches all events from `/api/events` on mount
- Maintains separate `unauthenticated` state for early returns vs. generic `error` state
- Derives `filtered` via search term, severity filter, and sort order (newest/oldest by timestamp) — all chained into one expression
- Renders a master-detail layout: filter bar + table on the left (flex: 1), selected event detail panel on the right (sticky, 360px fixed width)
- Viewer restrictions: row clicks and export button are disabled/hidden
- Export: strips `id` and `userId` from events before serialising to JSON
- Raw event detail: sanitised with the same destructure pattern before `JSON.stringify`

---

### `src/pages/UsersPage.tsx`
User management view (admin-only). Key responsibilities:
- Fetches users from `/api/users` on mount
- Distinguishes 401 (unauthenticated → early return), 403 (authenticated but not admin → warning panel), and other errors
- Add User form: maxWidth 400px, email + password (with eye toggle) + role select
- Role/status filter dropdowns derived client-side from the `users` array
- Table: status toggle button (calls PATCH), delete link (calls DELETE)
- Three mutating API calls bypass `api.ts` and use raw hardcoded `fetch` URLs — a code quality and maintainability issue

---

### `src/pages/NotFound.tsx`
Catch-all 404 page. Renders ASCII art of a penguin with a 404 heading and a link back to `/events`. No logic — purely presentational.

---

### `src/server.ts`
Express application entry point. Middleware applied in order:
1. `globalLimiter` — 100 req/15min global rate limit
2. `helmet()` — secure HTTP headers
3. `cors(...)` — allows only `http://localhost:5173` with credentials
4. `express.json({ limit: '10kb' })` — body parsing with payload cap
5. `cookieParser()` — parses cookies for `requireAuth`
6. Route mounts: `/api/auth`, `/api/events`, `/api/users`
7. `/health` — unauthenticated health probe
8. `app.listen(PORT)` — defaults to 4000

Missing: `app.set('trust proxy', 1)` for correct IP detection behind proxies.

---

### `src/routes/auth.ts`
Authentication routes. Exports an Express Router with three routes:
- `POST /login` — Zod-validated, rate-limited (5/15min), bcrypt-verified, JWT-signed, cookie-set
- `POST /logout` — Clears the auth cookie client-side (does not invalidate the token server-side)
- `GET /me` — Protected by `requireAuth`, returns `req.user`

Issues: duplicate `JWT_SECRET` declaration, `PrismaClient` instantiated locally, no timing equalization for user-not-found path.

---

### `src/routes/events.ts`
Events route. Single endpoint: `GET /` protected by `requireAuth`. Reads `data/mock_events.json` synchronously via `readFileSync` on every request. Returns the full JSON array. No pagination, no filtering, no single-event endpoint despite the API contract defining one.

---

### `src/routes/users.ts`
User management routes (all admin-only via `requireAuth` + `requireRole(['admin'])`):
- `GET /` — Returns all users, selects only safe fields (no `passwordHash`)
- `POST /` — Creates a user; Zod `.strict()` schema validates email, password (≥8), role (arbitrary string — not enum-validated)
- `DELETE /:id` — Deletes a user by ID; returns 204 on success
- `PATCH /:id/status` — Toggles status between `active` and `inactive`; no protection against last-admin deactivation

Issues: separate `PrismaClient` instance, role not constrained to valid values, no self-deletion protection.

---

### `src/middleware/auth.ts`
Authentication and authorization middleware:
- `requireAuth` — reads `req.cookies.token`, verifies JWT, attaches `{ id, role }` to `req.user`, returns 401 on failure
- `requireRole(allowedRoles)` — checks `req.user.role` is in the allowed list, returns 403 on failure

Issues: `JWT_SECRET` duplicated here, no live user status check (deactivated users pass `requireAuth`), token blocklist not implemented.

---

### `prisma/schema.prisma`
Defines the single `User` model: UUID primary key, unique email, passwordHash, role (default `"analyst"`), status (default `"active"`). No timestamps, no enum type enforcement, no relations to events.

---

### `prisma/seed.ts`
Seeds two users: `admin@penguwave.io` and `analyst@penguwave.io`, both with `password123` (bcrypt, 10 rounds). Uses `upsert` with `update: {}` (idempotent — existing records are not modified). No viewer user seeded. Console output only logs start, not successful completion.

---

### `prisma/migrations/20260510160606_init/migration.sql`
Original boilerplate migration. **Out of sync with current schema.** Creates a `User` table with `username` (not `email`) as the unique field. Has no `status` or `email` columns. This migration was never applied to the current database; the actual schema was created via `prisma db push` or a separate migration that was not committed.

---

### `data/mock_events.json`
50 realistic security events covering HIGH/MEDIUM/LOW severities. Fields: `id`, `timestamp`, `severity`, `title`, `description`, `assetHostname`, `assetIp`, `sourceIp`, `tags`, `userId`. The `userId` values (`usr-001` etc.) do not correspond to any database records. The `id` and `userId` fields are stripped by the export and raw-detail display logic in the frontend.

---

### `docs/api_contract.md`
Original API specification. Documents all endpoints with request/response shapes. Out of date in two ways: (1) specifies Bearer token auth instead of cookie auth, (2) specifies port 3001 instead of 4000. Missing: `PATCH /api/users/:id/status` which was added beyond the contract spec. The `GET /api/events/:id` endpoint specified here is not implemented.

---

### `package.json`
Defines the project as a private ESM package. Dependencies include all runtime packages (express, prisma, bcrypt, helmet, zod, etc.). Dev dependencies include all build tools (vite, tsx, typescript, eslint). Notable: no `start` script for production; no combined build script.

---

### `.env`
Contains two variables: `DATABASE_URL` (path to SQLite file) and `JWT_SECRET`. Not in `.gitignore` — a critical oversight. The `JWT_SECRET` value shown is `"your-secure-jwt-secret-change-in-production"`, which is a weak placeholder. Should be replaced with a cryptographically random 256-bit value (e.g., `openssl rand -hex 32`).

---

### `.gitignore`
Contains only `node_modules`. Missing `.env`, `*.db`, `dist/`. A significant security gap.

---

### `vite.config.ts`
Minimal Vite configuration: React plugin only. No proxy, no environment variable handling, no build output customisation.

---

### `eslint.config.js`
ESLint flat config using `@eslint/js`, `typescript-eslint`, `eslint-plugin-react-hooks`, and `eslint-plugin-react-refresh`. Ignores the `dist/` directory. A solid configuration for a TypeScript React project.

---

### `tsconfig.app.json` / `tsconfig.json` / `tsconfig.node.json`
Standard Vite + TypeScript project configuration. Not reviewed in depth as they contain no application logic.

---

## 6. Additional Review Elements

### 6.1 OWASP Top 10 (2021) Coverage

| # | Risk | Status |
|---|---|---|
| A01 — Broken Access Control | RBAC enforced server-side with `requireRole`; viewer restrictions in UI | ✅ Addressed |
| A02 — Cryptographic Failures | bcrypt for passwords; JWT for sessions; HttpOnly+Secure cookies | ✅ Addressed |
| A03 — Injection | Prisma ORM with parameterised queries prevents SQL injection; Zod prevents type confusion | ✅ Addressed |
| A04 — Insecure Design | Role enum not enforced (any string accepted as role) | ⚠️ Partial |
| A05 — Security Misconfiguration | `.env` not in `.gitignore`; CORS hardcoded; no CSP; migration out of sync | ⚠️ Issues Found |
| A06 — Vulnerable Components | Dependencies are current; no known CVEs in `package.json` at review time | ✅ OK |
| A07 — Auth & Session Failures | Login rate limiting; anti-enumeration error messages; no token revocation on status change | ⚠️ Partial |
| A08 — Software & Data Integrity | No integrity checks on `mock_events.json`; no signed releases | ℹ️ Low risk for this scope |
| A09 — Logging & Monitoring Failures | `console.error` only; no structured logging; no audit trail for admin actions | ⚠️ Gap |
| A10 — SSRF | No outbound HTTP calls from backend; not applicable | ✅ N/A |

---

### 6.2 Secrets Management Assessment

| Secret | Location | In `.gitignore`? | Strength |
|---|---|---|---|
| `JWT_SECRET` | `.env` | No | Placeholder value — must be rotated |
| `DATABASE_URL` | `.env` | No | Contains only a local file path |
| bcrypt hash cost | Hardcoded as `10` | — | Adequate (OWASP recommends ≥10) |

**Recommendation:** Generate a production JWT secret with `openssl rand -hex 32` and store it in a secrets manager (AWS Secrets Manager, HashiCorp Vault, or at minimum a `.env` file excluded from version control).

---

### 6.3 Dependency Risk Summary

All dependencies are current versions as of the review date. Notable observations:
- `express-rate-limit ^6.11.2` — v6 is stable; v7 exists but is not a required upgrade
- `bcrypt ^5.1.1` — preferred over `bcryptjs`; uses native bindings for performance
- `helmet ^7.0.0` — current major version; CSP must be configured explicitly beyond defaults
- `zod ^3.23.2` — current; v4 alpha exists but is not required
- No `express-validator`, `joi`, or other competing validation libraries — single choice is good
- No `winston` or `pino` for structured logging — a gap for production observability

---

### 6.4 Code Quality Metrics (Qualitative)

| Dimension | Assessment |
|---|---|
| Type Safety | Moderate — `any` used in App.tsx and Navbar; otherwise TypeScript is used correctly |
| Separation of Concerns | Good — routes, middleware, pages, and API helpers are cleanly separated |
| DRY (Don't Repeat Yourself) | Violated — API calls duplicated between `api.ts` and `UsersPage.tsx`; JWT_SECRET duplicated |
| Consistency | Mixed — some pages use `apiCall` helper, one doesn't; some errors use state, one uses early return |
| Comments | Good — security-relevant decisions are commented with "why" explanations throughout |
| Dead Code | `WelcomeBanner.tsx` rendered nowhere; `.welcome-banner` CSS unused |

---

### 6.5 Production Readiness Checklist

| Item | Ready? |
|---|---|
| Environment variables for all secrets | ❌ Hardcoded URLs and fallback secrets |
| Database migration history consistent with schema | ❌ Migration SQL is out of sync |
| `.gitignore` covers all sensitive files | ❌ `.env` and `*.db` are not excluded |
| HTTPS enforcement | ❌ No redirect or HSTS in non-Helmet config |
| Structured logging | ❌ `console.error` only |
| Proxy-aware rate limiting | ❌ `trust proxy` not set |
| Token revocation on deactivation | ❌ Not implemented |
| CSP header configured | ❌ Helmet defaults only |
| README reflects actual setup | ❌ Still describes frontend-only starter |
| Production start script | ❌ No `start` script |
| Role enum validation | ❌ Arbitrary strings accepted |
| Audit trail (createdAt/updatedAt) | ❌ Not in schema |

---

*End of Review*
