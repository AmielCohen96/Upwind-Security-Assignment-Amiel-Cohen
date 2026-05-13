# Threat Model: Security Operations Portal

**Scope:** TLS/HTTPS is handled by infrastructure. The backend is the sole trusted authority.

### The Attacker's Perspective
Attackers aim to steal sessions, escalate privileges, or dump sensitive data via:
1. **XSS & CSRF** — injecting malicious scripts into event logs to steal session tokens, or forging unauthorized cross-site requests.
2. **API Abuse** — bypassing the frontend to access other users' data (IDOR), or injecting unauthorized fields like `role: "admin"` into request payloads (Mass Assignment).
3. **Data & Auth Attacks** — SQL injection to dump the database, brute-forcing the login endpoint, and enumerating valid accounts via differential error responses.

### The Defender's Perspective
1. **Session Security:** JWTs are issued into `HttpOnly`, `SameSite=Strict` cookies — invisible to JavaScript, eliminating both XSS-based token theft and CSRF in a single mechanism.
2. **Strict Authorisation:** UI hiding is cosmetic only. Backend `requireRole` middleware validates JWT role claims on every sensitive route. `Zod.strict()` schemas reject any undeclared field before the route handler runs, structurally preventing Mass Assignment.
3. **Hardened Core:** Prisma ORM uses parameterised queries — no raw SQL in the codebase. Passwords hashed with bcrypt (cost factor 10). Login is rate-limited; identical 401 errors for unknown email vs. wrong password, with a dummy `bcrypt.compare` call in the not-found branch to close a latency-based enumeration oracle.