# Task 1: Threat Thinking

**Scope:** TLS is handled by infrastructure. The backend is the sole trusted authority.

**The Attacker's Perspective**
Attackers aim to steal sessions, escalate privileges, or dump sensitive data via:
1. **XSS & CSRF:** Injecting malicious scripts into event logs to steal session tokens, or forging unauthorized cross-site requests.
2. **API Abuse:** Bypassing the frontend UI to access other users' data (IDOR) or injecting unauthorized fields like `role: "admin"` into payloads (Mass Assignment).
3. **Data & Auth Attacks:** Exploiting SQL injection to dump the database, or brute-forcing the login endpoint to guess passwords and enumerate valid emails.

**The Defender's Perspective**
1. **Session Security:** JWTs are issued via HttpOnly cookies to render them completely invisible to XSS JavaScript, and marked SameSite=Strict to neutralize CSRF attacks.
2. **Strict Authorization:** UI hiding is purely cosmetic. A backend RBAC middleware strictly validates JWT roles on all sensitive routes. `Zod` validates all payloads to automatically drop unexpected fields, preventing Mass Assignment.
3. **Hardened Core:** Prisma ORM inherently prevents SQL injection. Passwords are cryptographically hashed using `bcrypt`. The login API is rate-limited and returns generic errors to thwart brute-force and enumeration attempts.