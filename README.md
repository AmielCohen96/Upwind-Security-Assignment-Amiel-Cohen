# 🐧 PenguWave: Security Operations Portal

A full-stack, production-oriented Security Operations Portal for monitoring and triaging security events across your infrastructure. Built with React, TypeScript, Express, Prisma, and SQLite — with a security-first architecture covering authentication hardening, role-based access control, and a clear path to production deployment.

---

## 📋 Table of Contents

1. [How to Run the Project](#-how-to-run-the-project)
2. [How Authentication Works](#-how-authentication-works)
3. [How Authorization is Enforced (RBAC)](#-how-authorization-is-enforced-rbac)
4. [Secure Production Deployment Strategy](#-secure-production-deployment-strategy)
5. [Future Enhancements (Product & UX)](#-future-enhancements-product--ux)

---

## 🚀 How to Run the Project

### Prerequisites

- **Node.js** v18 or higher
- **npm** v9 or higher

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Variables

Create a `.env` file in the project root. The database is intentionally excluded from version control (see `.gitignore`) to prevent accidental credential or data exposure.

```env
DATABASE_URL="file:./dev.db"
JWT_SECRET="replace-with-a-long-random-secret"
```

> **Security note:** `JWT_SECRET` should be a cryptographically random string of at least 32 characters. In production, this value must never live in a `.env` file — see the [deployment section](#-secure-production-deployment-strategy) for the recommended approach.

### 3. Initialize the Database & Seed Test Data

Push the Prisma schema to create the local SQLite database:

```bash
npx prisma db push
```

Seed the database with the three test accounts:

```bash
npm run db:seed
```

### 4. Start the Application

The following command starts both the Express API server (port **4000**) and the Vite dev server (port **5173**) concurrently:

```bash
npm run dev:all
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### 🔑 Seeded Test Accounts

All accounts share the same password for reviewer convenience.

| Email | Password | Role | Access Level |
|---|---|---|---|
| `admin@penguwave.io` | `password123` | `admin` | Full access — event visibility, user management, JSON export |
| `analyst@penguwave.io` | `password123` | `analyst` | Standard access — event visibility, JSON export |
| `viewer@penguwave.io` | `password123` | `viewer` | Read-only — event visibility only (no export) |

---

## 🔐 How Authentication Works

Authentication is implemented with a defense-in-depth approach. Each layer addresses a specific threat vector.

### Password Storage

User passwords are hashed with **`bcrypt`** (cost factor 10) before being written to the database. Plaintext passwords are never stored or logged. Even if the database is fully compromised, recovering the original passwords requires significant computational effort.

### Token Issuance — HttpOnly Cookies (not localStorage)

After a successful login, the server issues a **JWT** stored in an **`HttpOnly`, `SameSite=Strict` cookie** rather than returning it in the response body for the client to store in `localStorage`.

This is a deliberate security decision:

| Storage | XSS readable? | CSRF risk |
|---|---|---|
| `localStorage` | **Yes** — any injected script can exfiltrate the token | No |
| `HttpOnly` cookie | **No** — the browser never exposes it to JavaScript | Mitigated by `SameSite=Strict` |

`SameSite=Strict` ensures the cookie is never sent on cross-origin requests, eliminating the primary CSRF attack surface without requiring a separate CSRF token.

### Anti-Enumeration

Both an unknown email address and a correct email with a wrong password return the same **generic `401 Unauthorized`** response with no distinguishing message. This prevents an attacker from using the login endpoint to enumerate valid accounts.

### Brute-Force Protection

The `/api/auth/login` endpoint is protected by **`express-rate-limit`**: a maximum of **5 login attempts per IP within a 15-minute window** triggers a `429 Too Many Requests` response. This makes online password-guessing attacks impractical.

### Disabled Account Blocking

Disabled user accounts are rejected at the authentication layer before a JWT is ever issued. If an admin disables an account, the affected user cannot obtain a new token — but any JWT they already hold remains valid until its natural 24-hour expiry. *(Note: Immediate revocation of active tokens upon deactivation is addressed in the Production Deployment Strategy via a Redis blocklist.)*

---

## 🛡️ How Authorization is Enforced (RBAC)

Authorization is enforced at two independent layers. The backend is the source of truth; the frontend provides UX clarity.

### Backend — Middleware & Schema Validation (Source of Truth)

**`requireRole` middleware** sits in front of every protected route and validates the role claim inside the JWT against the required role for that endpoint. A `viewer` hitting an admin-only endpoint receives `403 Forbidden` regardless of what the frontend renders.

```
GET    /api/users              →  requireRole('admin')
DELETE /api/users/:id          →  requireRole('admin')
PATCH  /api/users/:id/status   →  requireRole('admin')
```

**Zod `.strict()` schema validation** is applied to all request bodies. `.strict()` causes Zod to reject any fields that are not explicitly declared in the schema — preventing Parameter Pollution and Mass Assignment attacks where an attacker attempts to overwrite privileged fields (e.g., `role`, `id`) by including them in the request payload.

**Self-Lockout Protection** prevents an admin from accidentally (or maliciously) deleting or disabling their own account. The backend compares the target user's ID against the authenticated requester's ID and returns `400 Bad Request` if they match. This ensures at least one admin always remains operational.

### Frontend — Feature Toggling & Data Sanitization (UX Layer)

**Feature toggling** conditionally renders UI elements based on the authenticated user's role, retrieved from the decoded JWT:

- The **"Users"** navigation link is hidden from `analyst` and `viewer` roles.
- The **"Export"** button on the events table is hidden from `viewer` roles.

These are UX improvements only — the backend enforces the same rules independently.

**Data Sanitization** strips internal identifiers (`userId`, `id`) from raw JSON displays and JSON exports before they reach the user. Exposing internal database IDs in the UI is an Information Disclosure risk: even read-only IDs can be used by an attacker for IDOR reconnaissance (enumerating resource IDs to map the database structure). Sanitization removes this recon surface without affecting functionality.

---

## ☁️ Secure Production Deployment Strategy

The following describes how this application would be hardened and deployed in a real production environment. No deployment is included in this submission, but every decision below maps to a concrete security control.

### TLS Termination via Reverse Proxy

All traffic must be served over HTTPS. A reverse proxy — **Nginx** or an **AWS Application Load Balancer (ALB)** — handles TLS termination in front of the Node.js process. The Node process itself listens on plain HTTP internally, never exposed directly to the internet.

Express must be configured to trust the proxy's forwarded headers so that `express-rate-limit` sees the real client IP rather than the proxy's IP (which would make rate limiting ineffective):

```ts
app.set('trust proxy', 1);
```

### Database — Managed, Encrypted-at-Rest PostgreSQL

SQLite is appropriate for local development but unsuitable for production. The migration path is:

1. Update `DATABASE_URL` to point to a **PostgreSQL** instance (e.g., **AWS RDS** with encryption at rest enabled and automated backups).
2. Run `npx prisma migrate deploy` to apply the existing schema to the new database.
3. No application code changes are required — Prisma abstracts the underlying engine.

RDS provides encryption at rest (AES-256), automated point-in-time recovery, and VPC network isolation, none of which are available with a local SQLite file.

### Secret Management — Vault or AWS Secrets Manager

`.env` files must not be used in production. Secrets (`JWT_SECRET`, `DATABASE_URL`, third-party API keys) should be injected at runtime from a dedicated secret manager:

- **HashiCorp Vault** for on-premises or multi-cloud environments.
- **AWS Secrets Manager** for AWS-native deployments.

Secrets are fetched by the application at startup via the provider's SDK, never written to disk, and rotated on a schedule without a code deploy.

### Centralized Audit Logging

Every privileged action (login, logout, role change, user creation/deletion, event status update) should emit a structured audit log entry including: `timestamp`, `actor_id`, `actor_role`, `action`, `target_resource`, `source_ip`, and `outcome`.

Logs are shipped to a centralized SIEM — **Splunk** or **Datadog** — giving the SOC team a tamper-resistant record of all administrative activity, enabling threat detection, compliance reporting, and forensic investigation.

### Token Revocation — Redis-Backed Blocklist

JWTs are stateless by design: once issued, they remain valid until expiry even if the user logs out or is deactivated. To close this gap, a **Redis-backed token blocklist** is introduced:

- On logout or account deactivation, the token's `jti` (JWT ID) is written to Redis with a TTL matching the token's remaining lifetime.
- Every authenticated request checks Redis for the `jti` before proceeding.
- This provides **immediate revocation** without abandoning the performance benefits of stateless JWT validation for non-revoked tokens.

---

## 🔭 Future Enhancements (Product & UX)

The current implementation fulfills the core security requirements of the assignment. In a real-world SOC portal, the following product capabilities would be prioritized as the next iteration:

### Interactive Dashboards

Static event tables do not scale for analysts triaging hundreds of alerts per hour. A dedicated analytics view would surface:

- **Timeline series** — event volume over time, enabling rapid identification of attack spikes or campaign windows.
- **Top Attacked Assets** — a ranked breakdown of the most frequently targeted hosts or services, helping analysts prioritize remediation.
- **Severity Distribution** — a visual split of `critical / high / medium / low` events so triage effort can be allocated proportionally.

These dashboards would be read-only for `viewer` and `analyst` roles, with drill-down filtering available to `admin` and `analyst` only — keeping the RBAC model consistent across the application.

### Incident Lifecycle Management

The current event model supports a binary status (`open` / `closed`). A production SOC workflow requires a richer resolution lifecycle:

| Status | Meaning |
|---|---|
| `Open` | Newly ingested, unreviewed |
| `In Progress` | Assigned to an analyst, investigation underway |
| `Resolved` | Root cause identified, remediation confirmed |

This would be paired with **analyst assignment** — linking an event to a specific user account — enabling workload visibility for SOC leads and creating an auditable chain of custody from detection to resolution.
