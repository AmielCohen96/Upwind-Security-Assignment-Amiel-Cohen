# PenguWave API Contract

Base URL: `http://localhost:4000`

These are the expected endpoints. Response shapes and status codes below are **suggestions** — feel free to deviate if you have a better approach. Document your decisions.

> **Authentication mechanism**: This implementation uses **`HttpOnly`, `SameSite=Strict` cookies** instead of `Authorization: Bearer` headers. The cookie is set automatically on login and cleared on logout. This prevents XSS-based token theft (JavaScript cannot read `HttpOnly` cookies) and CSRF is neutralised by `SameSite=Strict`. All authenticated requests must include `credentials: 'include'` in the fetch call so the browser sends the cookie.

---

## Authentication

### `POST /api/auth/login`

Authenticate a user and start a session.

- **Body:** `{ "email": "...", "password": "..." }`
- **Success (200):** Sets an `HttpOnly`, `SameSite=Strict` auth cookie and returns:
  ```json
  { "id": "...", "email": "...", "role": "..." }
  ```
  *(No token in the response body — the JWT lives only in the cookie.)*
- **Too many attempts (429):** Rate-limited to 5 attempts per IP per 15 minutes.
- **Invalid credentials (401):**
  ```json
  { "error": "Invalid email or password" }
  ```
  *(Same message whether the email is unknown or the password is wrong — prevents user enumeration.)*

### `POST /api/auth/logout`

End the current session.

- **Success (200):** `{ "message": "Logged out" }`

### `GET /api/auth/me`

Get the currently authenticated user's info.

- **Auth:** Cookie-based — the `HttpOnly` auth cookie is sent automatically by the browser (no `Authorization` header required).
- **Success (200):**
  ```json
  { "id": "...", "email": "...", "role": "...", "status": "..." }
  ```
- **Not authenticated (401):**
  ```json
  { "error": "Authentication required" }
  ```

---

## Events

All event endpoints require authentication.

### `GET /api/events`

Returns the list of security events.

- **Success (200):**
  ```json
  [
    {
      "id": "evt-001",
      "timestamp": "2025-02-18T14:32:01Z",
      "severity": "HIGH",
      "title": "...",
      "description": "...",
      "assetHostname": "...",
      "assetIp": "...",
      "sourceIp": "...",
      "tags": ["..."]
    }
  ]
  ```

> Pagination is not required, but consider it if you have time.

### `GET /api/events/:id`

> **Not implemented in this submission.** The assignment spec listed this as an optional endpoint. The frontend detail panel reads from the already-loaded event list in client state rather than making a separate API call per event, so the endpoint was not needed.

Returns a single event by ID.

- **Success (200):** Single event object (same shape as above)
- **Not found (404):** `{ "error": "Event not found" }`

---

## Users

User management endpoints require the **admin** role. Non-admin users should receive a `403 Forbidden` response.

### `GET /api/users`

Returns the list of users. Passwords must **never** be included in the response.

- **Success (200):**
  ```json
  [
    { "id": "...", "email": "...", "role": "admin", "status": "active" }
  ]
  ```

### `POST /api/users`

Create a new user.

- **Body:** `{ "email": "...", "password": "...", "role": "admin" | "analyst" | "viewer" }`
- **Success (201):** The created user (without password): `{ "id": "...", "email": "...", "role": "...", "status": "active" }`
- **Validation error (400):** `{ "error": "Invalid input" }` — if `role` is not one of the three allowed values, or email is malformed, or password is under 8 characters.
- **Duplicate email (400):** `{ "error": "A user with that email already exists" }`

### `PATCH /api/users/:id/status`

Toggle a user's active/inactive status.

- **Body:** none — the backend reads the current status from the database and toggles it.
- **Success (200):** `{ "id": "...", "status": "active" | "inactive" }`
- **Not found (404):** `{ "error": "User not found" }`
- **Self-disable (400):** `{ "error": "You cannot delete or disable your own account." }`

### `DELETE /api/users/:id`

Delete a user.

- **Success (204):** No response body.
- **Not found (404):** `{ "error": "User not found" }`
- **Self-deletion (400):** `{ "error": "You cannot delete or disable your own account." }`

---

## Error Responses

All error responses should follow a consistent format:

```json
{ "error": "Human-readable error message" }
```

Common status codes:
- `200` — Success
- `201` — Created
- `400` — Bad request / validation error
- `401` — Not authenticated
- `403` — Not authorized (wrong role)
- `404` — Resource not found
- `500` — Server error
