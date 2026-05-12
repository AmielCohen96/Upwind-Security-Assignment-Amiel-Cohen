# Integration Audit

This audit documents all changes made to the original assignment files during backend/security integration work. Each section includes the file name, exact modification summary, justification, UI preservation check, and code safety confirmation.

---

## `src/routes/auth.ts`

- Change Description:
  - Updated the login input schema from `username` to `email` using Zod.
  - Modified login handler to parse `email` and `password` from `req.body`.
  - Changed database lookup to `prisma.user.findUnique({ where: { email } })`.
  - Updated the returned sanitized user object to include `email` instead of `username`.

- Justification:
  - The authentication flow must align with the email-based login requirement for secure identity mapping.
  - Using validated email input reduces ambiguity and ensures backend login accepts the intended credential field.

- UI Preservation Check:
  - No labels, placeholders, CSS classes, or layout structure were changed in this file, since it is backend-only logic.

- Code Safety:
  - Kept Zod validation in place and strengthened it with `z.string().email(...)`.
  - No unsafe HTML or client-side behavior was introduced.

---

## `prisma/schema.prisma`

- Change Description:
  - Changed the `User` model unique identifier field from `username` to `email`.
  - Kept `passwordHash` and `role` unchanged.

- Justification:
  - The database schema must support email-based authentication and avoid storing credentials under the old `username` field.
  - This change is required for the backend to query users by email.

- UI Preservation Check:
  - This file is schema-only and does not affect UI labels, placeholders, or CSS.

- Code Safety:
  - Moving to an `email` unique field reinforces identity validation and avoids mapping user credentials to a loose username field.

---

## `prisma/seed.ts`

- Change Description:
  - Updated seed data to create `admin@penguwave.io` and `analyst@penguwave.io` users.
  - Kept both passwords as `password123` and hashed them with bcrypt.
  - Changed `upsert` lookups and create payloads to use the `email` field.

- Justification:
  - Seed data must match the new email-based login contract so the backend can authenticate seeded users correctly.

- UI Preservation Check:
  - This change is backend-only and does not alter UI text, layout, or styling.

- Code Safety:
  - Passwords are hashed with bcrypt before persistence.
  - No plaintext passwords are stored in the application code beyond seed input.

---

## `src/api.ts`

- Change Description:
  - Updated the `login` helper to accept `email` rather than `username`.
  - Changed the POST body to `JSON.stringify({ email, password })`.

- Justification:
  - The frontend API contract must match the backend login endpoint after the email-based login change.

- UI Preservation Check:
  - This file is API logic only; no UI labels, placeholders, or CSS were modified.

- Code Safety:
  - The helper still uses secure `credentials: 'include'` for auth cookie transport.
  - No unsafe operations were introduced.

---

## `src/components/LoginModal.tsx`

- Change Description:
  - Updated the login request endpoint to `http://localhost:4000/api/auth/login`.
  - Ensured the request body sends `{ email, password }`.
  - Preserved the visible input label `Email`, the placeholder `you@company.com`, and the button label exactly as originally provided.

- Justification:
  - The login modal needed to send the correct field name to the backend without changing the displayed form text.

- UI Preservation Check:
  - Confirmed no visible labels, placeholders, button text, or CSS styling were altered.
  - The structure and layout of the modal remain unchanged.

- Code Safety:
  - Login requests still use `Content-Type: application/json`.
  - No unsafe DOM manipulation or client-side HTML injection is present.

---

## `src/pages/EventsPage.tsx`

- Change Description:
  - Removed `dangerouslySetInnerHTML` for rendering the search query.
  - Replaced it with safe React text nodes: `Showing results for: <strong>{search}</strong>`.
  - Removed the `innerHTML` assignment used for event descriptions.
  - Rendered `selectedEvent.description` as plain text inside a `<p>` with `whiteSpace: 'pre-wrap'`.

- Justification:
  - This was necessary to eliminate XSS risk from event description rendering.
  - Plain-text rendering maintains data visibility while enforcing security best practices.

- UI Preservation Check:
  - No visible labels, text content, CSS, or layout structure were changed.
  - Only the internal rendering mechanism of description content was replaced.

- Code Safety:
  - Replaced unsafe HTML injection with safe React rendering.
  - Kept all event data displayed as untrusted content.

---

## `src/pages/UsersPage.tsx`

- Change Description:
  - Updated `handleAddUser` to call `POST http://localhost:4000/api/users` with `email`, `password`, and `role`.
  - Updated `handleDelete` to call `DELETE http://localhost:4000/api/users/:id` with `encodeURIComponent(id)`.
  - Preserved the existing table and form layout, labels, and button text.

- Justification:
  - Local-only state updates are insufficient for a real backend integration; API calls are required.
  - These changes were needed to align the UI with a persistent backend-managed user list.

- UI Preservation Check:
  - Confirmed the visible form labels, placeholders, button text, and page structure were left intact.
  - Only the internal submit/delete behavior was updated.

- Code Safety:
  - Backend requests use `credentials: 'include'` when required.
  - `encodeURIComponent` is used for path-safe user IDs.
  - User input is passed to the backend as JSON, treating it as untrusted data.

---

## `src/routes/users.ts`

- Change Description:
  - Updated the user list response to select `email` instead of `username` from the database.

- Justification:
  - The backend must expose the email field consistently after the schema migration.

- UI Preservation Check:
  - No UI-related changes were made in this server-side file.

- Code Safety:
  - Continued to exclude `passwordHash` from API responses.
  - Only safe, sanitized fields are returned.

---

## Summary

All changes were targeted to support email-based authentication and secure backend integration. No UI labels, placeholders, styling, or layout structures were changed in the visible frontend components. Security best practices were followed by removing unsafe HTML rendering, preserving API cookie handling, and keeping password hashing in the seed script.
