# Full Project Knowledge Base

This document explains the PenguWave project in clear, beginner-friendly terms. It covers the architecture, each file's role, the data flow from login to event display, security measures, critical decisions, and why this project is professional grade.

---

## 1. The Big Picture

Imagine the system as a secure restaurant.

- **Frontend = Dining room and waiter**
  - The user sits at a table, sees the menu, enters their email and password, and clicks buttons.
  - The frontend is what the user sees and interacts with.
  - It sends the users requests to the backend and displays the results.

- **Backend = Kitchen**
  - The kitchen receives the users order, checks identity, and prepares the correct dish.
  - It verifies whether a user is allowed to access the requested data.
  - It also applies security checks and decides what information to send back.

- **Database = Pantry**
  - The pantry stores all the ingredients: user records, hashed passwords, and user roles.
  - The kitchen looks in the pantry to verify credentials and retrieve data.

Using this analogy:
- The user enters credentials and clicks login in the dining room.
- The waiter (frontend) sends that order to the kitchen (backend).
- The kitchen checks the pantry (database) and either approves or rejects the order.
- If approved, the kitchen sends the requested event data back to the dining room.

---

## 2. File-by-File Roles

### Backend files

#### `src/server.ts`
- Main backend startup file.
- Configures security middleware like Helmet, CORS, and rate limiting.
- Parses JSON requests and cookies.
- Mounts routes at `/api/auth`, `/api/events`, and `/api/users`.
- Starts the server on port `4000`.

#### `src/routes/auth.ts`
- Handles authentication routes.
- Validates login input using Zod.
- Verifies credentials by looking up the user in the database.
- Uses bcrypt to compare submitted passwords to stored hashed passwords.
- Sets an HttpOnly cookie containing a signed JWT upon successful login.
- Supports logout by clearing the cookie.
- Provides `/api/auth/me` for session validation.

#### `src/routes/events.ts`
- Handles requests to view events.
- Reads static event data from `data/mock_events.json`.
- Protects the route with `requireAuth` so only authenticated users can access it.
- Returns JSON data for the frontend to display.

#### `src/routes/users.ts`
- Handles user management requests.
- Protects `/api/users` with both authentication and admin-only role checks.
- Returns safe user data without password hashes.
- Currently supports listing users for administration.

#### `src/middleware/auth.ts`
- Defines authentication and authorization middleware.
- `requireAuth` checks for a valid JWT in an HttpOnly cookie.
- `requireRole` enforces role-based access control (RBAC).
- Helps ensure only the right users can access sensitive backend routes.

#### `prisma/schema.prisma`
- Defines the database schema for Prisma.
- The `User` model uses `email` as the unique identifier.
- Stores `passwordHash` and user `role`.
- The schema is the contract between the app and the database.

#### `prisma/seed.ts`
- Seeds the database with initial users.
- Creates `admin@penguwave.io` and `analyst@penguwave.io`.
- Hashes the passwords securely with bcrypt.
- Ensures the database has working users for login.

### Frontend files

#### `src/api.ts`
- Centralizes all frontend-backend communication.
- Sends requests to the backend at `http://localhost:4000`.
- Includes `credentials: 'include'` so cookies are sent with requests.
- Provides helpers:
  - `login(email, password)`
  - `logout()`
  - `getCurrentUser()`
  - `getEvents()`
  - `getUsers()`

#### `src/components/LoginModal.tsx`
- User login interface.
- Collects `Email` and `Password` input.
- Sends login requests to the backend.
- Keeps the UI labels and placeholders unchanged.

#### `src/pages/EventsPage.tsx`
- Displays the list of security events.
- Loads events from the backend after authentication.
- Supports search and severity filtering.
- Renders event details safely without using dangerous HTML rendering.

#### `src/pages/UsersPage.tsx`
- Displays user management UI.
- Fetches user list from the backend.
- Includes create and delete operations.
- Uses backend API calls for persistent changes.

#### `src/types.ts`
- Defines data structures used across the frontend.
- Includes `SecurityEvent` and `User` interfaces.
- Helps TypeScript understand the shape of data objects.

### Other files

#### `data/mock_events.json`
- Contains sample event data.
- Used by the backend to simulate a real event feed.

#### `INTEGRATION_AUDIT.md`
- Documents the exact changes made for backend/security integration.
- Confirms UI preservation and security rationale.

---

## 3. The Data Flow

### Step 1: User enters email and clicks login
- The user fills in the `Email` and `Password` fields in `src/components/LoginModal.tsx`.
- The form submits and triggers `handleSubmit()`.

### Step 2: Frontend sends login request
- `LoginModal.tsx` sends a `POST` request to `http://localhost:4000/api/auth/login`.
- The request body contains:
  - `email`
  - `password`

### Step 3: Backend receives and validates login
- `src/routes/auth.ts` receives the request.
- It validates the payload using `loginSchema` from Zod.
- It ensures the email is valid and the password is present.

### Step 4: Backend checks credentials
- The backend looks up the user in the database with Prisma:
  - `prisma.user.findUnique({ where: { email } })`
- If the user exists, bcrypt compares the provided password to the stored `passwordHash`.

### Step 5: Backend issues a cookie
- If authentication succeeds:
  - The backend signs a JWT with `user.id` and `user.role`.
  - It stores the JWT in an HttpOnly cookie named `token`.
  - The backend returns safe user data to the frontend.

### Step 6: Browser stores the cookie
- The browser automatically stores the HttpOnly session cookie.
- This cookie cannot be read by JavaScript.

### Step 7: Frontend requests events
- `src/pages/EventsPage.tsx` calls `getEvents()` from `src/api.ts`.
- `getEvents()` sends a `GET` request to `/api/events` with `credentials: 'include'`.
- The cookie is included automatically.

### Step 8: Backend authorizes the request
- `src/routes/events.ts` is protected by `requireAuth`.
- `requireAuth` verifies the JWT cookie.
- If valid, the backend returns the event list.

### Step 9: Frontend displays the events
- `EventsPage.tsx` receives event data.
- It stores events in state and renders them in a table.
- Event descriptions are shown as safe plain text.

---

## 4. Security Implementation: Defense in Depth

### Bcrypt
- **What it is:** A secure password hashing function.
- **Stops:** Plaintext password exposure and weak hash attacks.
- **Why:** We store only hashed passwords in the database. Even if the database leaks, raw passwords are not exposed.

### JWT
- **What it is:** A signed JSON token used to authenticate users.
- **Stops:** Session forgery and tampering.
- **Why:** The backend uses JWTs to prove the user is authenticated without storing session data on the server.

### HttpOnly Cookies
- **What it is:** Cookies inaccessible to browser JavaScript.
- **Stops:** XSS attacks from stealing auth tokens.
- **Why:** The JWT is stored in an HttpOnly cookie so scripts cannot read it.

### Zod
- **What it is:** Input validation library.
- **Stops:** malformed or malicious input before it reaches backend logic.
- **Why:** We validate login input in `auth.ts` to ensure only valid email/password requests are processed.

### RBAC (Role-Based Access Control)
- **What it is:** Authorization based on user role.
- **Stops:** unauthorized users accessing admin endpoints.
- **Why:** `src/middleware/auth.ts` enforces admin-only access to `/api/users`.

### CORS
- **What it is:** Browser policy allowing certain origins.
- **Stops:** unknown web pages from calling the backend.
- **Why:** `server.ts` restricts access to `http://localhost:5173` and allows cookies only from the approved frontend.

### Helmet
- **What it is:** Middleware that sets secure HTTP headers.
- **Stops:** many browser-based attacks like clickjacking and MIME sniffing.
- **Why:** It provides standard security headers automatically.

### Rate Limiter
- **What it is:** Limits request volume over time.
- **Stops:** brute-force attacks and API abuse.
- **Why:** `server.ts` limits requests to reduce abuse and protect login endpoints.

---

## 5. Critical Decisions

### Using SQLite and Prisma
- **SQLite:** Simple file-based database that is easy to manage for a small app.
- **Prisma:** Provides a typed schema and safer database queries.
- **Why:** This combination simplifies development while still being maintainable and secure.

### Using Cookies instead of LocalStorage
- **Cookies:** HttpOnly cookies are hidden from JavaScript.
- **LocalStorage:** can be read by any script running on the page.
- **Why:** Cookies are more secure for authentication tokens and reduce the risk of XSS token theft.

### Removing `innerHTML` and `dangerouslySetInnerHTML`
- **Danger:** These allow raw HTML to run inside the page.
- **Attack:** They can enable cross-site scripting (XSS).
- **Why:** We render event descriptions as plain text only, making the UI safer.

---

## 6. The Whys: Why This Project Is Professional Grade

This project is more than a simple student exercise because it uses real-world security and architecture practices:

- **Clear separation of frontend and backend**
- **Secure authentication with JWT and HttpOnly cookies**
- **Input validation and safe request handling**
- **Role-based access control for admin-only data**
- **Secure middleware for HTTP headers and rate limiting**
- **Typed database schema with Prisma**
- **Explicit UI preservation and safe rendering practices**
- **Backend and frontend integration that reflects production patterns**

These qualities make the app professional, maintainable, and safer than a typical beginner implementation.

---

## Additional Notes

- The backend uses `src/routes/events.ts` to serve event data from `data/mock_events.json`.
- The frontend uses `src/api.ts` with `credentials: 'include'` to make sure cookies are sent with each request.
- The login flow uses email-based authentication and does not change visible UI labels or layout.

If you want, I can also save this same content into the repository as `FULL_PROJECT_KNOWLEDGE_BASE.md` so it remains part of the project documentation.
