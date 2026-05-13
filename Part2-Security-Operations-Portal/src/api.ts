// Backend URL: The Express server runs on port 4000.
// This is separate from the frontend (port 5173) so CORS is needed.
const API_URL = import.meta.env.VITE_API_URL || "http://localhost:4000";

// Helper to make authenticated API calls with credentials.
// CRITICAL: credentials: 'include' tells the browser to send HttpOnly cookies
// with cross-origin requests. Without this, the auth cookie won't be sent,
// and the backend won't be able to authenticate the user.
async function apiCall(endpoint: string, options: RequestInit = {}) {
  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    credentials: 'include', // Include HttpOnly cookies in the request.
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  
  // If the response is not ok, throw an error with status code.
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    const errorObj = new Error(error.error || response.statusText) as any;
    errorObj.status = response.status;
    throw errorObj;
  }

  // 204 No Content (e.g. DELETE success) carries no body — skip JSON parsing.
  if (response.status === 204) return null;

  return response.json();
}

// Login: Sends email and password, receives user data and sets HttpOnly cookie.
// Note: The backend sets the auth cookie automatically, so the frontend doesn't
// need to manage tokens. This is more secure than localStorage.
export async function login(email: string, password: string) {
  return apiCall('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

// Logout: Clears the auth cookie on the server.
export async function logout() {
  return apiCall('/api/auth/logout', {
    method: 'POST',
  });
}

// Check current session: Returns the logged-in user if authenticated.
// This is called by the frontend to verify the user is still logged in.
export async function getCurrentUser() {
  try {
    return await apiCall('/api/auth/me');
  } catch (error: any) {
    if (error.status === 401) return null; // Not authenticated.
    throw error;
  }
}

// Fetch all security events.
// Protected with requireAuth: only authenticated users can view events.
export async function getEvents() {
  return apiCall('/api/events');
}

// Fetch all users.
// Protected with requireAuth + requireRole(['admin']): only admin users can view.
// If the user is not admin, the backend returns a 403 Forbidden response.
export async function getUsers() {
  return apiCall('/api/users');
}

// Create a new user (admin-only).
export async function createUser(email: string, password: string, role: string) {
  return apiCall('/api/users', {
    method: 'POST',
    body: JSON.stringify({ email, password, role }),
  });
}

// Delete a user by ID (admin-only). Returns null (204 No Content).
export async function deleteUser(id: string) {
  return apiCall(`/api/users/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

// Toggle a user's active/inactive status (admin-only).
export async function toggleUserStatus(id: string) {
  return apiCall(`/api/users/${encodeURIComponent(id)}/status`, { method: 'PATCH' });
}

