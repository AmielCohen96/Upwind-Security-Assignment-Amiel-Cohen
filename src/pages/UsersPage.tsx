import { useState, useEffect } from "react";
import { getUsers, createUser, deleteUser, toggleUserStatus } from "../api";
import { User } from "../types";

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [accessDenied, setAccessDenied] = useState(false);
  const [unauthenticated, setUnauthenticated] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("analyst");
  const [showPassword, setShowPassword] = useState(false);

  // Filter state — "all" means no filter applied for that dimension.
  const [filterRole, setFilterRole] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");

  // Fetch users from the backend when the component mounts.
  // If the user is not an admin, the backend returns a 403 error.
  useEffect(() => {
    async function fetchUsers() {
      try {
        setLoading(true);
        setError(null);
        setAccessDenied(false);
        setUnauthenticated(false);
        const data = await getUsers();
        setUsers(data);
      } catch (err: any) {
        if (err.status === 401) {
          // Track unauthenticated separately so we can early-return and reveal
          // nothing about the application structure to unauthenticated visitors.
          setUnauthenticated(true);
        } else if (err.status === 403) {
          // User is authenticated but not an admin.
          setAccessDenied(true);
        } else {
          setError("Failed to load users. Please try again.");
        }
        console.error("Error fetching users:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchUsers();
  }, []);

  // Derived list: apply role and status filters client-side.
  const filteredUsers = users.filter((u) => {
    const matchesRole = filterRole === "all" || u.role === filterRole;
    const matchesStatus = filterStatus === "all" || u.status === filterStatus;
    return matchesRole && matchesStatus;
  });

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEmail || !newPassword) return;

    try {
      setError(null);
      const createdUser = await createUser(newEmail, newPassword, newRole);
      setUsers((prev) => [
        ...prev,
        {
          id: createdUser.id,
          email: createdUser.email || newEmail,
          role: createdUser.role || newRole,
          status: createdUser.status || "active",
          password: "***",
        },
      ]);
      setNewEmail("");
      setNewPassword("");
      setNewRole("analyst");
      setShowForm(false);
    } catch (err: any) {
      setError(err.message || "Failed to create user. Please try again.");
      console.error("Error creating user:", err);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      setError(null);
      await deleteUser(id);
      setUsers((prev) => prev.filter((u) => u.id !== id));
    } catch (err: any) {
      setError(err.message || "Failed to delete user. Please try again.");
      console.error("Error deleting user:", err);
    }
  };

  const handleToggleStatus = async (id: string) => {
    try {
      setError(null);
      const updated = await toggleUserStatus(id);
      setUsers((prev) =>
        prev.map((user) => (user.id === id ? { ...user, status: updated.status } : user))
      );
    } catch (err: any) {
      setError(err.message || "Failed to update status. Please try again.");
      console.error("Error toggling status:", err);
    }
  };

  // Do not render any app structure for unauthenticated visitors.
  if (!loading && unauthenticated) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: "60px 16px", textAlign: "center" }}>
        <p style={{ color: "#666", fontSize: 15 }}>Authentication required. Please log in.</p>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h1>User Management</h1>
        {!accessDenied && !loading && (
          <button className="btn-primary" onClick={() => setShowForm(!showForm)}>
            {showForm ? "Cancel" : "Add User"}
          </button>
        )}
      </div>

      {loading && <p style={{ color: "#666" }}>Loading users...</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}
      {accessDenied && (
        <div style={{ padding: 16, background: "#fff3cd", border: "1px solid #ffc107", borderRadius: 4 }}>
          <p style={{ margin: 0 }}>
            <strong>Access Denied:</strong> You do not have permission to view user management.
            User management is restricted to administrators only.
          </p>
        </div>
      )}

      {!loading && !error && !accessDenied && (
        <>
          {showForm && (
            <div style={{ border: "1px solid #ddd", padding: 16, marginBottom: 20, background: "#fafafa" }}>
              <h3 style={{ marginBottom: 12 }}>New User</h3>
              <form onSubmit={handleAddUser} style={{ maxWidth: 400 }}>
                <div style={{ marginBottom: 8 }}>
                  <label>Email</label>
                  <input
                    type="email"
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="user@penguwave.io"
                    required
                  />
                </div>
                <div style={{ marginBottom: 8 }}>
                  <label>Password</label>
                  {/* Relative wrapper positions the eye toggle inside the input's right edge. */}
                  <div style={{ position: "relative" }}>
                    <input
                      type={showPassword ? "text" : "password"}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="••••••••"
                      required
                      style={{ paddingRight: 38 }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((v) => !v)}
                      aria-label={showPassword ? "Hide password" : "Show password"}
                      style={{
                        position: "absolute",
                        right: 10,
                        top: "50%",
                        transform: "translateY(-50%)",
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        padding: 0,
                        color: "#888",
                        display: "flex",
                        alignItems: "center",
                      }}
                    >
                      {showPassword ? (
                        // Eye-slash: password is visible, click to hide
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                          <line x1="1" y1="1" x2="23" y2="23"/>
                        </svg>
                      ) : (
                        // Eye: password is hidden, click to reveal
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                          <circle cx="12" cy="12" r="3"/>
                        </svg>
                      )}
                    </button>
                  </div>
                </div>
                <div style={{ marginBottom: 12 }}>
                  <label>Role</label>
                  <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
                    <option value="admin">Admin</option>
                    <option value="analyst">Analyst</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </div>
                <button type="submit" className="btn-primary">
                  Create User
                </button>
              </form>
            </div>
          )}

          {/* Filter bar — applied client-side against the already-fetched user list. */}
          <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
            <select
              value={filterRole}
              onChange={(e) => setFilterRole(e.target.value)}
              style={{ width: 160 }}
            >
              <option value="all">All Roles</option>
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
              <option value="viewer">Viewer</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              style={{ width: 160 }}
            >
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>

          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Password</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => (
                <tr key={user.id}>
                  <td>{user.email}</td>
                  <td>{user.role}</td>
                  <td>
                    <button
                      type="button"
                      onClick={() => handleToggleStatus(user.id)}
                      style={{
                        border: "none",
                        background: "none",
                        padding: 0,
                        cursor: "pointer",
                        color: user.status === "active" ? "green" : "#d9534f",
                        fontWeight: 600,
                      }}
                    >
                      {user.status}
                    </button>
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: 13 }}>********</td>
                  <td>
                    <a
                      href="#"
                      onClick={(e) => {
                        e.preventDefault();
                        handleDelete(user.id);
                      }}
                      style={{ color: "red" }}
                    >
                      Delete
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredUsers.length === 0 && (
            <p style={{ color: "#999" }}>
              {users.length === 0 ? "No users." : "No users match the selected filters."}
            </p>
          )}
        </>
      )}
    </div>
  );
}
