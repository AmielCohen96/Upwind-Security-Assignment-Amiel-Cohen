import { useState, useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { getCurrentUser, logout } from "./api";
import { CurrentUser } from "./types";
import Navbar from "./components/Navbar";
import LoginModal from "./components/LoginModal";
import EventsPage from "./pages/EventsPage";
import UsersPage from "./pages/UsersPage";
import NotFound from "./pages/NotFound";

function App() {
  const [showLogin, setShowLogin] = useState(false);
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);

  // Check if user is already authenticated on mount.
  useEffect(() => {
    async function checkAuth() {
      const user = await getCurrentUser();
      setCurrentUser(user);
    }
    checkAuth();
  }, []);

  // Show login modal on first visit if not authenticated.
  useEffect(() => {
    if (!currentUser) {
      const dismissed = sessionStorage.getItem("login-dismissed");
      if (!dismissed) {
        setShowLogin(true);
      }
    }
  }, [currentUser]);

  const handleCloseLogin = () => {
    sessionStorage.setItem("login-dismissed", "true");
    setShowLogin(false);
  };

  // Called by LoginModal on successful login.
  // Fetches the current user from the server and updates state — no page reload required.
  const handleLoginSuccess = async () => {
    const user = await getCurrentUser();
    setCurrentUser(user);
    setShowLogin(false);
    sessionStorage.setItem("login-dismissed", "true");
  };

  // Handle logout: clear auth state and redirect to login.
  const handleLogout = async () => {
    try {
      await logout();
      setCurrentUser(null);
      sessionStorage.removeItem("login-dismissed");
      window.location.reload();
    } catch (err) {
      console.error("Logout failed:", err);
    }
  };

  return (
    <>
      <Navbar 
        onLoginClick={() => setShowLogin(true)} 
        currentUser={currentUser}
        onLogout={handleLogout}
      />
      <div className="container">
        <Routes>
          <Route path="/" element={<Navigate to="/events" replace />} />
          <Route path="/events" element={<EventsPage currentUser={currentUser} />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </div>
      {showLogin && <LoginModal onClose={handleCloseLogin} onLoginSuccess={handleLoginSuccess} />}
    </>
  );
}

export default App;
