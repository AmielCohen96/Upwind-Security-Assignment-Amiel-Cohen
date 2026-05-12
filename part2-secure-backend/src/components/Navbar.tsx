import { Link, useLocation } from "react-router-dom";

interface NavbarProps {
  onLoginClick: () => void;
  currentUser: any;
  onLogout: () => void;
}

export default function Navbar({ onLoginClick, currentUser, onLogout }: NavbarProps) {
  const location = useLocation();

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <Link to="/events" style={{ textDecoration: "none", color: "inherit" }}>
          PenguWave 🐧
        </Link>
      </div>
      <div className="navbar-links">
        <Link
          to="/events"
          className={location.pathname.startsWith("/events") ? "active" : ""}
        >
          Events
        </Link>
        {currentUser?.role === "admin" && (
          <Link
            to="/users"
            className={location.pathname === "/users" ? "active" : ""}
          >
            Users
          </Link>
        )}
        {currentUser ? (
          <button onClick={onLogout} className="navbar-login-btn">
            Logout
          </button>
        ) : (
          <button onClick={onLoginClick} className="navbar-login-btn">
            Login
          </button>
        )}
      </div>
    </nav>
  );
}
