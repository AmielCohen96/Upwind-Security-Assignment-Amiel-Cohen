import { useState } from "react";

export default function WelcomeBanner() {
  const [dismissed, setDismissed] = useState(() => {
    return sessionStorage.getItem("welcome-dismissed") === "true";
  });

  if (dismissed) return null;

  const handleDismiss = () => {
    sessionStorage.setItem("welcome-dismissed", "true");
    setDismissed(true);
  };

  return (
    <div className="welcome-banner">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h2 style={{ margin: "0 0 8px", fontSize: 16 }}>
            Welcome to PenguWave
          </h2>
          <p style={{ margin: "0 0 12px", color: "#555", fontSize: 13 }}>
            This is a frontend-only security operations portal. Your assignment is to turn it into a working full-stack application.
          </p>

          <h3 style={{ margin: "0 0 6px", fontSize: 14 }}>Backend</h3>
          <ul style={{ margin: "0 0 10px", paddingLeft: 20, fontSize: 13, lineHeight: 1.7, color: "#444" }}>
            <li>Build a backend service that serves the API defined in <code>docs/api_contract.md</code></li>
            <li>Implement authentication (login, logout, session management)</li>
            <li>Serve security events from the provided mock data or your own storage</li>
            <li>User management — CRUD with role-based access control</li>
            <li>Persistent storage — data must survive server restarts</li>
          </ul>

          <h3 style={{ margin: "0 0 6px", fontSize: 14 }}>Frontend</h3>
          <ul style={{ margin: "0 0 10px", paddingLeft: 20, fontSize: 13, lineHeight: 1.7, color: "#444" }}>
            <li>Connect the frontend to your backend (replace mock data with API calls)</li>
            <li>Review the existing code — fix any issues you find (bugs, security concerns, bad patterns)</li>
            <li>Improve the application — better UX, state management, and new functionality</li>
          </ul>

          <h3 style={{ margin: "0 0 6px", fontSize: 14 }}>Security</h3>
          <ul style={{ margin: "0 0 10px", paddingLeft: 20, fontSize: 13, lineHeight: 1.7, color: "#444" }}>
            <li>Write a Threat Thinking document — what could go wrong and what you'd protect against</li>
            <li>Review existing code for security concerns and fix what you find</li>
            <li>Make sure your backend follows security best practices</li>
          </ul>

          <h3 style={{ margin: "0 0 6px", fontSize: 14 }}>Documentation</h3>
          <ul style={{ margin: "0 0 10px", paddingLeft: 20, fontSize: 13, lineHeight: 1.7, color: "#444" }}>
            <li>Update the README — how to run the project, auth flow, authorization model, production deployment</li>
          </ul>

          <p style={{ margin: "0", color: "#888", fontSize: 12, fontStyle: "italic" }}>
            See <code>README.md</code> for full details and bonus tasks. Tip: Start by exploring the existing code before you build anything.
          </p>
        </div>
        <button
          onClick={handleDismiss}
          style={{
            background: "none",
            border: "none",
            fontSize: 18,
            cursor: "pointer",
            color: "#999",
            padding: "0 0 0 12px",
            lineHeight: 1,
          }}
        >
          ✕
        </button>
      </div>
    </div>
  );
}
