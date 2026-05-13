// Represents the authenticated session user returned by GET /api/auth/me.
// Kept separate from User (the admin user-management model) because
// the session payload contains only what the JWT carries: id and role.
export interface CurrentUser {
  id: string;
  role: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  title: string;
  description: string;
  assetHostname: string;
  assetIp: string;
  sourceIp: string;
  tags: string[];
  userId: string;
}

export interface User {
  id: string;
  email: string;
  role: string;
  status: string;
  password: string;
}
