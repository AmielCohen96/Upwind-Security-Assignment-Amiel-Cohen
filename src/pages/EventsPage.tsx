import { useState, useEffect } from "react";
import { getEvents } from "../api";
import { SecurityEvent } from "../types";

interface Props {
  // Only the role field is needed for RBAC checks in this component.
  currentUser?: { role: string } | null;
}

export default function EventsPage({ currentUser }: Props) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  // "newest" = descending by timestamp (default); "oldest" = ascending.
  const [sortOrder, setSortOrder] = useState<"newest" | "oldest">("newest");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [unauthenticated, setUnauthenticated] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Viewers may read events but must not export data or drill into raw details.
  const isViewer = currentUser?.role === "viewer";

  useEffect(() => {
    async function fetchEvents() {
      try {
        setLoading(true);
        setError(null);
        const data = await getEvents();
        setEvents(data);
      } catch (err: any) {
        if (err.status === 401) {
          // Track unauthenticated separately so we can return early and reveal
          // nothing about the application structure to unauthenticated visitors.
          setUnauthenticated(true);
        } else {
          setError("Failed to load events. Please try again.");
        }
        console.error("Error fetching events:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchEvents();
  }, []);

  // --- Early returns: keep these before any derived state to avoid wasted work. ---

  if (loading) {
    return (
      <div className="page-container">
        <h1>Security Events</h1>
        <p style={{ color: "#666" }}>Loading events...</p>
      </div>
    );
  }

  // Do not render any app structure for unauthenticated visitors — even the page
  // skeleton leaks information about what features exist.
  if (unauthenticated) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: "60px 16px", textAlign: "center" }}>
        <p style={{ color: "#666", fontSize: 15 }}>Authentication required. Please log in.</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-container">
        <h1>Security Events</h1>
        <p style={{ color: "red" }}>{error}</p>
      </div>
    );
  }

  // -------------------------------------------------------------------------------

  const filtered = events
    .filter((e) => {
      const matchesSearch =
        e.title.toLowerCase().includes(search.toLowerCase()) ||
        e.description.toLowerCase().includes(search.toLowerCase()) ||
        e.assetHostname.toLowerCase().includes(search.toLowerCase());
      const matchesSeverity = severityFilter === "ALL" || e.severity === severityFilter;
      return matchesSearch && matchesSeverity;
    })
    // Sort after filtering so the dropdown always reflects what is on screen.
    .sort((a, b) => {
      const diff = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      return sortOrder === "newest" ? -diff : diff;
    });

  const severityColor = (s: string) => {
    if (s === "HIGH") return "red";
    if (s === "MEDIUM") return "orange";
    return "green";
  };

  return (
    <div className="page-container">
      <h1>Security Events</h1>

      {/* Filter bar */}
      <div style={{ display: "flex", gap: 16, alignItems: "center", marginBottom: 24, flexWrap: "wrap" }}>
        <input
          type="text"
          placeholder="Search events..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: "1 1 220px", minWidth: 160, maxWidth: 400 }}
        />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ width: 150 }}
        >
          <option value="ALL">All Severities</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select
          value={sortOrder}
          onChange={(e) => setSortOrder(e.target.value as "newest" | "oldest")}
          style={{ width: 220 }}
        >
          <option value="newest">Sort by Date: Newest to Oldest</option>
          <option value="oldest">Sort by Date: Oldest to Newest</option>
        </select>
      </div>

      {search && (
        <p>
          Showing results for: <strong>{search}</strong> ({filtered.length} events)
        </p>
      )}

      {/*
        Master-detail layout: table on the left, detail panel on the right.
        The detail panel only renders when an event is selected, so the table
        occupies full width otherwise. minWidth: 0 on the table column prevents
        table content from overflowing past the flex boundary.
      */}
      <div style={{ display: "flex", gap: 24, alignItems: "flex-start" }}>

        {/* Left column: table + export */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Asset</th>
                <th>Source IP</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((event) => (
                <tr
                  key={event.id}
                  // Viewers are not permitted to drill into raw event details.
                  onClick={isViewer ? undefined : () => setSelectedEvent(event)}
                  style={{ cursor: isViewer ? "default" : "pointer" }}
                >
                  <td style={{ color: severityColor(event.severity), fontWeight: 600 }}>
                    {event.severity}
                  </td>
                  <td>{event.title}</td>
                  <td style={{ fontFamily: "monospace", fontSize: 13 }}>
                    {event.assetHostname}
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: 13 }}>
                    {event.sourceIp}
                  </td>
                  <td style={{ fontSize: 13 }}>
                    {new Date(event.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filtered.length === 0 && <p style={{ color: "#999" }}>No events found.</p>}

          {/* Export is hidden for viewers — bulk data export exceeds read-only access. */}
          {!isViewer && (
            <div style={{ marginTop: 12 }}>
              <button
                onClick={() => {
                  // Strip internal DB fields before export — same rule as the raw detail view.
                  const exportData = filtered.map(({ id: _id, userId: _userId, ...rest }) => rest);
                  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = "penguwave_events_export.json";
                  a.click();
                  URL.revokeObjectURL(url);
                }}
                style={{ fontSize: 13 }}
              >
                Export Events (JSON)
              </button>
            </div>
          )}
        </div>

        {/* Right column: detail panel, sticky so it stays in view while scrolling the table. */}
        {selectedEvent && (
          <div
            className="event-detail"
            style={{
              width: 360,
              flexShrink: 0,
              position: "sticky",
              top: 16,
              maxHeight: "calc(100vh - 120px)",
              overflowY: "auto",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2>{selectedEvent.title}</h2>
              <button onClick={() => setSelectedEvent(null)} style={{ cursor: "pointer" }}>
                Close
              </button>
            </div>
            <p>
              <strong>Severity:</strong>{" "}
              <span style={{ color: severityColor(selectedEvent.severity) }}>
                {selectedEvent.severity}
              </span>
            </p>
            <p><strong>Description:</strong></p>
            <p style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {selectedEvent.description}
            </p>
            <p>
              <strong>Asset:</strong> {selectedEvent.assetHostname} ({selectedEvent.assetIp})
            </p>
            <p>
              <strong>Source IP:</strong> {selectedEvent.sourceIp}
            </p>
            <p>
              <strong>Tags:</strong> {selectedEvent.tags.join(", ")}
            </p>
            <p>
              <strong>Timestamp:</strong> {new Date(selectedEvent.timestamp).toLocaleString()}
            </p>
            <h3>Raw Event Data</h3>
            <pre>{(() => {
              // Strip internal DB fields before display — same rule as the export.
              const { id: _id, userId: _userId, ...sanitized } = selectedEvent;
              return JSON.stringify(sanitized, null, 2);
            })()}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
