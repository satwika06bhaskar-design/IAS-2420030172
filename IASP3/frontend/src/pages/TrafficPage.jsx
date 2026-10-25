import React, { useState, useEffect, useRef } from "react";
import {
  Play,
  Square,
  Pause,
  RotateCcw,
  Trash2,
  Activity,
  Layers,
  ShieldAlert,
  Server,
  Zap,
  CheckCircle,
  XCircle,
  Sliders,
  Filter,
  RefreshCw,
} from "lucide-react";
import { api } from "../services/api";
import ConfirmationModal from "../components/ConfirmationModal";
import EmptyState from "../components/EmptyState";

const PREDEFINED_SCENARIOS = [
  {
    type: "NORMAL_HTTP",
    title: "1. Normal HTTP Web Traffic",
    desc: "Simulates legitimate client web browsing traffic targeting HTTP (80) and HTTPS (443). Usually permitted by firewall.",
    defaultCount: 8,
    badge: "Legitimate",
    badgeClass: "badge-allow",
  },
  {
    type: "FAILED_SSH",
    title: "2. Failed SSH Login Attempts",
    desc: "Simulates repeated SSH authentication failures from a single IP to trigger Rule 1 (SSH brute-force detection threshold >= 5).",
    defaultCount: 6,
    badge: "Threat",
    badgeClass: "badge-critical",
  },
  {
    type: "TELNET",
    title: "3. Suspicious Telnet Traffic",
    desc: "Simulates TCP connection probes targeting unencrypted Telnet port 23, triggering Rule 2 (Insecure protocol alert).",
    defaultCount: 3,
    badge: "Suspicious",
    badgeClass: "badge-high",
  },
  {
    type: "PORT_SCAN",
    title: "4. Port Scan Reconnaissance",
    desc: "Simulates sequential reconnaissance probes across 10+ distinct ports to trigger Rule 3 (Port scan alert threshold >= 10).",
    defaultCount: 12,
    badge: "Recon",
    badgeClass: "badge-high",
  },
  {
    type: "HIGH_VOLUME",
    title: "5. High-Volume Packet Burst",
    desc: "Generates an intense burst of simulated UDP packets (>20 pkts) triggering Rule 4 and statistical anomaly z-score spike.",
    defaultCount: 25,
    badge: "Anomaly",
    badgeClass: "badge-warning",
  },
  {
    type: "LARGE_TRANSFER",
    title: "6. Large Data Transfer",
    desc: "Simulates bulky data transfers (up to 64 KB per packet) testing bandwidth metrics in the statistical anomaly model.",
    defaultCount: 5,
    badge: "Bandwidth",
    badgeClass: "badge-info",
  },
];

export default function TrafficPage() {
  const [events, setEvents] = useState([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [loading, setLoading] = useState(false);
  const [runningScenario, setRunningScenario] = useState(null);

  // Continuous stream generator state
  const [isStreaming, setIsStreaming] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const streamTimerRef = useRef(null);

  // Filters
  const [decisionFilter, setDecisionFilter] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("");
  const [alertFilter, setAlertFilter] = useState("");

  // Confirmation Modals
  const [clearModalOpen, setClearModalOpen] = useState(false);
  const [resetModalOpen, setResetModalOpen] = useState(false);

  // Custom Traffic Form State
  const [customForm, setCustomForm] = useState({
    source_ip: "192.168.1.50",
    destination_ip: "10.0.0.10",
    protocol: "TCP",
    destination_port: 80,
    source_port: 49152,
    event_count: 5,
    packet_size: 64,
    event_type: "CUSTOM_PROBE",
    ssh_auth_success: null,
    event_generation_rate: 5,
  });
  const [customSubmitting, setCustomSubmitting] = useState(false);

  const fetchEvents = async () => {
    try {
      const res = await api.getTrafficEvents({
        limit: 50,
        decision: decisionFilter,
        protocol: protocolFilter,
        has_alert: alertFilter ? alertFilter === "true" : undefined,
      });
      setEvents(res.items || []);
      setTotalEvents(res.total || 0);
    } catch (err) {
      console.error("Failed to fetch events:", err);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 3000);
    return () => clearInterval(interval);
  }, [decisionFilter, protocolFilter, alertFilter]);

  // Continuous background streamer
  useEffect(() => {
    if (isStreaming && !isPaused) {
      streamTimerRef.current = setInterval(async () => {
        try {
          const types = ["NORMAL_HTTP", "FAILED_SSH", "TELNET", "NORMAL_HTTP", "LARGE_TRANSFER"];
          const randomType = types[Math.floor(Math.random() * types.length)];
          await api.triggerScenario(randomType, 1);
          fetchEvents();
        } catch (e) {
          console.error("Streamer error:", e);
        }
      }, 1500);
    } else {
      if (streamTimerRef.current) clearInterval(streamTimerRef.current);
    }
    return () => {
      if (streamTimerRef.current) clearInterval(streamTimerRef.current);
    };
  }, [isStreaming, isPaused]);

  const handleRunScenario = async (type, count) => {
    try {
      setRunningScenario(type);
      await api.triggerScenario(type, count);
      await fetchEvents();
    } catch (err) {
      alert(`Error running scenario: ${err.message}`);
    } finally {
      setRunningScenario(null);
    }
  };

  const handleCustomSubmit = async (e) => {
    e.preventDefault();
    try {
      setCustomSubmitting(true);
      await api.triggerCustomTraffic(customForm);
      await fetchEvents();
    } catch (err) {
      alert(`Failed to generate custom traffic: ${err.message}`);
    } finally {
      setCustomSubmitting(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      await api.clearTrafficHistory();
      setClearModalOpen(false);
      fetchEvents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleResetSimulation = async () => {
    try {
      await api.resetSimulation();
      setResetModalOpen(false);
      fetchEvents();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div>
      {/* Simulation Controls & Header */}
      <div
        className="sentinel-card"
        style={{
          marginBottom: "1.5rem",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "1rem",
        }}
      >
        <div>
          <h2 style={{ fontSize: "1.25rem", fontWeight: 700, color: "var(--navy-dark)", marginBottom: "0.25rem" }}>
            Network Traffic Simulator
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)" }}>
            Inject simulated network packets into the Sentinel inspection pipeline. Packets trigger firewall evaluations, IDS rule trackers, and anomaly models.
          </p>
        </div>

        {/* Live Stream Generator Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
          {!isStreaming ? (
            <button
              className="btn btn-primary btn-sm"
              onClick={() => {
                setIsStreaming(true);
                setIsPaused(false);
              }}
            >
              <Play size={14} />
              <span>Start Continuous Traffic</span>
            </button>
          ) : (
            <>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setIsPaused(!isPaused)}
              >
                {isPaused ? <Play size={14} /> : <Pause size={14} />}
                <span>{isPaused ? "Resume" : "Pause"}</span>
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => {
                  setIsStreaming(false);
                  setIsPaused(false);
                }}
              >
                <Square size={14} />
                <span>Stop Stream</span>
              </button>
            </>
          )}

          <button className="btn btn-secondary btn-sm" onClick={() => setClearModalOpen(true)}>
            <Trash2 size={14} />
            <span>Clear Events</span>
          </button>

          <button className="btn btn-secondary btn-sm" onClick={() => setResetModalOpen(true)}>
            <RotateCcw size={14} />
            <span>Reset All</span>
          </button>
        </div>
      </div>

      {/* Predefined Scenarios Grid */}
      <div style={{ marginBottom: "1.5rem" }}>
        <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.75rem" }}>
          Predefined Attack & Traffic Scenarios
        </h3>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
            gap: "1rem",
          }}
        >
          {PREDEFINED_SCENARIOS.map((sc) => (
            <div key={sc.type} className="sentinel-card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                  <h4 style={{ fontSize: "0.9375rem", fontWeight: 600, color: "var(--navy-dark)" }}>
                    {sc.title}
                  </h4>
                  <span className={`badge ${sc.badgeClass}`}>{sc.badge}</span>
                </div>
                <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginBottom: "1rem", lineHeight: 1.45 }}>
                  {sc.desc}
                </p>
              </div>

              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", paddingTop: "0.75rem", borderTop: "1px solid var(--border-color)" }}>
                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                  Generates {sc.defaultCount} packets
                </span>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => handleRunScenario(sc.type, sc.defaultCount)}
                  disabled={runningScenario === sc.type}
                >
                  <Play size={13} />
                  <span>{runningScenario === sc.type ? "Simulating..." : "Start"}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Custom Traffic Generator Form Card */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <div style={{ marginBottom: "1rem" }}>
          <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)" }}>
            7. Custom Traffic Injector
          </h3>
          <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>
            Construct custom packet sequences with specific source IPs, ports, authentication outcomes, and injection frequencies.
          </p>
        </div>

        <form onSubmit={handleCustomSubmit}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: "1rem",
              marginBottom: "1rem",
            }}
          >
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Source IP</label>
              <input
                type="text"
                className="form-input"
                value={customForm.source_ip}
                onChange={(e) => setCustomForm({ ...customForm, source_ip: e.target.value })}
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Destination IP</label>
              <input
                type="text"
                className="form-input"
                value={customForm.destination_ip}
                onChange={(e) => setCustomForm({ ...customForm, destination_ip: e.target.value })}
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Protocol</label>
              <select
                className="form-select"
                value={customForm.protocol}
                onChange={(e) => setCustomForm({ ...customForm, protocol: e.target.value })}
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Destination Port</label>
              <input
                type="number"
                min="1"
                max="65535"
                className="form-input"
                value={customForm.destination_port}
                onChange={(e) => setCustomForm({ ...customForm, destination_port: parseInt(e.target.value) || 80 })}
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Number of Packets</label>
              <input
                type="number"
                min="1"
                max="100"
                className="form-input"
                value={customForm.event_count}
                onChange={(e) => setCustomForm({ ...customForm, event_count: parseInt(e.target.value) || 1 })}
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Packet Size (Bytes)</label>
              <input
                type="number"
                min="20"
                max="65535"
                className="form-input"
                value={customForm.packet_size}
                onChange={(e) => setCustomForm({ ...customForm, packet_size: parseInt(e.target.value) || 64 })}
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">SSH Auth Outcome</label>
              <select
                className="form-select"
                value={customForm.ssh_auth_success === null ? "" : String(customForm.ssh_auth_success)}
                onChange={(e) => {
                  const v = e.target.value;
                  setCustomForm({
                    ...customForm,
                    ssh_auth_success: v === "" ? null : v === "true",
                  });
                }}
              >
                <option value="">N/A (Non-SSH traffic)</option>
                <option value="true">Successful Authentication</option>
                <option value="false">Failed Authentication (Invalid Password)</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Rate (Packets / Sec)</label>
              <input
                type="number"
                min="1"
                max="50"
                className="form-input"
                value={customForm.event_generation_rate}
                onChange={(e) => setCustomForm({ ...customForm, event_generation_rate: parseInt(e.target.value) || 5 })}
              />
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button type="submit" className="btn btn-primary" disabled={customSubmitting}>
              <Zap size={16} />
              <span>{customSubmitting ? "Transmitting..." : "Generate Custom Packets"}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Real-Time Simulated Event Stream Table */}
      <div className="sentinel-card">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "1rem",
            marginBottom: "1rem",
          }}
        >
          <div>
            <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)" }}>
              Simulated Event Stream Log ({totalEvents} total)
            </h3>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Showing latest 50 processed packets with firewall decisions and IDS findings
            </p>
          </div>

          {/* Table Filters */}
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <select
              className="form-select"
              style={{ width: "auto", fontSize: "0.775rem" }}
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
            >
              <option value="">All Decisions</option>
              <option value="ALLOW">ALLOW only</option>
              <option value="BLOCK">BLOCK only</option>
            </select>

            <select
              className="form-select"
              style={{ width: "auto", fontSize: "0.775rem" }}
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
            >
              <option value="">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>

            <select
              className="form-select"
              style={{ width: "auto", fontSize: "0.775rem" }}
              value={alertFilter}
              onChange={(e) => setAlertFilter(e.target.value)}
            >
              <option value="">All Traffic</option>
              <option value="true">With IDS Alert</option>
              <option value="false">Clean Packets</option>
            </select>
          </div>
        </div>

        {events.length > 0 ? (
          <div className="table-container">
            <table className="sentinel-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Port</th>
                  <th>Size</th>
                  <th>Firewall Decision</th>
                  <th>Matched Rule</th>
                  <th>IDS Status</th>
                </tr>
              </thead>
              <tbody>
                {events.map((evt) => (
                  <tr key={evt.id}>
                    <td style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td style={{ fontFamily: "monospace", fontWeight: 600, fontSize: "0.8125rem" }}>
                      {evt.source_ip}
                    </td>
                    <td style={{ fontFamily: "monospace", fontSize: "0.8125rem" }}>
                      {evt.destination_ip}
                    </td>
                    <td>
                      <span className="badge badge-info">{evt.protocol}</span>
                    </td>
                    <td style={{ fontFamily: "monospace", fontSize: "0.8125rem" }}>
                      {evt.destination_port || "-"}
                    </td>
                    <td style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      {evt.packet_size} B
                    </td>
                    <td>
                      <span className={`badge ${evt.firewall_decision === "ALLOW" ? "badge-allow" : "badge-block"}`}>
                        {evt.firewall_decision}
                      </span>
                    </td>
                    <td style={{ fontSize: "0.75rem", color: "var(--text-secondary)", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={evt.firewall_reason}>
                      {evt.matched_rule_name ? `${evt.matched_rule_name} (#${evt.matched_rule_id})` : "Default Fallback"}
                    </td>
                    <td>
                      {evt.has_alert ? (
                        <span className="badge badge-critical">ALERT TRIGGERED</span>
                      ) : (
                        <span className="badge badge-allow">Normal</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No simulated events logged"
            description="Start a predefined scenario above or launch continuous traffic to view live packet processing."
          />
        )}
      </div>

      {/* Confirmation Modals */}
      <ConfirmationModal
        isOpen={clearModalOpen}
        title="Clear Traffic Event History?"
        message="This action will clear all stored simulated packet events from the database. IDS alerts and firewall rules will be retained."
        confirmText="Clear History"
        confirmVariant="danger"
        onConfirm={handleClearHistory}
        onCancel={() => setClearModalOpen(false)}
      />

      <ConfirmationModal
        isOpen={resetModalOpen}
        title="Reset Entire Simulation Data?"
        message="This will delete both simulated packets and all IDS alerts. The simulation metrics will return to zero."
        confirmText="Reset Simulation"
        confirmVariant="danger"
        onConfirm={handleResetSimulation}
        onCancel={() => setResetModalOpen(false)}
      />
    </div>
  );
}
