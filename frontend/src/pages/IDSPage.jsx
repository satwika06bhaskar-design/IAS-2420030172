import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle,
  Trash2,
  Sliders,
  AlertTriangle,
  Info,
  Clock,
  Layers,
  X,
  ExternalLink,
  Flame,
  Check
} from "lucide-react";
import { api } from "../services/api";
import ConfirmationModal from "../components/ConfirmationModal";
import EmptyState from "../components/EmptyState";

export default function IDSPage() {
  const [alerts, setAlerts] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [loading, setLoading] = useState(true);

  // Filters & Search
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [methodFilter, setMethodFilter] = useState("");
  const [ackFilter, setAckFilter] = useState("");

  // Modals & Drawers
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [clearModalOpen, setClearModalOpen] = useState(false);

  // Config State
  const [config, setConfig] = useState({
    ssh_failed_threshold: 5,
    telnet_port: 23,
    port_scan_distinct_ports_threshold: 10,
    excessive_packet_threshold: 20,
    repeated_denials_threshold: 5,
    rolling_window_seconds: 60,
  });
  const [savingConfig, setSavingConfig] = useState(false);
  const [configSuccess, setConfigSuccess] = useState(false);

  const fetchAlerts = async () => {
    try {
      const res = await api.getIDSAlerts({
        severity: severityFilter,
        detection_method: methodFilter,
        is_acknowledged: ackFilter,
        search: search,
        limit: 100,
      });
      setAlerts(res.items || []);
      setTotalAlerts(res.total || 0);
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchConfig = async () => {
    try {
      const cfg = await api.getIDSThresholds();
      setConfig(cfg);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchAlerts();
    fetchConfig();
    const interval = setInterval(fetchAlerts, 4000);
    return () => clearInterval(interval);
  }, [severityFilter, methodFilter, ackFilter, search]);

  const handleAcknowledge = async (alertId) => {
    try {
      await api.acknowledgeSingleAlert(alertId);
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert({ ...selectedAlert, is_acknowledged: true });
      }
      fetchAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleAcknowledgeAll = async () => {
    const unacked = alerts.filter((a) => !a.is_acknowledged).map((a) => a.id);
    if (unacked.length === 0) return;
    try {
      await api.acknowledgeAlerts(unacked);
      fetchAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleClearAlerts = async () => {
    try {
      await api.clearAllAlerts();
      setClearModalOpen(false);
      setSelectedAlert(null);
      fetchAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveConfig = async (e) => {
    e.preventDefault();
    try {
      setSavingConfig(true);
      const updated = await api.updateIDSThresholds(config);
      setConfig(updated);
      setConfigSuccess(true);
      setTimeout(() => setConfigSuccess(false), 3000);
      setIsConfigOpen(false);
    } catch (err) {
      alert(`Failed to save config: ${err.message}`);
    } finally {
      setSavingConfig(false);
    }
  };

  return (
    <div>
      {/* Header and Controls */}
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
            Intrusion Detection System (IDS) Dashboard
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)" }}>
            Correlates real-time packet telemetry using Rule-Based Signature Inspection and Statistical Anomaly Thresholds.
          </p>
        </div>

        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button className="btn btn-secondary btn-sm" onClick={() => setIsConfigOpen(true)}>
            <Sliders size={14} />
            <span>Configure Thresholds</span>
          </button>

          <button className="btn btn-secondary btn-sm" onClick={handleAcknowledgeAll}>
            <CheckCircle size={14} />
            <span>Acknowledge All</span>
          </button>

          <button className="btn btn-danger btn-sm" onClick={() => setClearModalOpen(true)}>
            <Trash2 size={14} />
            <span>Clear Alerts</span>
          </button>
        </div>
      </div>

      {/* Search and Filters Bar */}
      <div
        className="sentinel-card"
        style={{
          marginBottom: "1.5rem",
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          flexWrap: "wrap",
        }}
      >
        <div style={{ position: "relative", flex: 1, minWidth: 220 }}>
          <Search size={16} style={{ position: "absolute", left: 10, top: 10, color: "var(--text-muted)" }} />
          <input
            type="text"
            className="form-input"
            style={{ paddingLeft: "2rem" }}
            placeholder="Search alerts by IP, type, or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <select
            className="form-select"
            style={{ width: "auto" }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            className="form-select"
            style={{ width: "auto" }}
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
          >
            <option value="">All Detection Methods</option>
            <option value="Rule-Based IDS">Rule-Based IDS</option>
            <option value="Statistical Anomaly Detection">Statistical Anomaly Detection</option>
          </select>

          <select
            className="form-select"
            style={{ width: "auto" }}
            value={ackFilter}
            onChange={(e) => setAckFilter(e.target.value)}
          >
            <option value="">All Statuses</option>
            <option value="false">Unacknowledged Only</option>
            <option value="true">Acknowledged</option>
          </select>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="sentinel-card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)" }}>
            Security Detections Log ({totalAlerts})
          </h3>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            Auto-refreshes every 4s
          </span>
        </div>

        {alerts.length > 0 ? (
          <div className="table-container">
            <table className="sentinel-table">
              <thead>
                <tr>
                  <th style={{ width: 80 }}>ID</th>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Alert Type</th>
                  <th>Severity</th>
                  <th>Detection Method</th>
                  <th>Description</th>
                  <th>Status</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    style={{
                      cursor: "pointer",
                      backgroundColor: alert.is_acknowledged ? "transparent" : "#fffbeb",
                    }}
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <td style={{ fontWeight: 700, color: "var(--text-muted)", fontSize: "0.8125rem" }}>
                      #{alert.id}
                    </td>
                    <td style={{ fontSize: "0.75rem", color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td style={{ fontFamily: "monospace", fontWeight: 600, fontSize: "0.8125rem" }}>
                      {alert.source_ip}
                    </td>
                    <td style={{ fontWeight: 600, fontSize: "0.8125rem", color: "var(--navy-dark)" }}>
                      {alert.alert_type}
                    </td>
                    <td>
                      <span className={`badge badge-${alert.severity.toLowerCase()}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                        {alert.detection_method}
                      </span>
                    </td>
                    <td
                      style={{
                        maxWidth: 320,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        fontSize: "0.8125rem",
                        color: "var(--text-secondary)",
                      }}
                      title={alert.description}
                    >
                      {alert.description}
                    </td>
                    <td>
                      {alert.is_acknowledged ? (
                        <span className="badge badge-allow">ACK</span>
                      ) : (
                        <span className="badge badge-warning">NEW</span>
                      )}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div style={{ display: "inline-flex", gap: "0.5rem" }} onClick={(e) => e.stopPropagation()}>
                        {!alert.is_acknowledged && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleAcknowledge(alert.id)}
                            title="Acknowledge alert"
                          >
                            <Check size={12} />
                            <span>Ack</span>
                          </button>
                        )}
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => setSelectedAlert(alert)}
                          title="View details"
                        >
                          Details
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No alerts recorded"
            description="The IDS has not detected any security anomalies or signature violations matching your criteria."
          />
        )}
      </div>

      {/* Alert Detail Modal / Drawer */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 620 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1rem" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem" }}>
                  <span className={`badge badge-${selectedAlert.severity.toLowerCase()}`}>
                    {selectedAlert.severity}
                  </span>
                  <span style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>
                    Alert #{selectedAlert.id}
                  </span>
                </div>
                <h3 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--navy-dark)" }}>
                  {selectedAlert.alert_type}
                </h3>
              </div>
              <button onClick={() => setSelectedAlert(null)} style={{ color: "var(--text-muted)" }}>
                <X size={18} />
              </button>
            </div>

            <div style={{ backgroundColor: "#f8fafc", padding: "1rem", borderRadius: "var(--radius-md)", marginBottom: "1.25rem", fontSize: "0.875rem", lineHeight: 1.5 }}>
              <strong>Description:</strong>
              <div style={{ color: "var(--text-secondary)", marginTop: "0.25rem" }}>
                {selectedAlert.description}
              </div>
            </div>

            {/* Telemetry Breakdown */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1.25rem", fontSize: "0.8125rem" }}>
              <div>
                <div style={{ color: "var(--text-muted)" }}>Source IP Address</div>
                <div style={{ fontWeight: 600, fontFamily: "monospace" }}>{selectedAlert.source_ip}</div>
              </div>
              <div>
                <div style={{ color: "var(--text-muted)" }}>Destination IP Address</div>
                <div style={{ fontWeight: 600, fontFamily: "monospace" }}>{selectedAlert.destination_ip || "Internal Gateway"}</div>
              </div>
              <div>
                <div style={{ color: "var(--text-muted)" }}>Detection Method</div>
                <div style={{ fontWeight: 600 }}>{selectedAlert.detection_method}</div>
              </div>
              <div>
                <div style={{ color: "var(--text-muted)" }}>Timestamp</div>
                <div style={{ fontWeight: 600 }}>{new Date(selectedAlert.timestamp).toLocaleString()}</div>
              </div>
            </div>

            {/* Related Event Packet Snapshot if present */}
            {selectedAlert.related_event && (
              <div style={{ border: "1px solid var(--border-color)", borderRadius: "var(--radius-md)", padding: "1rem", marginBottom: "1.25rem" }}>
                <h4 style={{ fontSize: "0.8125rem", fontWeight: 700, color: "var(--navy-dark)", textTransform: "uppercase", marginBottom: "0.5rem" }}>
                  Triggering Packet Snapshot
                </h4>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "0.75rem", fontSize: "0.775rem" }}>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Protocol: </span>
                    <strong>{selectedAlert.related_event.protocol}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Port: </span>
                    <strong>{selectedAlert.related_event.destination_port}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Decision: </span>
                    <strong style={{ color: selectedAlert.related_event.firewall_decision === "ALLOW" ? "var(--success-green)" : "var(--danger-red)" }}>
                      {selectedAlert.related_event.firewall_decision}
                    </strong>
                  </div>
                </div>
              </div>
            )}

            {/* Extra Metadata / Statistical Context */}
            {selectedAlert.extra_data && (
              <div style={{ backgroundColor: "#f1f5f9", padding: "0.75rem", borderRadius: "var(--radius-sm)", fontSize: "0.75rem", fontFamily: "monospace", overflowX: "auto", marginBottom: "1.25rem" }}>
                {selectedAlert.extra_data}
              </div>
            )}

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem" }}>
              <button className="btn btn-secondary" onClick={() => setSelectedAlert(null)}>
                Close
              </button>
              {!selectedAlert.is_acknowledged && (
                <button className="btn btn-primary" onClick={() => handleAcknowledge(selectedAlert.id)}>
                  <Check size={14} />
                  <span>Acknowledge Alert</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Threshold Configuration Modal */}
      {isConfigOpen && (
        <div className="modal-overlay" onClick={() => setIsConfigOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 540 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
              <h3 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--navy-dark)" }}>
                Rule-Based IDS Thresholds Configuration
              </h3>
              <button onClick={() => setIsConfigOpen(false)} style={{ color: "var(--text-muted)" }}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSaveConfig}>
              <div className="form-group">
                <label className="form-label">Rule 1: Failed SSH Logins Threshold (count in window)</label>
                <input
                  type="number"
                  min="1"
                  max="50"
                  className="form-input"
                  value={config.ssh_failed_threshold}
                  onChange={(e) => setConfig({ ...config, ssh_failed_threshold: parseInt(e.target.value) || 5 })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Rule 2: Suspicious Telnet Port</label>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  className="form-input"
                  value={config.telnet_port}
                  onChange={(e) => setConfig({ ...config, telnet_port: parseInt(e.target.value) || 23 })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Rule 3: Port Scan Distinct Ports Threshold</label>
                <input
                  type="number"
                  min="2"
                  max="50"
                  className="form-input"
                  value={config.port_scan_distinct_ports_threshold}
                  onChange={(e) => setConfig({ ...config, port_scan_distinct_ports_threshold: parseInt(e.target.value) || 10 })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Rule 4: Excessive Packet Volume Threshold</label>
                <input
                  type="number"
                  min="5"
                  max="500"
                  className="form-input"
                  value={config.excessive_packet_threshold}
                  onChange={(e) => setConfig({ ...config, excessive_packet_threshold: parseInt(e.target.value) || 20 })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Rule 5: Repeated Firewall Denials Threshold</label>
                <input
                  type="number"
                  min="2"
                  max="50"
                  className="form-input"
                  value={config.repeated_denials_threshold}
                  onChange={(e) => setConfig({ ...config, repeated_denials_threshold: parseInt(e.target.value) || 5 })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Rolling Time Window (Seconds)</label>
                <input
                  type="number"
                  min="10"
                  max="300"
                  className="form-input"
                  value={config.rolling_window_seconds}
                  onChange={(e) => setConfig({ ...config, rolling_window_seconds: parseInt(e.target.value) || 60 })}
                  required
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "1.25rem" }}>
                <button type="button" className="btn btn-secondary" onClick={() => setIsConfigOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={savingConfig}>
                  {savingConfig ? "Saving..." : "Save Thresholds"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Clear Alerts Confirmation */}
      <ConfirmationModal
        isOpen={clearModalOpen}
        title="Clear All Security Alerts?"
        message="Are you sure you want to permanently clear all rule-based and anomaly alerts from the database? This action cannot be reversed."
        confirmText="Clear All Alerts"
        confirmVariant="danger"
        onConfirm={handleClearAlerts}
        onCancel={() => setClearModalOpen(false)}
      />
    </div>
  );
}
