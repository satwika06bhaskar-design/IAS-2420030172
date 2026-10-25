import React, { useState, useEffect } from "react";
import {
  TrendingUp,
  Sliders,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Activity,
  Layers,
  Info,
  RefreshCw,
} from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
  Legend,
} from "recharts";
import { api } from "../services/api";

const METRIC_OPTIONS = [
  { value: "PACKETS_PER_SECOND", label: "Packets Per Second (pkts/sec)" },
  { value: "SSH_ATTEMPTS_PER_MIN", label: "SSH Attempts Per Min (attempts/min)" },
  { value: "BYTES_TRANSFERRED", label: "Bytes Transferred (bytes/sec)" },
];

export default function AnomalyPage() {
  const [selectedMetric, setSelectedMetric] = useState("PACKETS_PER_SECOND");
  const [stats, setStats] = useState(null);
  const [anomalyAlerts, setAnomalyAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  // Settings
  const [kFactor, setKFactor] = useState(3.0);
  const [twoSided, setTwoSided] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsSuccess, setSettingsSuccess] = useState(false);

  const fetchAnomalyData = async () => {
    try {
      const [statsData, alertsData, configData] = await Promise.all([
        api.getAnomalyStats(selectedMetric),
        api.getAnomalyAlerts(20),
        api.getAnomalyConfig(),
      ]);
      setStats(statsData);
      setAnomalyAlerts(alertsData || []);
      if (configData) {
        setKFactor(configData.k_factor || 3.0);
        setTwoSided(configData.two_sided || false);
      }
    } catch (err) {
      console.error("Failed to fetch anomaly data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnomalyData();
    const interval = setInterval(fetchAnomalyData, 4000);
    return () => clearInterval(interval);
  }, [selectedMetric]);

  const handleUpdateSettings = async (e) => {
    e.preventDefault();
    try {
      setSavingSettings(true);
      await api.updateAnomalyConfig({
        metric_name: selectedMetric,
        k_factor: parseFloat(kFactor) || 3.0,
        two_sided: twoSided,
        min_baseline_samples: 5,
      });
      setSettingsSuccess(true);
      setTimeout(() => setSettingsSuccess(false), 3000);
      fetchAnomalyData();
    } catch (err) {
      alert(`Error updating anomaly settings: ${err.message}`);
    } finally {
      setSavingSettings(false);
    }
  };

  const isAnomaly = stats?.is_anomaly;
  const hasData = stats?.has_sufficient_data;

  return (
    <div>
      {/* Intro Header Card */}
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
            Statistical Anomaly Detection Engine
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", maxWidth: 750 }}>
            Utilizes Python and NumPy to establish rolling statistical baselines (Mean &mu; and Standard Deviation &sigma;). Flags traffic rates exceeding \( \text{Threshold} = \mu + K \cdot \sigma \).
          </p>
        </div>

        {/* Metric Selector Dropdown */}
        <div>
          <label style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", display: "block", marginBottom: "0.25rem" }}>
            Active Monitored Metric
          </label>
          <select
            className="form-select"
            value={selectedMetric}
            onChange={(e) => setSelectedMetric(e.target.value)}
            style={{ fontWeight: 600, color: "var(--primary-blue)" }}
          >
            {METRIC_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* KPI Statistical Summary Cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        {/* Baseline Samples */}
        <div className="sentinel-card">
          <span style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", fontWeight: 600 }}>Baseline Samples</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--navy-dark)", marginTop: "0.25rem" }}>
            {stats?.baseline_samples || 0}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            {hasData ? "Reliable baseline" : "Need >= 5 samples"}
          </span>
        </div>

        {/* Baseline Mean */}
        <div className="sentinel-card">
          <span style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", fontWeight: 600 }}>Baseline Mean (&mu;)</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--primary-blue)", marginTop: "0.25rem" }}>
            {stats?.baseline_mean ?? 0}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{stats?.metric_unit}</span>
        </div>

        {/* Baseline Std Dev */}
        <div className="sentinel-card">
          <span style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", fontWeight: 600 }}>Std Deviation (&sigma;)</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--navy-dark)", marginTop: "0.25rem" }}>
            {stats?.baseline_std ?? 0}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>NumPy np.std(ddof=1)</span>
        </div>

        {/* Current Observed */}
        <div className="sentinel-card">
          <span style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", fontWeight: 600 }}>Current Value</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: isAnomaly ? "var(--danger-red)" : "var(--navy-dark)", marginTop: "0.25rem" }}>
            {stats?.current_value ?? 0}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Latest time window</span>
        </div>

        {/* Upper Threshold */}
        <div className="sentinel-card">
          <span style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", fontWeight: 600 }}>Upper Threshold</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--warning-amber)", marginTop: "0.25rem" }}>
            {stats?.upper_threshold ?? 0}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>&mu; + {stats?.k_factor}&sigma;</span>
        </div>

        {/* Anomaly Status Badge */}
        <div className="sentinel-card">
          <span style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", fontWeight: 600 }}>Anomaly Status</span>
          <div style={{ marginTop: "0.5rem" }}>
            {isAnomaly ? (
              <span className="badge badge-critical" style={{ fontSize: "0.875rem", padding: "0.35rem 0.65rem" }}>
                ANOMALY DETECTED
              </span>
            ) : hasData ? (
              <span className="badge badge-allow" style={{ fontSize: "0.875rem", padding: "0.35rem 0.65rem" }}>
                NORMAL TRAFFIC
              </span>
            ) : (
              <span className="badge badge-warning" style={{ fontSize: "0.875rem", padding: "0.35rem 0.65rem" }}>
                LEARNING BASELINE
              </span>
            )}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.35rem" }}>
            Z-Score: {stats?.z_score ?? 0}
          </div>
        </div>
      </div>

      {/* Main Chart Card with Recharts */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <div>
            <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)" }}>
              {stats?.metric_display_name || "Traffic Rate"} Time-Series & Statistical Thresholds
            </h3>
            <p style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>
              {stats?.status_text}
            </p>
          </div>
        </div>

        <div style={{ width: "100%", height: 320 }}>
          {stats?.time_series && stats.time_series.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={stats.time_series} margin={{ top: 20, right: 30, left: 10, bottom: 10 }}>
                <XAxis dataKey="timestamp" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#ffffff",
                    border: "1px solid #e2e8f0",
                    borderRadius: "6px",
                    fontSize: "0.8125rem",
                  }}
                />
                <Legend verticalAlign="top" height={36} />

                {/* Threshold Reference Lines */}
                {stats.upper_threshold > 0 && (
                  <ReferenceLine
                    y={stats.upper_threshold}
                    label={{ value: `Upper Threshold (${stats.upper_threshold})`, fill: "#dc2626", fontSize: 11 }}
                    stroke="#dc2626"
                    strokeDasharray="4 4"
                  />
                )}
                {stats.baseline_mean > 0 && (
                  <ReferenceLine
                    y={stats.baseline_mean}
                    label={{ value: `Mean \u03bc (${stats.baseline_mean})`, fill: "#2563eb", fontSize: 11 }}
                    stroke="#2563eb"
                    strokeDasharray="3 3"
                  />
                )}
                {stats.two_sided && stats.lower_threshold !== null && (
                  <ReferenceLine
                    y={stats.lower_threshold}
                    label={{ value: `Lower Threshold (${stats.lower_threshold})`, fill: "#d97706", fontSize: 11 }}
                    stroke="#d97706"
                    strokeDasharray="4 4"
                  />
                )}

                <Line
                  type="monotone"
                  dataKey="observed_value"
                  name={stats.metric_display_name}
                  stroke="#0f172a"
                  strokeWidth={2}
                  dot={{ r: 4, fill: "#2563eb" }}
                  activeDot={{ r: 7 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", fontSize: "0.875rem" }}>
              No traffic data collected. Generate packets in the Traffic Simulator to establish the statistical baseline.
            </div>
          )}
        </div>
      </div>

      {/* Threshold Configuration & Educational Note Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: "1.5rem",
          marginBottom: "1.5rem",
        }}
      >
        {/* Settings Form */}
        <div className="sentinel-card">
          <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.75rem" }}>
            Anomaly Sensitivity Tuning
          </h3>

          <form onSubmit={handleUpdateSettings}>
            <div className="form-group">
              <label className="form-label">
                Standard Deviation Multiplier (K Factor): <strong>{kFactor}</strong>
              </label>
              <input
                type="range"
                min="1.0"
                max="5.0"
                step="0.1"
                value={kFactor}
                onChange={(e) => setKFactor(e.target.value)}
                style={{ width: "100%" }}
              />
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Standard K=3.0 covers 99.7% of normal distributions (three-sigma rule). Smaller K increases sensitivity.
              </span>
            </div>

            <div className="form-group">
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <input
                  type="checkbox"
                  id="two_sided_check"
                  checked={twoSided}
                  onChange={(e) => setTwoSided(e.target.checked)}
                  style={{ width: 16, height: 16 }}
                />
                <label htmlFor="two_sided_check" style={{ fontSize: "0.875rem", fontWeight: 600, cursor: "pointer" }}>
                  Enable Two-Sided Anomaly Detection
                </label>
              </div>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
                Flags both abnormally high spikes and unusually low drops (e.g. heartbeat loss or sudden outage).
              </span>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", gap: "0.75rem", marginTop: "1rem" }}>
              {settingsSuccess && (
                <span style={{ fontSize: "0.8125rem", color: "var(--success-green)", fontWeight: 600 }}>
                  Settings Saved!
                </span>
              )}
              <button type="submit" className="btn btn-primary btn-sm" disabled={savingSettings}>
                {savingSettings ? "Updating..." : "Update Threshold"}
              </button>
            </div>
          </form>
        </div>

        {/* Educational Concept Callout */}
        <div className="sentinel-card" style={{ backgroundColor: "#f8fafc", border: "1px solid var(--border-color)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <Info size={18} color="var(--primary-blue)" />
            <h4 style={{ fontSize: "0.9375rem", fontWeight: 600, color: "var(--navy-dark)" }}>
              Statistical Anomaly vs. Confirmed Attack
            </h4>
          </div>
          <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: "0.75rem" }}>
            <strong>Important Concept:</strong> A statistical anomaly signifies that the observed rate deviates significantly from historical behavior, but is <em>not necessarily</em> malicious. For instance, a marketing campaign launch or scheduled batch backup can cause an anomaly without being an attack.
          </p>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", borderTop: "1px solid var(--border-color)", paddingTop: "0.5rem" }}>
            Sentinel demonstrates how security analysts must correlate statistical anomalies with rule-based packet inspections to minimize False Positives.
          </div>
        </div>
      </div>

      {/* Historical Anomaly Alerts Table */}
      <div className="sentinel-card">
        <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.75rem" }}>
          Statistical Anomaly Alert History
        </h3>

        {anomalyAlerts.length > 0 ? (
          <div className="table-container">
            <table className="sentinel-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Severity</th>
                  <th>Detection Reason</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {anomalyAlerts.map((a) => (
                  <tr key={a.id}>
                    <td style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </td>
                    <td style={{ fontFamily: "monospace", fontWeight: 600 }}>{a.source_ip}</td>
                    <td>
                      <span className="badge badge-high">{a.severity}</span>
                    </td>
                    <td style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>{a.description}</td>
                    <td>
                      {a.is_acknowledged ? (
                        <span className="badge badge-allow">Acknowledged</span>
                      ) : (
                        <span className="badge badge-warning">Active</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.875rem" }}>
            No statistical anomalies detected yet. Run the "High-Volume Packet Burst" scenario in the Traffic Simulator to trigger an anomaly.
          </div>
        )}
      </div>
    </div>
  );
}
