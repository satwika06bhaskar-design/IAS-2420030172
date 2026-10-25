import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  Flame,
  TrendingUp,
  ArrowRight,
  Play,
  PlusCircle,
  Eye,
  BookOpen,
  RefreshCw,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";
import { api } from "../services/api";

const PIE_COLORS = ["#16a34a", "#dc2626"];

export default function OverviewPage() {
  const [stats, setStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchDashboardData = async () => {
    try {
      setIsRefreshing(true);
      const [statsData, alertsData] = await Promise.all([
        api.getTrafficStats(),
        api.getIDSAlerts({ limit: 5 }),
      ]);
      setStats(statsData);
      setRecentAlerts(alertsData.items || []);
    } catch (err) {
      console.error("Failed to load dashboard data:", err);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    // Auto-poll every 5 seconds
    const interval = setInterval(fetchDashboardData, 5000);
    const handleRefresh = () => fetchDashboardData();
    window.addEventListener("sentinel-data-refresh", handleRefresh);
    return () => {
      clearInterval(interval);
      window.removeEventListener("sentinel-data-refresh", handleRefresh);
    };
  }, []);

  const total = stats?.total_packets || 0;
  const allowed = stats?.allowed_packets || 0;
  const blocked = stats?.blocked_packets || 0;
  const totalAlerts = stats?.total_alerts || 0;
  const highAlerts = stats?.high_severity_alerts || 0;
  const isAnomaly = stats?.anomaly_status === "ANOMALY_DETECTED";

  const pieData = [
    { name: "Allowed", value: allowed },
    { name: "Blocked", value: blocked },
  ];

  return (
    <div>
      {/* Intro Header */}
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
            Security Operations Overview
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", maxWidth: 700 }}>
            Sentinel demonstrates how rule-based packet filtering, rule-based signature IDS, and statistical anomaly detection collaborate to secure virtual network perimeters.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button className="btn btn-secondary btn-sm" onClick={fetchDashboardData} disabled={isRefreshing}>
            <RefreshCw size={14} className={isRefreshing ? "spin" : ""} />
            <span>Refresh Stats</span>
          </button>
        </div>
      </div>

      {/* 6 Key Stat KPI Cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        {/* Card 1: Total Packets */}
        <div className="sentinel-card">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--text-secondary)" }}>Total Packets</span>
            <Activity size={18} color="var(--primary-blue)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--navy-dark)" }}>{total}</div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>Simulated pipeline events</div>
        </div>

        {/* Card 2: Allowed Packets */}
        <div className="sentinel-card">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--text-secondary)" }}>Allowed</span>
            <ShieldCheck size={18} color="var(--success-green)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--success-green)" }}>{allowed}</div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
            {total > 0 ? `${Math.round((allowed / total) * 100)}% of total traffic` : "No traffic yet"}
          </div>
        </div>

        {/* Card 3: Blocked Packets */}
        <div className="sentinel-card">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--text-secondary)" }}>Blocked</span>
            <ShieldX size={18} color="var(--danger-red)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--danger-red)" }}>{blocked}</div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
            {total > 0 ? `${Math.round((blocked / total) * 100)}% filtered out` : "No drops yet"}
          </div>
        </div>

        {/* Card 4: Total IDS Alerts */}
        <div className="sentinel-card">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--text-secondary)" }}>Total IDS Alerts</span>
            <AlertTriangle size={18} color="var(--warning-amber)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--navy-dark)" }}>{totalAlerts}</div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>Rule & Anomaly triggered</div>
        </div>

        {/* Card 5: High Severity Alerts */}
        <div className="sentinel-card">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--text-secondary)" }}>High/Critical Alerts</span>
            <Flame size={18} color="var(--danger-red)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--danger-red)" }}>{highAlerts}</div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>Urgent threat indicators</div>
        </div>

        {/* Card 6: Anomaly Status */}
        <div className="sentinel-card">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--text-secondary)" }}>Anomaly Status</span>
            <TrendingUp size={18} color={isAnomaly ? "var(--danger-red)" : "var(--primary-blue)"} />
          </div>
          <div style={{ marginTop: "0.25rem" }}>
            {isAnomaly ? (
              <span className="badge badge-critical" style={{ fontSize: "0.875rem", padding: "0.3rem 0.6rem" }}>
                ANOMALY DETECTED
              </span>
            ) : (
              <span className="badge badge-allow" style={{ fontSize: "0.875rem", padding: "0.3rem 0.6rem" }}>
                BASELINE NORMAL
              </span>
            )}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.4rem" }}>
            NumPy statistical z-score
          </div>
        </div>
      </div>

      {/* Visual Charts Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
          gap: "1.5rem",
          marginBottom: "1.5rem",
        }}
      >
        {/* Activity Over Time Area Chart */}
        <div className="sentinel-card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)" }}>
              Simulated Traffic Over Time
            </h3>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Time Buckets</span>
          </div>

          <div style={{ width: "100%", height: 260 }}>
            {stats?.recent_activity_chart && stats.recent_activity_chart.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.recent_activity_chart} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#16a34a" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#16a34a" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#dc2626" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#dc2626" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#94a3b8" fontSize={11} />
                  <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#ffffff",
                      border: "1px solid #e2e8f0",
                      borderRadius: "6px",
                      fontSize: "0.75rem",
                    }}
                  />
                  <Area type="monotone" dataKey="allowed" name="Allowed" stroke="#16a34a" fillOpacity={1} fill="url(#colorAllowed)" />
                  <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#dc2626" fillOpacity={1} fill="url(#colorBlocked)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", fontSize: "0.875rem" }}>
                No traffic events generated yet. Click "Simulate Traffic" below.
              </div>
            )}
          </div>
        </div>

        {/* Firewall Decisions Ratio Donut Chart */}
        <div className="sentinel-card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)" }}>
              Firewall Decisions Breakdown
            </h3>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Allowed vs Blocked</span>
          </div>

          <div style={{ width: "100%", height: 260 }}>
            {total > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", fontSize: "0.875rem" }}>
                Generate packets to view firewall decision proportions.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Quick Action Navigation Buttons */}
      <div
        className="sentinel-card"
        style={{
          marginBottom: "1.5rem",
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "1rem",
        }}
      >
        <Link to="/traffic" className="btn btn-primary" style={{ padding: "0.75rem 1rem", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Play size={18} />
            <span>Simulate Traffic</span>
          </div>
          <ArrowRight size={16} />
        </Link>

        <Link to="/firewall" className="btn btn-secondary" style={{ padding: "0.75rem 1rem", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <PlusCircle size={18} color="var(--primary-blue)" />
            <span>Add Firewall Rule</span>
          </div>
          <ArrowRight size={16} />
        </Link>

        <Link to="/ids" className="btn btn-secondary" style={{ padding: "0.75rem 1rem", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Eye size={18} color="var(--warning-amber)" />
            <span>View IDS Alerts ({totalAlerts})</span>
          </div>
          <ArrowRight size={16} />
        </Link>

        <Link to="/threats" className="btn btn-secondary" style={{ padding: "0.75rem 1rem", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <BookOpen size={18} color="var(--info-cyan)" />
            <span>Explore Threats</span>
          </div>
          <ArrowRight size={16} />
        </Link>
      </div>

      {/* Recent IDS Alerts Table */}
      <div className="sentinel-card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <div>
            <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)" }}>
              Recent Security Alerts
            </h3>
            <p style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>
              Latest detections triggered by Rule-Based signatures and Statistical Anomaly metrics
            </p>
          </div>
          <Link to="/ids" style={{ fontSize: "0.8125rem", color: "var(--primary-blue)", fontWeight: 600 }}>
            View All Alerts &rarr;
          </Link>
        </div>

        {recentAlerts.length > 0 ? (
          <div className="table-container">
            <table className="sentinel-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Alert Type</th>
                  <th>Severity</th>
                  <th>Detection Method</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((alert) => (
                  <tr key={alert.id}>
                    <td style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td style={{ fontWeight: 600, fontFamily: "monospace" }}>{alert.source_ip}</td>
                    <td>{alert.alert_type}</td>
                    <td>
                      <span className={`badge badge-${alert.severity.toLowerCase()}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>
                        {alert.detection_method}
                      </span>
                    </td>
                    <td>
                      {alert.is_acknowledged ? (
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
            No security alerts have been generated yet. Trigger scenarios in the Traffic Simulator to view alerts.
          </div>
        )}
      </div>
    </div>
  );
}
