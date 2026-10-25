import React from "react";
import {
  Shield,
  Layers,
  Cpu,
  Database,
  Terminal,
  Activity,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
} from "lucide-react";

export default function AboutPage() {
  return (
    <div style={{ maxWidth: 900 }}>
      {/* Intro Header */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.75rem" }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: "10px",
              backgroundColor: "var(--primary-blue)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#ffffff",
            }}
          >
            <Shield size={26} />
          </div>
          <div>
            <h2 style={{ fontSize: "1.375rem", fontWeight: 700, color: "var(--navy-dark)" }}>
              Sentinel — Intrusion Detection & Firewall Simulator
            </h2>
            <div style={{ fontSize: "0.875rem", color: "var(--text-muted)" }}>
              Educational Full-Stack Cybersecurity Web Application
            </div>
          </div>
        </div>

        <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
          Sentinel is designed for undergraduate and college computer science and cybersecurity students to bridge the gap between theoretical network security concepts and practical operational defenses. It pairs an authentic first-match packet evaluation engine with two distinct intrusion detection mechanisms: a deterministic rule-based signature engine and a NumPy statistical baseline anomaly model.
        </p>
      </div>

      {/* 9-Step Processing Pipeline Card */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <h3 style={{ fontSize: "1.0625rem", fontWeight: 700, color: "var(--navy-dark)", marginBottom: "0.75rem" }}>
          The Sentinel 9-Step Packet Processing Pipeline
        </h3>
        <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
          Every simulated packet injected into Sentinel rigorously traverses the following unified processing sequence:
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          {[
            { step: 1, title: "Simulated Event Generation", desc: "Construct packet with 5-tuple (Src IP, Dst IP, Proto, Src Port, Dst Port), payload size, and timestamp." },
            { step: 2, title: "Firewall Rule Priority Sorting", desc: "Query enabled firewall rules from SQLite and order them in ascending numerical priority." },
            { step: 3, title: "First-Match Rule Evaluation", desc: "Evaluate IP CIDR subnet boundaries, protocols, and port ranges. Apply first-match decision or fallback default." },
            { step: 4, title: "Database Event Ingestion", desc: "Persist the packet telemetry record and firewall outcome into SQLite with high-performance indexes." },
            { step: 5, title: "Rule-Based IDS Condition Tracking", desc: "Scan rolling 60s window for SSH brute force (>=5 fails), Telnet (port 23), Port scan (>=10 ports), Volume, Denials." },
            { step: 6, title: "Statistical Baseline Metric Aggregation", desc: "Extract time-series metrics into NumPy arrays (Packets/sec, SSH attempts/min, Bytes transferred)." },
            { step: 7, title: "NumPy Anomaly Detection", desc: "Compute rolling mean \u03bc and standard deviation \u03c3. Flag deviations exceeding threshold \u03bc + K\u00b7\u03c3." },
            { step: 8, title: "Alert Deduplication & Ingestion", desc: "Create IDSAlert records with severity, detection method, and triggering event links while preventing alert flooding." },
            { step: 9, title: "Real-Time UI State Return", desc: "Return structured JSON telemetry to Vite React frontend for instant chart rendering and audit log updates." },
          ].map((item) => (
            <div
              key={item.step}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "0.75rem",
                padding: "0.625rem 0.75rem",
                backgroundColor: "#f8fafc",
                borderRadius: "var(--radius-sm)",
                border: "1px solid var(--border-color)",
                fontSize: "0.8125rem",
              }}
            >
              <span
                style={{
                  width: 24,
                  height: 24,
                  borderRadius: "50%",
                  backgroundColor: "var(--primary-blue)",
                  color: "#ffffff",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontWeight: 700,
                  fontSize: "0.75rem",
                  flexShrink: 0,
                }}
              >
                {item.step}
              </span>
              <div>
                <strong style={{ color: "var(--navy-dark)" }}>{item.title}: </strong>
                <span style={{ color: "var(--text-secondary)" }}>{item.desc}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Tech Stack Breakdown */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <h3 style={{ fontSize: "1.0625rem", fontWeight: 700, color: "var(--navy-dark)", marginBottom: "0.75rem" }}>
          Full-Stack Technology Stack
        </h3>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "1rem" }}>
          <div style={{ backgroundColor: "#f8fafc", padding: "1rem", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
            <h4 style={{ fontSize: "0.875rem", fontWeight: 700, color: "var(--primary-blue)", marginBottom: "0.5rem" }}>
              Backend Architecture
            </h4>
            <ul style={{ paddingLeft: "1.25rem", fontSize: "0.8125rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
              <li><strong>Python 3.12 & FastAPI:</strong> High-performance async REST API</li>
              <li><strong>SQLAlchemy 2.0:</strong> Object-relational mapping and index management</li>
              <li><strong>SQLite:</strong> Persistent local database engine</li>
              <li><strong>NumPy:</strong> Vectorized statistical mean, variance, and z-score calculations</li>
              <li><strong>Pydantic v2:</strong> Strict IP CIDR and port schema validation</li>
              <li><strong>Pytest:</strong> Automated test coverage verifying all 12 criteria</li>
            </ul>
          </div>

          <div style={{ backgroundColor: "#f8fafc", padding: "1rem", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
            <h4 style={{ fontSize: "0.875rem", fontWeight: 700, color: "var(--primary-blue)", marginBottom: "0.5rem" }}>
              Frontend Architecture
            </h4>
            <ul style={{ paddingLeft: "1.25rem", fontSize: "0.8125rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
              <li><strong>React 19 & Vite:</strong> Ultra-fast modern component rendering</li>
              <li><strong>React Router v7:</strong> Seamless client-side page routing</li>
              <li><strong>Recharts:</strong> Interactive SVG Area, Donut, and Line charts with reference thresholds</li>
              <li><strong>Lucide React:</strong> Consistent cybersecurity iconography</li>
              <li><strong>Modern CSS Variables:</strong> Cohesive professional light theme</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Educational Scope and Simulator Limitations */}
      <div className="sentinel-card" style={{ backgroundColor: "#fffbeb", border: "1px solid #fde68a" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
          <AlertCircle size={20} color="var(--warning-amber)" />
          <h4 style={{ fontSize: "0.9375rem", fontWeight: 700, color: "#92400e" }}>
            Educational Simulator Scope & Limitations
          </h4>
        </div>
        <p style={{ fontSize: "0.8125rem", color: "#78350f", lineHeight: 1.5, marginBottom: "0.5rem" }}>
          Sentinel is strictly an educational cybersecurity simulation tool designed for coursework demonstrations, labs, and student learning.
        </p>
        <ul style={{ paddingLeft: "1.25rem", fontSize: "0.8125rem", color: "#78350f", lineHeight: 1.5 }}>
          <li>All network packets, host addresses, and attack events are simulated entirely in software.</li>
          <li>Sentinel does not capture real raw network packets from network interfaces or promiscuous sockets (e.g. no PCAP or WinPcap driver).</li>
          <li>Sentinel does not modify operating system iptables, Windows Filtering Platform (WFP), or commercial firewalls.</li>
          <li>Sentinel does not replace production enterprise firewalls (e.g. Palo Alto, Fortinet) or commercial SIEMs (e.g. Splunk, Elastic).</li>
        </ul>
      </div>
    </div>
  );
}
