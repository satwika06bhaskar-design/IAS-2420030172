import React, { useState, useEffect } from "react";
import {
  HelpCircle,
  Shield,
  Layers,
  CheckCircle,
  XCircle,
  Info,
  ExternalLink,
  ChevronRight,
} from "lucide-react";
import { api } from "../services/api";

const COMPARISON_MATRIX = [
  {
    feature: "OSI Layer Operating Level",
    packet: "Layer 3 (Network) & Layer 4 (Transport)",
    stateful: "Layer 3, Layer 4 (Tracks Handshakes)",
    alg: "Layer 7 (Application Layer)",
    ngfw: "Layers 3 through 7 (Full Stack)",
  },
  {
    feature: "Connection State Awareness",
    packet: "No (Stateless - packet by packet)",
    stateful: "Yes (Maintains dynamic state table)",
    alg: "Yes (Full proxy connection termination)",
    ngfw: "Yes (Stateful + Deep Inspection)",
  },
  {
    feature: "Payload / Content Inspection",
    packet: "None (Headers only)",
    stateful: "None (Session state only)",
    alg: "High (Inspects HTTP/FTP commands)",
    ngfw: "Deep (DPI, TLS Decryption, Antivirus)",
  },
  {
    feature: "Throughput & Latency Performance",
    packet: "Highest throughput, near zero latency",
    stateful: "High throughput, minimal latency",
    alg: "Lower throughput, noticeable proxy latency",
    ngfw: "High (requires hardware ASIC acceleration)",
  },
  {
    feature: "Sentinel Simulator Status",
    packet: "Active Simulated Engine (First-Match Policy)",
    stateful: "Educational Reference Concept",
    alg: "Educational Reference Concept",
    ngfw: "Educational Reference Concept",
  },
];

export default function ConceptsPage() {
  const [concepts, setConcepts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadConcepts() {
      try {
        const data = await api.getFirewallConcepts();
        setConcepts(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    loadConcepts();
  }, []);

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
            Protocol & Firewall Architectural Concepts
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", maxWidth: 750 }}>
            In-depth academic comparison of the four historical and modern generations of firewall architectures.
          </p>
        </div>
      </div>

      {/* Simulator Scope Clarification Box */}
      <div
        className="sentinel-card"
        style={{
          backgroundColor: "#eff6ff",
          border: "1px solid #bfdbfe",
          marginBottom: "1.5rem",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.35rem" }}>
          <Info size={18} color="var(--primary-blue)" />
          <h4 style={{ fontSize: "0.9375rem", fontWeight: 700, color: "#1e40af" }}>
            Sentinel's Architectural Implementation Scope
          </h4>
        </div>
        <p style={{ fontSize: "0.8125rem", color: "#1e3a8a", lineHeight: 1.5 }}>
          Sentinel's implemented rule engine is an authentic educational simulation of <strong>Rule-Based Packet Filtering</strong>. It executes actual first-match rule searches, CIDR subnet matching, and port checks on simulated packets. To preserve strict educational integrity, Sentinel does not falsely claim to implement kernel-level stateful connection tracking or hardware-accelerated next-generation deep packet decryption.
        </p>
      </div>

      {/* Comparison Matrix Table */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.75rem" }}>
          Firewall Generation Comparison Matrix
        </h3>

        <div className="table-container">
          <table className="sentinel-table">
            <thead>
              <tr>
                <th style={{ width: "22%" }}>Architectural Dimension</th>
                <th style={{ width: "20%" }}>1. Packet-Filtering</th>
                <th style={{ width: "20%" }}>2. Stateful Inspection</th>
                <th style={{ width: "19%" }}>3. Application Gateway</th>
                <th style={{ width: "19%" }}>4. Next-Gen (NGFW)</th>
              </tr>
            </thead>
            <tbody>
              {COMPARISON_MATRIX.map((row, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 600, color: "var(--navy-dark)" }}>{row.feature}</td>
                  <td style={{ fontSize: "0.8125rem", color: idx === 4 ? "var(--primary-blue)" : "var(--text-secondary)", fontWeight: idx === 4 ? 600 : 400 }}>
                    {row.packet}
                  </td>
                  <td style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>{row.stateful}</td>
                  <td style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>{row.alg}</td>
                  <td style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>{row.ngfw}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deep-Dive Cards for the 4 Firewall Types */}
      <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
        {concepts.map((c) => (
          <div key={c.id} className="sentinel-card">
            <h3 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--navy-dark)", marginBottom: "0.5rem" }}>
              {c.name}
            </h3>

            <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: "1rem" }}>
              <strong>Definition:</strong> {c.definition}
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1rem", marginBottom: "1rem" }}>
              <div style={{ backgroundColor: "#f8fafc", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
                <strong style={{ fontSize: "0.8125rem", color: "var(--navy-dark)" }}>How It Works</strong>
                <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginTop: "0.25rem", lineHeight: 1.45 }}>
                  {c.how_it_works}
                </p>
              </div>

              <div style={{ backgroundColor: "#f8fafc", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
                <strong style={{ fontSize: "0.8125rem", color: "var(--navy-dark)" }}>What It Examines</strong>
                <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginTop: "0.25rem", lineHeight: 1.45 }}>
                  {c.what_it_examines}
                </p>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1rem" }}>
              <div style={{ backgroundColor: "#f0fdf4", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid #bbf7d0" }}>
                <strong style={{ fontSize: "0.8125rem", color: "var(--success-green)" }}>Advantages</strong>
                <ul style={{ paddingLeft: "1.25rem", marginTop: "0.25rem", fontSize: "0.8125rem", color: "#14532d", lineHeight: 1.45 }}>
                  {c.advantages?.map((adv, idx) => (
                    <li key={idx}>{adv}</li>
                  ))}
                </ul>
              </div>

              <div style={{ backgroundColor: "#fef2f2", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid #fecaca" }}>
                <strong style={{ fontSize: "0.8125rem", color: "var(--danger-red)" }}>Limitations</strong>
                <ul style={{ paddingLeft: "1.25rem", marginTop: "0.25rem", fontSize: "0.8125rem", color: "#7f1d1d", lineHeight: 1.45 }}>
                  {c.limitations?.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div style={{ backgroundColor: "#faf5ff", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid #e9d5ff", marginBottom: "0.75rem", fontSize: "0.8125rem" }}>
              <strong style={{ color: "#7e22ce" }}>Practical Real-World Example:</strong>
              <div style={{ color: "#581c87", marginTop: "0.25rem" }}>{c.practical_example}</div>
            </div>

            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              <strong>Sentinel Implementation Note:</strong> {c.sentinel_simulation_note}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
