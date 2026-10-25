import React from "react";
import { CheckCircle2, XCircle, ArrowRight, Shield, Layers, FileText, Activity } from "lucide-react";

export default function PacketJourneyVisualizer({ result }) {
  if (!result) return null;

  const isAllowed = result.decision === "ALLOW";
  const statusColor = isAllowed ? "var(--success-green)" : "var(--danger-red)";
  const statusBg = isAllowed ? "var(--success-bg)" : "var(--danger-bg)";
  const statusBorder = isAllowed ? "var(--success-border)" : "var(--danger-border)";

  const packet = result.packet_details || {};

  return (
    <div style={{ marginTop: "1.25rem" }}>
      {/* 4-Step Pipeline Journey Cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "1rem",
          alignItems: "center",
          marginBottom: "1.5rem",
        }}
      >
        {/* Step 1: Packet Created */}
        <div
          className="sentinel-card"
          style={{
            borderLeft: "4px solid var(--primary-blue)",
            backgroundColor: "#ffffff",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <Activity size={18} color="var(--primary-blue)" />
            <span style={{ fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)" }}>
              Step 1
            </span>
          </div>
          <div style={{ fontWeight: 600, fontSize: "0.9375rem", color: "var(--navy-dark)", marginBottom: "0.25rem" }}>
            Packet Generated
          </div>
          <div style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", lineHeight: 1.4 }}>
            <div><strong>Src:</strong> {packet.source_ip || "Any"}</div>
            <div><strong>Dst:</strong> {packet.destination_ip || "Any"} : {packet.destination_port || "*"}</div>
            <div><strong>Proto:</strong> {packet.protocol} ({packet.packet_size || 64} B)</div>
          </div>
        </div>

        {/* Step 2: Firewall Rules Evaluated */}
        <div
          className="sentinel-card"
          style={{
            borderLeft: "4px solid #6366f1",
            backgroundColor: "#ffffff",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <Layers size={18} color="#6366f1" />
            <span style={{ fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)" }}>
              Step 2
            </span>
          </div>
          <div style={{ fontWeight: 600, fontSize: "0.9375rem", color: "var(--navy-dark)", marginBottom: "0.25rem" }}>
            Rules Inspected
          </div>
          <div style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", lineHeight: 1.4 }}>
            <div>Evaluated in ascending priority</div>
            <div>Tested: {result.evaluation_steps?.length || 0} configured rules</div>
            <div style={{ color: "#6366f1", fontWeight: 500 }}>First-match policy</div>
          </div>
        </div>

        {/* Step 3: Match / Decision */}
        <div
          className="sentinel-card"
          style={{
            borderLeft: `4px solid ${statusColor}`,
            backgroundColor: "#ffffff",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <Shield size={18} color={statusColor} />
            <span style={{ fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)" }}>
              Step 3
            </span>
          </div>
          <div style={{ fontWeight: 600, fontSize: "0.9375rem", color: "var(--navy-dark)", marginBottom: "0.25rem" }}>
            Firewall Decision
          </div>
          <div style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", lineHeight: 1.4 }}>
            {result.matched_rule_id ? (
              <>
                <div>Rule #{result.matched_rule_id}</div>
                <div style={{ fontWeight: 600, color: statusColor }}>{result.matched_rule_name}</div>
              </>
            ) : (
              <div>Default Fallback Policy</div>
            )}
          </div>
        </div>

        {/* Step 4: Final Outcome */}
        <div
          className="sentinel-card"
          style={{
            backgroundColor: statusBg,
            border: `1px solid ${statusBorder}`,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            textAlign: "center",
            padding: "1rem",
          }}
        >
          {isAllowed ? (
            <CheckCircle2 size={36} color="var(--success-green)" style={{ marginBottom: "0.25rem" }} />
          ) : (
            <XCircle size={36} color="var(--danger-red)" style={{ marginBottom: "0.25rem" }} />
          )}
          <span style={{ fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", color: statusColor }}>
            Final Result
          </span>
          <span style={{ fontSize: "1.25rem", fontWeight: 700, color: statusColor }}>
            {result.decision}
          </span>
        </div>
      </div>

      {/* Human-Readable Explanation Banner */}
      <div
        style={{
          backgroundColor: "#ffffff",
          border: "1px solid var(--border-color)",
          borderRadius: "var(--radius-md)",
          padding: "1rem 1.25rem",
          marginBottom: "1rem",
        }}
      >
        <h4 style={{ fontSize: "0.9375rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.35rem" }}>
          Decision Summary
        </h4>
        <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
          {result.reason}
        </p>
      </div>

      {/* Step-by-Step Rule Audit Log */}
      {result.evaluation_steps && result.evaluation_steps.length > 0 && (
        <div style={{ backgroundColor: "#ffffff", border: "1px solid var(--border-color)", borderRadius: "var(--radius-md)", padding: "1rem" }}>
          <h4 style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.75rem" }}>
            Sequential Rule Evaluation Trace (Ascending Priority)
          </h4>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {result.evaluation_steps.map((step, idx) => (
              <div
                key={idx}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "0.5rem 0.75rem",
                  borderRadius: "var(--radius-sm)",
                  fontSize: "0.8125rem",
                  backgroundColor: step.matched
                    ? isAllowed
                      ? "var(--success-bg)"
                      : "var(--danger-bg)"
                    : !step.is_enabled
                    ? "var(--bg-subtle)"
                    : "#f8fafc",
                  border: step.matched
                    ? `1px solid ${statusBorder}`
                    : "1px solid var(--border-color)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                  <span style={{ fontWeight: 700, color: "var(--text-muted)", width: 48 }}>
                    #{step.priority}
                  </span>
                  <div>
                    <span style={{ fontWeight: 600, color: "var(--navy-dark)" }}>{step.rule_name}</span>
                    <span style={{ color: "var(--text-muted)", marginLeft: "0.5rem" }}>({step.reason})</span>
                  </div>
                </div>
                <div>
                  {step.matched ? (
                    <span className={`badge ${isAllowed ? "badge-allow" : "badge-block"}`}>MATCHED</span>
                  ) : !step.is_enabled ? (
                    <span className="badge badge-warning">DISABLED</span>
                  ) : (
                    <span className="badge" style={{ backgroundColor: "var(--bg-subtle)", color: "var(--text-muted)" }}>SKIPPED</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
