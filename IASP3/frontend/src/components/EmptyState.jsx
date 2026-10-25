import React from "react";
import { Inbox } from "lucide-react";

export default function EmptyState({
  icon: Icon = Inbox,
  title = "No data found",
  description = "No records match the current criteria or no simulation events have occurred yet.",
  actionText,
  onAction,
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "3rem 1.5rem",
        textAlign: "center",
        backgroundColor: "#ffffff",
        borderRadius: "var(--radius-md)",
        border: "1px dashed var(--border-color)",
      }}
    >
      <div
        style={{
          width: 48,
          height: 48,
          borderRadius: "50%",
          backgroundColor: "var(--bg-subtle)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--text-muted)",
          marginBottom: "1rem",
        }}
      >
        <Icon size={24} />
      </div>
      <h4 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.25rem" }}>
        {title}
      </h4>
      <p style={{ fontSize: "0.875rem", color: "var(--text-muted)", maxWidth: 380, marginBottom: actionText ? "1rem" : 0 }}>
        {description}
      </p>
      {actionText && onAction && (
        <button className="btn btn-secondary btn-sm" onClick={onAction}>
          {actionText}
        </button>
      )}
    </div>
  );
}
