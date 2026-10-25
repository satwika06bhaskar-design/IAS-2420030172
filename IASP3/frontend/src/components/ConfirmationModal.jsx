import React from "react";
import { AlertTriangle, X } from "lucide-react";

export default function ConfirmationModal({
  isOpen,
  title = "Confirm Action",
  message = "Are you sure you want to proceed?",
  confirmText = "Confirm",
  confirmVariant = "danger", // danger or primary
  onConfirm,
  onCancel,
}) {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 440 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: "50%",
                backgroundColor: confirmVariant === "danger" ? "var(--danger-bg)" : "var(--primary-light)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: confirmVariant === "danger" ? "var(--danger-red)" : "var(--primary-blue)",
              }}
            >
              <AlertTriangle size={20} />
            </div>
            <h3 style={{ fontSize: "1.125rem", color: "var(--navy-dark)", fontWeight: 600 }}>{title}</h3>
          </div>
          <button onClick={onCancel} style={{ color: "var(--text-muted)" }}>
            <X size={18} />
          </button>
        </div>

        <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem", marginBottom: "1.5rem", lineHeight: 1.5 }}>
          {message}
        </p>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem" }}>
          <button className="btn btn-secondary" onClick={onCancel}>
            Cancel
          </button>
          <button
            className={`btn ${confirmVariant === "danger" ? "btn-danger" : "btn-primary"}`}
            onClick={onConfirm}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
