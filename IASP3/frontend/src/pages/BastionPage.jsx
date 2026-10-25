import React, { useState, useEffect } from "react";
import {
  Server,
  Plus,
  Shield,
  CheckCircle,
  XCircle,
  Power,
  Edit,
  Trash2,
  Lock,
  ArrowRight,
  Activity,
  AlertTriangle,
  Play,
  X,
  FileCheck,
} from "lucide-react";
import { api } from "../services/api";
import ConfirmationModal from "../components/ConfirmationModal";
import EmptyState from "../components/EmptyState";

const HARDENING_PRACTICES = [
  {
    title: "1. Restrict Exposed Services & Daemons",
    desc: "Disable all non-essential protocols, services, and compilers (e.g. disable Telnet, FTP, X11, printing). Only bind the single hardened management protocol.",
    impact: "Minimizes the attack surface to the bare minimum.",
  },
  {
    title: "2. Enforce Multi-Factor Authentication (MFA)",
    desc: "Mandate hardware security keys (FIDO2) or TOTP tokens in addition to cryptographically verified SSH public keys. Prohibit raw password authentication.",
    impact: "Prevents account takeover even if passwords are leaked.",
  },
  {
    title: "3. Limit Administrative Access & Least Privilege",
    desc: "Restrict bastion access to specific authorized administrative IP subnets via firewall rules. Disallow direct root logins (`PermitRootLogin no`).",
    impact: "Constrains lateral traversal and rogue insider access.",
  },
  {
    title: "4. Apply Continuous Security Updates",
    desc: "Automate kernel and OpenSSH security patching via unattended upgrades and vulnerability scanning.",
    impact: "Immunizes perimeter hosts against known public exploits.",
  },
  {
    title: "5. Comprehensive Monitoring & Session Audit",
    desc: "Record all administrative terminal keystrokes and session multiplexing to an immutable write-once remote SIEM repository.",
    impact: "Guarantees complete forensic accountability.",
  },
];

export default function BastionPage() {
  const [hosts, setHosts] = useState([]);
  const [loading, setLoading] = useState(true);

  // Modals & Form
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingHost, setEditingHost] = useState(null);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [hostToDelete, setHostToDelete] = useState(null);

  const [formData, setFormData] = useState({
    name: "",
    ip_address: "10.0.0.254",
    purpose: "Perimeter Management Jump Box",
    management_protocol: "SSH",
    management_port: 22,
    admin_access_status: "MFA_REQUIRED",
    monitoring_status: "ACTIVE",
    is_enabled: true,
    description: "",
  });
  const [formError, setFormError] = useState("");

  // Connection Test Simulator State
  const [testHostId, setTestHostId] = useState("");
  const [testPort, setTestPort] = useState(22);
  const [testProtocol, setTestProtocol] = useState("SSH");
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const fetchHosts = async () => {
    try {
      setLoading(true);
      const data = await api.getBastionHosts();
      setHosts(data);
      if (data.length > 0 && !testHostId) {
        setTestHostId(data[0].id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHosts();
  }, []);

  const handleOpenAdd = () => {
    setEditingHost(null);
    setFormData({
      name: "",
      ip_address: "10.0.0.254",
      purpose: "Perimeter Jump Host",
      management_protocol: "SSH",
      management_port: 22,
      admin_access_status: "MFA_REQUIRED",
      monitoring_status: "ACTIVE",
      is_enabled: true,
      description: "",
    });
    setFormError("");
    setIsModalOpen(true);
  };

  const handleOpenEdit = (host) => {
    setEditingHost(host);
    setFormData({
      name: host.name,
      ip_address: host.ip_address,
      purpose: host.purpose,
      management_protocol: host.management_protocol,
      management_port: host.management_port,
      admin_access_status: host.admin_access_status,
      monitoring_status: host.monitoring_status,
      is_enabled: host.is_enabled,
      description: host.description || "",
    });
    setFormError("");
    setIsModalOpen(true);
  };

  const handleSaveHost = async (e) => {
    e.preventDefault();
    setFormError("");
    try {
      if (editingHost) {
        await api.updateBastionHost(editingHost.id, formData);
      } else {
        await api.createBastionHost(formData);
      }
      setIsModalOpen(false);
      fetchHosts();
    } catch (err) {
      setFormError(err.message);
    }
  };

  const handleToggleHost = async (id) => {
    try {
      await api.toggleBastionHost(id);
      fetchHosts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteHost = async () => {
    if (!hostToDelete) return;
    try {
      await api.deleteBastionHost(hostToDelete.id);
      setDeleteModalOpen(false);
      fetchHosts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleTestConnection = async (e) => {
    e.preventDefault();
    if (!testHostId) return;
    try {
      setTesting(true);
      const res = await api.testBastionConnection({
        host_id: parseInt(testHostId),
        source_ip: "203.0.113.45",
        attempted_port: parseInt(testPort) || 22,
        protocol: testProtocol,
        auth_credentials_valid: true,
      });
      setTestResult(res);
    } catch (err) {
      alert(`Test failed: ${err.message}`);
    } finally {
      setTesting(false);
    }
  };

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
            Bastion Host Perimeter Architecture
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", maxWidth: 750 }}>
            A bastion host is a specially hardened, locked-down server positioned at the network boundary. It acts as the single controlled gateway through which all administrative traffic must transit before entering internal protected subnets.
          </p>
        </div>

        <button className="btn btn-primary btn-sm" onClick={handleOpenAdd}>
          <Plus size={16} />
          <span>Add Bastion Host</span>
        </button>
      </div>

      {/* Visual Network Topology Diagram Card */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "1rem" }}>
          Perimeter Mediation Architecture
        </h3>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "1rem",
            backgroundColor: "#f8fafc",
            border: "1px solid var(--border-color)",
            borderRadius: "var(--radius-md)",
            padding: "1.5rem",
          }}
        >
          {/* External Network */}
          <div
            style={{
              flex: 1,
              minWidth: 180,
              backgroundColor: "#ffffff",
              border: "1px solid #fca5a5",
              borderRadius: "var(--radius-sm)",
              padding: "1rem",
              textAlign: "center",
            }}
          >
            <div style={{ color: "var(--danger-red)", fontWeight: 700, fontSize: "0.875rem", marginBottom: "0.25rem" }}>
              Untrusted External Network
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Internet / Remote Admin IP</div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginTop: "0.5rem" }}>
              Direct access to database/internal servers is strictly BLOCKED by firewall.
            </div>
          </div>

          <ArrowRight size={24} color="#94a3b8" />

          {/* Bastion Host Box */}
          <div
            style={{
              flex: 1.2,
              minWidth: 220,
              backgroundColor: "#ffffff",
              border: "2px solid var(--primary-blue)",
              borderRadius: "var(--radius-md)",
              padding: "1.25rem",
              textAlign: "center",
              boxShadow: "var(--shadow-sm)",
            }}
          >
            <div style={{ display: "inline-flex", padding: "0.35rem", borderRadius: "50%", backgroundColor: "var(--primary-light)", color: "var(--primary-blue)", marginBottom: "0.5rem" }}>
              <Lock size={20} />
            </div>
            <div style={{ color: "var(--primary-blue)", fontWeight: 700, fontSize: "0.9375rem" }}>
              Hardened Bastion Host (Jump Box)
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
              Single Ingress Point &bull; MFA Required &bull; Full Keystroke Audit Log
            </div>
            <div style={{ marginTop: "0.5rem", display: "inline-block" }}>
              <span className="badge badge-info" style={{ fontSize: "0.7rem" }}>Only SSH Port 22 Open</span>
            </div>
          </div>

          <ArrowRight size={24} color="#94a3b8" />

          {/* Protected Internal Enclave */}
          <div
            style={{
              flex: 1,
              minWidth: 180,
              backgroundColor: "#ffffff",
              border: "1px solid #86efac",
              borderRadius: "var(--radius-sm)",
              padding: "1rem",
              textAlign: "center",
            }}
          >
            <div style={{ color: "var(--success-green)", fontWeight: 700, fontSize: "0.875rem", marginBottom: "0.25rem" }}>
              Protected Internal Network
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Isolated Database & App Servers</div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginTop: "0.5rem" }}>
              Accepts administrative SSH connections <em>only</em> if sourced from the Bastion Host.
            </div>
          </div>
        </div>
      </div>

      {/* Bastion Host Management List */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "1rem" }}>
          Configured Bastion Hosts ({hosts.length})
        </h3>

        {hosts.length > 0 ? (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
              gap: "1rem",
            }}
          >
            {hosts.map((host) => (
              <div
                key={host.id}
                className="sentinel-card"
                style={{
                  border: "1px solid var(--border-color)",
                  borderTop: `4px solid ${host.is_enabled ? "var(--primary-blue)" : "var(--text-muted)"}`,
                  opacity: host.is_enabled ? 1 : 0.6,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.75rem" }}>
                  <div>
                    <h4 style={{ fontSize: "0.9375rem", fontWeight: 700, color: "var(--navy-dark)" }}>
                      {host.name}
                    </h4>
                    <span style={{ fontSize: "0.75rem", fontFamily: "monospace", color: "var(--primary-blue)" }}>
                      {host.ip_address}
                    </span>
                  </div>
                  <button
                    onClick={() => handleToggleHost(host.id)}
                    className={`badge ${host.is_enabled ? "badge-allow" : "badge-warning"}`}
                    title="Toggle host operational state"
                  >
                    <Power size={11} />
                    <span>{host.is_enabled ? "Online" : "Offline"}</span>
                  </button>
                </div>

                <div style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginBottom: "0.75rem", minHeight: 36 }}>
                  {host.purpose}
                </div>

                <div style={{ fontSize: "0.75rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", backgroundColor: "var(--bg-subtle)", padding: "0.6rem", borderRadius: "var(--radius-sm)", marginBottom: "1rem" }}>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Protocol: </span>
                    <strong>{host.management_protocol}:{host.management_port}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Auth: </span>
                    <strong>{host.admin_access_status}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Audit: </span>
                    <strong>{host.monitoring_status}</strong>
                  </div>
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
                  <button className="btn btn-secondary btn-sm" onClick={() => handleOpenEdit(host)}>
                    <Edit size={14} />
                    <span>Edit</span>
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    style={{ color: "var(--danger-red)" }}
                    onClick={() => {
                      setHostToDelete(host);
                      setDeleteModalOpen(true);
                    }}
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            title="No bastion hosts configured"
            description="Add a simulated bastion host to configure perimeter management access controls."
            actionText="Add Bastion Host"
            onAction={handleOpenAdd}
          />
        )}
      </div>

      {/* Interactive Bastion Connection Simulator */}
      <div className="sentinel-card" style={{ marginBottom: "1.5rem" }}>
        <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.5rem" }}>
          Interactive Access Verification Tool
        </h3>
        <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
          Simulates an external administrative connection through the bastion host to verify security enforcement (host status, port binding, and MFA challenge).
        </p>

        <form onSubmit={handleTestConnection} style={{ display: "flex", alignItems: "flex-end", gap: "1rem", flexWrap: "wrap", marginBottom: "1rem" }}>
          <div className="form-group" style={{ marginBottom: 0, minWidth: 200 }}>
            <label className="form-label">Target Bastion Host</label>
            <select
              className="form-select"
              value={testHostId}
              onChange={(e) => setTestHostId(e.target.value)}
              required
            >
              {hosts.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.name} ({h.ip_address})
                </option>
              ))}
            </select>
          </div>

          <div className="form-group" style={{ marginBottom: 0, width: 120 }}>
            <label className="form-label">Protocol</label>
            <select
              className="form-select"
              value={testProtocol}
              onChange={(e) => setTestProtocol(e.target.value)}
            >
              <option value="SSH">SSH</option>
              <option value="HTTPS">HTTPS</option>
              <option value="TELNET">TELNET</option>
              <option value="RDP">RDP</option>
            </select>
          </div>

          <div className="form-group" style={{ marginBottom: 0, width: 110 }}>
            <label className="form-label">Target Port</label>
            <input
              type="number"
              min="1"
              max="65535"
              className="form-input"
              value={testPort}
              onChange={(e) => setTestPort(e.target.value)}
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={testing || hosts.length === 0}>
            <Play size={16} />
            <span>{testing ? "Testing..." : "Test Connection"}</span>
          </button>
        </form>

        {/* Test Result Output Card */}
        {testResult && (
          <div
            style={{
              marginTop: "1rem",
              padding: "1rem",
              borderRadius: "var(--radius-md)",
              backgroundColor: testResult.connection_status === "ACCEPTED" ? "var(--success-bg)" : "var(--danger-bg)",
              border: `1px solid ${testResult.connection_status === "ACCEPTED" ? "var(--success-border)" : "var(--danger-border)"}`,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
              {testResult.connection_status === "ACCEPTED" ? (
                <CheckCircle size={20} color="var(--success-green)" />
              ) : (
                <XCircle size={20} color="var(--danger-red)" />
              )}
              <h4 style={{ fontSize: "0.9375rem", fontWeight: 700, color: testResult.connection_status === "ACCEPTED" ? "var(--success-green)" : "var(--danger-red)" }}>
                Status: {testResult.connection_status}
              </h4>
            </div>

            <p style={{ fontSize: "0.875rem", color: "var(--navy-dark)", marginBottom: "0.75rem", lineHeight: 1.4 }}>
              {testResult.explanation}
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
              {testResult.security_checks?.map((chk, idx) => (
                <div key={idx} style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.8125rem" }}>
                  {chk.passed ? (
                    <CheckCircle size={14} color="var(--success-green)" />
                  ) : (
                    <XCircle size={14} color="var(--danger-red)" />
                  )}
                  <span><strong>{chk.check}:</strong> {chk.detail}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Bastion Hardening Practices Cards */}
      <div className="sentinel-card">
        <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)", marginBottom: "0.75rem" }}>
          Industry Hardening Principles for Bastion Systems
        </h3>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: "1rem",
          }}
        >
          {HARDENING_PRACTICES.map((prac, i) => (
            <div
              key={i}
              style={{
                backgroundColor: "#f8fafc",
                border: "1px solid var(--border-color)",
                borderRadius: "var(--radius-sm)",
                padding: "1rem",
              }}
            >
              <h4 style={{ fontSize: "0.875rem", fontWeight: 700, color: "var(--navy-dark)", marginBottom: "0.35rem" }}>
                {prac.title}
              </h4>
              <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginBottom: "0.5rem", lineHeight: 1.4 }}>
                {prac.desc}
              </p>
              <div style={{ fontSize: "0.75rem", color: "var(--primary-blue)", fontWeight: 500 }}>
                &rarr; {prac.impact}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Add / Edit Bastion Modal */}
      {isModalOpen && (
        <div className="modal-overlay" onClick={() => setIsModalOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
              <h3 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--navy-dark)" }}>
                {editingHost ? `Edit Bastion Host: ${editingHost.name}` : "Configure New Bastion Host"}
              </h3>
              <button onClick={() => setIsModalOpen(false)} style={{ color: "var(--text-muted)" }}>
                <X size={18} />
              </button>
            </div>

            {formError && (
              <div
                style={{
                  padding: "0.6rem 0.8rem",
                  backgroundColor: "var(--danger-bg)",
                  color: "var(--danger-red)",
                  border: "1px solid var(--danger-border)",
                  borderRadius: "var(--radius-sm)",
                  fontSize: "0.8125rem",
                  marginBottom: "1rem",
                }}
              >
                {formError}
              </div>
            )}

            <form onSubmit={handleSaveHost}>
              <div className="form-group">
                <label className="form-label">Server Host Name *</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Sentinel-Jump-01"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div className="form-group">
                  <label className="form-label">Simulated IP Address *</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.ip_address}
                    onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Purpose / Role *</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. Database Tier Ingress"
                    value={formData.purpose}
                    onChange={(e) => setFormData({ ...formData, purpose: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div className="form-group">
                  <label className="form-label">Management Protocol</label>
                  <select
                    className="form-select"
                    value={formData.management_protocol}
                    onChange={(e) => setFormData({ ...formData, management_protocol: e.target.value })}
                  >
                    <option value="SSH">SSH</option>
                    <option value="HTTPS">HTTPS</option>
                    <option value="RDP">RDP</option>
                    <option value="VPN">VPN</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Management Port</label>
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    className="form-input"
                    value={formData.management_port}
                    onChange={(e) => setFormData({ ...formData, management_port: parseInt(e.target.value) || 22 })}
                    required
                  />
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div className="form-group">
                  <label className="form-label">Admin Access Policy</label>
                  <select
                    className="form-select"
                    value={formData.admin_access_status}
                    onChange={(e) => setFormData({ ...formData, admin_access_status: e.target.value })}
                  >
                    <option value="MFA_REQUIRED">MFA Required (FIDO2 / TOTP)</option>
                    <option value="RESTRICTED">Restricted Whitelist Only</option>
                    <option value="FULL">Standard Access</option>
                    <option value="DISABLED">Administrative Access Disabled</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Monitoring & Audit Status</label>
                  <select
                    className="form-select"
                    value={formData.monitoring_status}
                    onChange={(e) => setFormData({ ...formData, monitoring_status: e.target.value })}
                  >
                    <option value="ACTIVE">Active SIEM Logging</option>
                    <option value="ENHANCED">Enhanced Keystroke Recording</option>
                    <option value="OFFLINE">Offline Audit Logs</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <input
                    type="checkbox"
                    id="host_enabled_check"
                    checked={formData.is_enabled}
                    onChange={(e) => setFormData({ ...formData, is_enabled: e.target.checked })}
                    style={{ width: 16, height: 16 }}
                  />
                  <label htmlFor="host_enabled_check" style={{ fontSize: "0.875rem", fontWeight: 600, cursor: "pointer" }}>
                    Enable Bastion Host (Online)
                  </label>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Description / Operational Notes</label>
                <textarea
                  className="form-textarea"
                  rows={2}
                  placeholder="Security notes, hardening parameters..."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "1.25rem" }}>
                <button type="button" className="btn btn-secondary" onClick={() => setIsModalOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  {editingHost ? "Save Changes" : "Create Host"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      <ConfirmationModal
        isOpen={deleteModalOpen}
        title="Delete Bastion Host?"
        message={`Are you sure you want to delete bastion host '${hostToDelete?.name}' (${hostToDelete?.ip_address})?`}
        confirmText="Delete Host"
        confirmVariant="danger"
        onConfirm={handleDeleteHost}
        onCancel={() => setDeleteModalOpen(false)}
      />
    </div>
  );
}
