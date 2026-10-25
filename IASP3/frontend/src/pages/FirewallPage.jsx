import React, { useState, useEffect } from "react";
import {
  Sliders,
  Plus,
  Search,
  Filter,
  Trash2,
  Edit,
  Power,
  RotateCcw,
  Play,
  Check,
  Shield,
  HelpCircle,
  AlertCircle,
  X
} from "lucide-react";
import { api } from "../services/api";
import PacketJourneyVisualizer from "../components/PacketJourneyVisualizer";
import ConfirmationModal from "../components/ConfirmationModal";
import EmptyState from "../components/EmptyState";

const PRESET_TEST_SCENARIOS = [
  {
    name: "Standard HTTP Traffic",
    source_ip: "192.168.1.45",
    destination_ip: "10.0.0.80",
    protocol: "TCP",
    destination_port: 80,
    packet_size: 512,
    desc: "Permitted web request matching Allow HTTP rule (TCP 80)",
  },
  {
    name: "Secure HTTPS Traffic",
    source_ip: "192.168.1.100",
    destination_ip: "10.0.0.80",
    protocol: "TCP",
    destination_port: 443,
    packet_size: 1024,
    desc: "Encrypted web session on port 443",
  },
  {
    name: "Telnet Legacy Probe",
    source_ip: "198.51.100.23",
    destination_ip: "10.0.0.1",
    protocol: "TCP",
    destination_port: 23,
    packet_size: 64,
    desc: "Insecure Telnet connection matching Block Telnet rule (Port 23)",
  },
  {
    name: "Known Malicious Host",
    source_ip: "203.0.113.100",
    destination_ip: "10.0.0.5",
    protocol: "TCP",
    destination_port: 80,
    packet_size: 128,
    desc: "Traffic from blocked source IP 203.0.113.100 (Priority 10)",
  },
];

export default function FirewallPage() {
  const [rules, setRules] = useState([]);
  const [defaultPolicy, setDefaultPolicy] = useState("BLOCK");
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  // Modals & form state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [ruleToDelete, setRuleToDelete] = useState(null);
  const [resetDemoModalOpen, setResetDemoModalOpen] = useState(false);

  // Form inputs
  const [formData, setFormData] = useState({
    name: "",
    source_ip: "ANY",
    destination_ip: "ANY",
    destination_port: "ANY",
    protocol: "ANY",
    action: "ALLOW",
    priority: 100,
    is_enabled: true,
    description: "",
  });
  const [formError, setFormError] = useState("");

  // Packet tester state
  const [testPacket, setTestPacket] = useState({
    source_ip: "192.168.1.45",
    destination_ip: "10.0.0.80",
    protocol: "TCP",
    destination_port: 80,
    packet_size: 256,
  });
  const [simulationResult, setSimulationResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  const fetchRules = async () => {
    try {
      setLoading(true);
      const [rulesData, policyData] = await Promise.all([
        api.getFirewallRules({
          action: actionFilter,
          protocol: protocolFilter,
          is_enabled: statusFilter,
          search: search,
        }),
        api.getDefaultPolicy(),
      ]);
      setRules(rulesData);
      setDefaultPolicy(policyData.policy);
    } catch (err) {
      console.error("Error fetching rules:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, [actionFilter, protocolFilter, statusFilter, search]);

  const handleOpenAddModal = () => {
    setEditingRule(null);
    setFormData({
      name: "",
      source_ip: "ANY",
      destination_ip: "ANY",
      destination_port: "ANY",
      protocol: "ANY",
      action: "ALLOW",
      priority: rules.length > 0 ? Math.max(...rules.map((r) => r.priority)) + 10 : 50,
      is_enabled: true,
      description: "",
    });
    setFormError("");
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (rule) => {
    setEditingRule(rule);
    setFormData({
      name: rule.name,
      source_ip: rule.source_ip || "ANY",
      destination_ip: rule.destination_ip || "ANY",
      destination_port: rule.destination_port || "ANY",
      protocol: rule.protocol,
      action: rule.action,
      priority: rule.priority,
      is_enabled: rule.is_enabled,
      description: rule.description || "",
    });
    setFormError("");
    setIsModalOpen(true);
  };

  const handleSaveRule = async (e) => {
    e.preventDefault();
    setFormError("");
    try {
      if (editingRule) {
        await api.updateFirewallRule(editingRule.id, formData);
      } else {
        await api.createFirewallRule(formData);
      }
      setIsModalOpen(false);
      fetchRules();
    } catch (err) {
      setFormError(err.message);
    }
  };

  const handleToggleRule = async (ruleId) => {
    try {
      await api.toggleFirewallRule(ruleId);
      fetchRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteRule = async () => {
    if (!ruleToDelete) return;
    try {
      await api.deleteFirewallRule(ruleToDelete.id);
      setDeleteModalOpen(false);
      fetchRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleToggleDefaultPolicy = async () => {
    const newPolicy = defaultPolicy === "ALLOW" ? "BLOCK" : "ALLOW";
    try {
      await api.setDefaultPolicy(newPolicy);
      setDefaultPolicy(newPolicy);
    } catch (err) {
      console.error(err);
    }
  };

  const handleResetDemo = async () => {
    try {
      await api.resetFirewallDemoRules();
      setResetDemoModalOpen(false);
      fetchRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleSimulatePacket = async (e) => {
    if (e) e.preventDefault();
    try {
      setSimulating(true);
      const res = await api.simulatePacket(testPacket);
      setSimulationResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setSimulating(false);
    }
  };

  const applyPresetScenario = (scenario) => {
    setTestPacket({
      source_ip: scenario.source_ip,
      destination_ip: scenario.destination_ip,
      protocol: scenario.protocol,
      destination_port: scenario.destination_port,
      packet_size: scenario.packet_size,
    });
  };

  return (
    <div>
      {/* Top Controls Header */}
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
            Firewall Rule Manager
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)" }}>
            Configure and order rules using first-match policy. Rules are evaluated in ascending priority order.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
          {/* Default Policy Indicator & Toggle */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              padding: "0.4rem 0.75rem",
              borderRadius: "var(--radius-sm)",
              backgroundColor: defaultPolicy === "BLOCK" ? "var(--danger-bg)" : "var(--success-bg)",
              border: `1px solid ${defaultPolicy === "BLOCK" ? "var(--danger-border)" : "var(--success-border)"}`,
            }}
          >
            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)" }}>
              Fallback Default:
            </span>
            <button
              onClick={handleToggleDefaultPolicy}
              style={{
                fontWeight: 700,
                fontSize: "0.8125rem",
                color: defaultPolicy === "BLOCK" ? "var(--danger-red)" : "var(--success-green)",
                textDecoration: "underline",
              }}
              title="Click to toggle default fallback policy"
            >
              {defaultPolicy}
            </button>
          </div>

          <button className="btn btn-secondary btn-sm" onClick={() => setResetDemoModalOpen(true)}>
            <RotateCcw size={14} />
            <span>Reset Demo Rules</span>
          </button>

          <button className="btn btn-primary btn-sm" onClick={handleOpenAddModal}>
            <Plus size={16} />
            <span>Add Rule</span>
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
        <div style={{ position: "relative", flex: 1, minWidth: 200 }}>
          <Search size={16} style={{ position: "absolute", left: 10, top: 10, color: "var(--text-muted)" }} />
          <input
            type="text"
            className="form-input"
            style={{ paddingLeft: "2rem" }}
            placeholder="Search rules by name, IP, port, description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <select
            className="form-select"
            style={{ width: "auto" }}
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
          >
            <option value="">All Actions</option>
            <option value="ALLOW">Action: ALLOW</option>
            <option value="BLOCK">Action: BLOCK</option>
          </select>

          <select
            className="form-select"
            style={{ width: "auto" }}
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="ANY">ANY</option>
          </select>

          <select
            className="form-select"
            style={{ width: "auto" }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All Statuses</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </div>
      </div>

      {/* Rules Table */}
      <div className="sentinel-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--navy-dark)" }}>
            Configured Firewall Rules ({rules.length})
          </h3>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            First match wins (evaluated from top to bottom)
          </span>
        </div>

        {rules.length > 0 ? (
          <div className="table-container">
            <table className="sentinel-table">
              <thead>
                <tr>
                  <th style={{ width: 80 }}>Priority</th>
                  <th>Rule Name</th>
                  <th>Source IP / Subnet</th>
                  <th>Destination IP</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>Action</th>
                  <th>Status</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} style={{ opacity: rule.is_enabled ? 1 : 0.55 }}>
                    <td style={{ fontWeight: 700, color: "var(--text-muted)", fontSize: "0.875rem" }}>
                      #{rule.priority}
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: "var(--navy-dark)" }}>{rule.name}</div>
                      {rule.description && (
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{rule.description}</div>
                      )}
                    </td>
                    <td style={{ fontFamily: "monospace", fontSize: "0.8125rem" }}>{rule.source_ip || "ANY"}</td>
                    <td style={{ fontFamily: "monospace", fontSize: "0.8125rem" }}>{rule.destination_ip || "ANY"}</td>
                    <td style={{ fontFamily: "monospace", fontSize: "0.8125rem" }}>{rule.destination_port || "ANY"}</td>
                    <td>
                      <span className="badge badge-info">{rule.protocol}</span>
                    </td>
                    <td>
                      <span className={`badge ${rule.action === "ALLOW" ? "badge-allow" : "badge-block"}`}>
                        {rule.action}
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={() => handleToggleRule(rule.id)}
                        className={`badge ${rule.is_enabled ? "badge-allow" : "badge-warning"}`}
                        style={{ cursor: "pointer" }}
                        title="Click to enable or disable this rule"
                      >
                        <Power size={11} />
                        <span>{rule.is_enabled ? "Enabled" : "Disabled"}</span>
                      </button>
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div style={{ display: "inline-flex", gap: "0.5rem" }}>
                        <button
                          onClick={() => handleOpenEditModal(rule)}
                          style={{ color: "var(--primary-blue)", padding: "0.25rem" }}
                          title="Edit Rule"
                        >
                          <Edit size={16} />
                        </button>
                        <button
                          onClick={() => {
                            setRuleToDelete(rule);
                            setDeleteModalOpen(true);
                          }}
                          style={{ color: "var(--danger-red)", padding: "0.25rem" }}
                          title="Delete Rule"
                        >
                          <Trash2 size={16} />
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
            title="No firewall rules configured"
            description="No rules match your filters or no rules exist in the system."
            actionText="Load Standard Rules"
            onAction={handleResetDemo}
          />
        )}
      </div>

      {/* Interactive Packet Testing Section */}
      <div className="sentinel-card">
        <div style={{ marginBottom: "1.25rem" }}>
          <h3 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--navy-dark)", marginBottom: "0.25rem" }}>
            Live Packet Processing & Inspection Engine
          </h3>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)" }}>
            Simulate an individual packet flow to visualize real-time evaluation against your active rules.
          </p>
        </div>

        {/* Predefined Test Scenarios Chips */}
        <div style={{ marginBottom: "1.25rem" }}>
          <div style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "0.5rem" }}>
            Quick Predefined Scenarios (Simulated):
          </div>
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
            {PRESET_TEST_SCENARIOS.map((sc, i) => (
              <button
                key={i}
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => applyPresetScenario(sc)}
                title={sc.desc}
              >
                <span>{sc.name}</span>
                <span style={{ fontSize: "0.6875rem", color: "var(--text-muted)" }}>
                  ({sc.protocol}:{sc.destination_port})
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Test Form */}
        <form onSubmit={handleSimulatePacket}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: "1rem",
              marginBottom: "1rem",
            }}
          >
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Source IP Address</label>
              <input
                type="text"
                className="form-input"
                value={testPacket.source_ip}
                onChange={(e) => setTestPacket({ ...testPacket, source_ip: e.target.value })}
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Destination IP Address</label>
              <input
                type="text"
                className="form-input"
                value={testPacket.destination_ip}
                onChange={(e) => setTestPacket({ ...testPacket, destination_ip: e.target.value })}
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Protocol</label>
              <select
                className="form-select"
                value={testPacket.protocol}
                onChange={(e) => setTestPacket({ ...testPacket, protocol: e.target.value })}
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
                value={testPacket.destination_port}
                onChange={(e) => setTestPacket({ ...testPacket, destination_port: parseInt(e.target.value) || 80 })}
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Packet Size (Bytes)</label>
              <input
                type="number"
                min="20"
                max="65535"
                className="form-input"
                value={testPacket.packet_size}
                onChange={(e) => setTestPacket({ ...testPacket, packet_size: parseInt(e.target.value) || 64 })}
              />
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button type="submit" className="btn btn-primary" disabled={simulating}>
              <Play size={16} />
              <span>{simulating ? "Evaluating Rules..." : "Simulate Packet"}</span>
            </button>
          </div>
        </form>

        {/* Visual Journey Output */}
        {simulationResult && <PacketJourneyVisualizer result={simulationResult} />}
      </div>

      {/* Add / Edit Rule Modal */}
      {isModalOpen && (
        <div className="modal-overlay" onClick={() => setIsModalOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
              <h3 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--navy-dark)" }}>
                {editingRule ? `Edit Firewall Rule #${editingRule.id}` : "Create New Firewall Rule"}
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

            <form onSubmit={handleSaveRule}>
              <div className="form-group">
                <label className="form-label">Rule Name *</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g., Allow Inbound HTTPS, Block Suspicious IP"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div className="form-group">
                  <label className="form-label">Source IP or CIDR Subnet</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="ANY, 192.168.1.100, 10.0.0.0/24"
                    value={formData.source_ip}
                    onChange={(e) => setFormData({ ...formData, source_ip: e.target.value })}
                  />
                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Leave "ANY" for all sources</span>
                </div>

                <div className="form-group">
                  <label className="form-label">Destination IP or CIDR Subnet</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="ANY, 10.0.0.50, 192.168.0.0/16"
                    value={formData.destination_ip}
                    onChange={(e) => setFormData({ ...formData, destination_ip: e.target.value })}
                  />
                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Leave "ANY" for all destinations</span>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "1rem" }}>
                <div className="form-group">
                  <label className="form-label">Protocol</label>
                  <select
                    className="form-select"
                    value={formData.protocol}
                    onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
                  >
                    <option value="ANY">ANY</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Destination Port</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="ANY, 80, 80-443"
                    value={formData.destination_port}
                    onChange={(e) => setFormData({ ...formData, destination_port: e.target.value })}
                  />
                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Single or range</span>
                </div>

                <div className="form-group">
                  <label className="form-label">Action *</label>
                  <select
                    className="form-select"
                    value={formData.action}
                    onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                  >
                    <option value="ALLOW">ALLOW</option>
                    <option value="BLOCK">BLOCK</option>
                  </select>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div className="form-group">
                  <label className="form-label">Priority (Evaluation Order) *</label>
                  <input
                    type="number"
                    min="1"
                    max="9999"
                    className="form-input"
                    value={formData.priority}
                    onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 100 })}
                    required
                  />
                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Lower number = higher priority</span>
                </div>

                <div className="form-group" style={{ justifyContent: "center" }}>
                  <label className="form-label">Status</label>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginTop: "0.25rem" }}>
                    <input
                      type="checkbox"
                      id="is_enabled"
                      checked={formData.is_enabled}
                      onChange={(e) => setFormData({ ...formData, is_enabled: e.target.checked })}
                      style={{ width: 18, height: 18 }}
                    />
                    <label htmlFor="is_enabled" style={{ fontSize: "0.875rem", cursor: "pointer" }}>
                      Enable this rule
                    </label>
                  </div>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Description (Optional)</label>
                <textarea
                  className="form-textarea"
                  rows={2}
                  placeholder="Security policy justification or note..."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "1.25rem" }}>
                <button type="button" className="btn btn-secondary" onClick={() => setIsModalOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  {editingRule ? "Save Changes" : "Create Rule"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      <ConfirmationModal
        isOpen={deleteModalOpen}
        title="Delete Firewall Rule?"
        message={`Are you sure you want to permanently delete rule '${ruleToDelete?.name}' (Priority #${ruleToDelete?.priority})? This cannot be undone.`}
        confirmText="Delete Rule"
        confirmVariant="danger"
        onConfirm={handleDeleteRule}
        onCancel={() => setDeleteModalOpen(false)}
      />

      {/* Reset Demo Rules Confirmation Modal */}
      <ConfirmationModal
        isOpen={resetDemoModalOpen}
        title="Reset Standard Demo Rules?"
        message="This will restore the standard baseline rules (Block Malicious IP, Block Telnet, Allow HTTP/HTTPS, Allow Internal Subnet, Allow DNS) and reset the fallback default policy to BLOCK."
        confirmText="Reset Rules"
        confirmVariant="primary"
        onConfirm={handleResetDemo}
        onCancel={() => setResetDemoModalOpen(false)}
      />
    </div>
  );
}
