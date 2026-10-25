import React, { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Shield,
  LayoutDashboard,
  ShieldAlert,
  Sliders,
  TrendingUp,
  Server,
  BookOpen,
  HelpCircle,
  Info,
  Menu,
  ChevronLeft,
  ChevronRight,
  Database,
  RefreshCw,
  AlertCircle,
  ExternalLink
} from "lucide-react";
import ConfirmationModal from "../components/ConfirmationModal";
import { api } from "../services/api";

const NAV_ITEMS = [
  { path: "/", label: "Overview", icon: LayoutDashboard },
  { path: "/firewall", label: "Firewall Manager", icon: Sliders },
  { path: "/traffic", label: "Traffic Simulator", icon: RefreshCw },
  { path: "/ids", label: "IDS Dashboard", icon: ShieldAlert },
  { path: "/anomaly", label: "Anomaly Detection", icon: TrendingUp },
  { path: "/bastion", label: "Bastion Host", icon: Server },
  { path: "/threats", label: "Threat Encyclopedia", icon: BookOpen },
  { path: "/concepts", label: "Protocol & Firewall Concepts", icon: HelpCircle },
  { path: "/about", label: "About Project", icon: Info },
];

export default function MainLayout({ children }) {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [resetModalOpen, setResetModalOpen] = useState(false);
  const [loadingAction, setLoadingAction] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (msg, type = "success") => {
    setToastMessage({ msg, type });
    setTimeout(() => setToastMessage(null), 4000);
  };

  const currentNav = NAV_ITEMS.find((item) => item.path === location.pathname) || {
    label: "Dashboard",
  };

  const handleLoadDemoConfig = async () => {
    try {
      setLoadingAction(true);
      const res = await api.loadSampleSimulation();
      showToast(res.message || "Demo data loaded successfully!");
      // Trigger a soft refresh event or reload window so all views pick up data
      window.dispatchEvent(new Event("sentinel-data-refresh"));
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleResetAllData = async () => {
    try {
      setLoadingAction(true);
      const res = await api.resetAllData();
      setResetModalOpen(false);
      showToast(res.message || "Data reset successfully!");
      window.dispatchEvent(new Event("sentinel-data-refresh"));
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoadingAction(false);
    }
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh", backgroundColor: "var(--bg-main)" }}>
      {/* Sidebar Desktop */}
      <aside
        style={{
          width: collapsed ? 76 : 260,
          transition: "width 0.2s ease",
          backgroundColor: "#ffffff",
          borderRight: "1px solid var(--border-color)",
          display: "flex",
          flexDirection: "column",
          position: "sticky",
          top: 0,
          height: "100vh",
          zIndex: 40,
        }}
      >
        {/* Brand Header */}
        <div
          style={{
            padding: "1.25rem 1rem",
            display: "flex",
            alignItems: "center",
            justifyContent: collapsed ? "center" : "space-between",
            borderBottom: "1px solid var(--border-color)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", overflow: "hidden" }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: "8px",
                backgroundColor: "var(--primary-blue)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#ffffff",
                flexShrink: 0,
              }}
            >
              <Shield size={22} />
            </div>
            {!collapsed && (
              <div>
                <div style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--navy-dark)", letterSpacing: "-0.02em" }}>
                  SENTINEL
                </div>
                <div style={{ fontSize: "0.6875rem", color: "var(--text-muted)", fontWeight: 500 }}>
                  IDS & Firewall Sim
                </div>
              </div>
            )}
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            style={{
              padding: "0.25rem",
              borderRadius: "4px",
              color: "var(--text-muted)",
              display: collapsed ? "none" : "flex",
            }}
            title="Toggle Sidebar"
          >
            <ChevronLeft size={18} />
          </button>
        </div>

        {/* Collapsed Expand Button */}
        {collapsed && (
          <div style={{ display: "flex", justifyContent: "center", padding: "0.5rem" }}>
            <button
              onClick={() => setCollapsed(false)}
              style={{ color: "var(--text-muted)", padding: "0.25rem" }}
              title="Expand Sidebar"
            >
              <ChevronRight size={18} />
            </button>
          </div>
        )}

        {/* Navigation Links */}
        <nav style={{ padding: "0.75rem 0.5rem", flex: 1, overflowY: "auto" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  title={collapsed ? item.label : undefined}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "0.75rem",
                    padding: "0.625rem 0.75rem",
                    borderRadius: "var(--radius-sm)",
                    color: isActive ? "var(--primary-blue)" : "var(--text-secondary)",
                    backgroundColor: isActive ? "var(--primary-light)" : "transparent",
                    fontWeight: isActive ? 600 : 500,
                    fontSize: "0.875rem",
                    transition: "all 0.15s ease",
                    justifyContent: collapsed ? "center" : "flex-start",
                  }}
                >
                  <Icon size={19} color={isActive ? "var(--primary-blue)" : "var(--text-muted)"} />
                  {!collapsed && <span style={{ whiteSpace: "nowrap" }}>{item.label}</span>}
                </Link>
              );
            })}
          </div>
        </nav>

        {/* Sidebar Footer */}
        {!collapsed && (
          <div style={{ padding: "1rem", borderTop: "1px solid var(--border-color)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "var(--success-green)" }}></span>
              <span style={{ fontWeight: 600, color: "var(--text-secondary)" }}>Simulator Engine Active</span>
            </div>
            <div>SQLite & NumPy Connected</div>
          </div>
        )}
      </aside>

      {/* Main Content Area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        {/* Top Header */}
        <header
          style={{
            height: 64,
            backgroundColor: "#ffffff",
            borderBottom: "1px solid var(--border-color)",
            padding: "0 1.5rem",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            position: "sticky",
            top: 0,
            zIndex: 30,
          }}
        >
          {/* Breadcrumb & Title */}
          <div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.1rem" }}>
              Sentinel / {currentNav.label}
            </div>
            <h2 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--navy-dark)" }}>
              {currentNav.label}
            </h2>
          </div>

          {/* Quick Header Actions */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={handleLoadDemoConfig}
              disabled={loadingAction}
              title="Loads realistic sample traffic & baseline"
            >
              <Database size={15} />
              <span>Load Demo Data</span>
            </button>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setResetModalOpen(true)}
              disabled={loadingAction}
              title="Reset all simulation events, alerts, and settings"
            >
              <RefreshCw size={15} />
              <span>Reset Data</span>
            </button>
          </div>
        </header>

        {/* Toast Notification */}
        {toastMessage && (
          <div
            style={{
              position: "fixed",
              top: 76,
              right: 24,
              zIndex: 1000,
              backgroundColor: toastMessage.type === "error" ? "var(--danger-bg)" : "var(--success-bg)",
              color: toastMessage.type === "error" ? "var(--danger-red)" : "var(--success-green)",
              border: `1px solid ${toastMessage.type === "error" ? "var(--danger-border)" : "var(--success-border)"}`,
              padding: "0.75rem 1.25rem",
              borderRadius: "var(--radius-sm)",
              fontSize: "0.875rem",
              fontWeight: 500,
              boxShadow: "var(--shadow-md)",
            }}
          >
            {toastMessage.msg}
          </div>
        )}

        {/* Page Content Body */}
        <main style={{ padding: "1.5rem", flex: 1, overflowY: "auto" }}>
          {/* Educational Simulation Disclaimer Banner */}
          <div className="disclaimer-banner">
            <AlertCircle size={18} style={{ flexShrink: 0 }} />
            <div>
              <strong>Educational Simulation Environment:</strong> Sentinel executes simulated packet flows and statistical anomaly detection in a sandboxed SQLite environment. No real external network traffic is captured, hosts scanned, or system firewalls modified.
            </div>
          </div>

          {children}
        </main>
      </div>

      {/* Confirmation Modal for Reset All Data */}
      <ConfirmationModal
        isOpen={resetModalOpen}
        title="Reset All Simulation Data?"
        message="This action will clear all accumulated traffic packets, IDS alerts, and restore the default demo firewall rules and bastion hosts. Existing simulation history will be removed."
        confirmText="Reset All Data"
        confirmVariant="danger"
        onConfirm={handleResetAllData}
        onCancel={() => setResetModalOpen(false)}
      />
    </div>
  );
}
