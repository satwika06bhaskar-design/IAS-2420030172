const API_BASE = "/api";

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const config = {
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
    ...options,
  };

  try {
    const response = await fetch(url, config);
    if (!response.ok) {
      let errorMessage = `Request failed with status ${response.status}`;
      try {
        const errorData = await response.json();
        if (errorData.detail) {
          if (Array.isArray(errorData.detail)) {
            errorMessage = errorData.detail.map((d) => d.msg || JSON.stringify(d)).join(", ");
          } else {
            errorMessage = errorData.detail;
          }
        }
      } catch (_) {}
      throw new Error(errorMessage);
    }
    return await response.json();
  } catch (error) {
    console.error(`API Error on ${endpoint}:`, error);
    throw error;
  }
}

export const api = {
  // Firewall API
  getFirewallRules: (params = {}) => {
    const q = new URLSearchParams();
    if (params.action) q.append("action", params.action);
    if (params.protocol) q.append("protocol", params.protocol);
    if (params.is_enabled !== undefined && params.is_enabled !== "") q.append("is_enabled", params.is_enabled);
    if (params.search) q.append("search", params.search);
    return request(`/firewall/rules?${q.toString()}`);
  },
  createFirewallRule: (data) => request("/firewall/rules", { method: "POST", body: JSON.stringify(data) }),
  updateFirewallRule: (id, data) => request(`/firewall/rules/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  deleteFirewallRule: (id) => request(`/firewall/rules/${id}`, { method: "DELETE" }),
  toggleFirewallRule: (id) => request(`/firewall/rules/${id}/toggle`, { method: "PATCH" }),
  getDefaultPolicy: () => request("/firewall/default-policy"),
  setDefaultPolicy: (policy) => request("/firewall/default-policy", { method: "POST", body: JSON.stringify({ policy }) }),
  simulatePacket: (packetData) => request("/firewall/simulate-packet", { method: "POST", body: JSON.stringify(packetData) }),
  resetFirewallDemoRules: () => request("/firewall/reset-demo", { method: "POST" }),

  // Bastion Host API
  getBastionHosts: () => request("/bastion/hosts"),
  createBastionHost: (data) => request("/bastion/hosts", { method: "POST", body: JSON.stringify(data) }),
  updateBastionHost: (id, data) => request(`/bastion/hosts/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  deleteBastionHost: (id) => request(`/bastion/hosts/${id}`, { method: "DELETE" }),
  toggleBastionHost: (id) => request(`/bastion/hosts/${id}/toggle`, { method: "PATCH" }),
  testBastionConnection: (data) => request("/bastion/test-connection", { method: "POST", body: JSON.stringify(data) }),

  // Traffic API
  triggerScenario: (scenario_type, count = 1, source_ip = null) =>
    request("/traffic/scenario", { method: "POST", body: JSON.stringify({ scenario_type, count, source_ip }) }),
  triggerCustomTraffic: (data) => request("/traffic/custom", { method: "POST", body: JSON.stringify(data) }),
  getTrafficEvents: (params = {}) => {
    const q = new URLSearchParams();
    if (params.limit) q.append("limit", params.limit);
    if (params.offset !== undefined) q.append("offset", params.offset);
    if (params.decision) q.append("decision", params.decision);
    if (params.protocol) q.append("protocol", params.protocol);
    if (params.source_ip) q.append("source_ip", params.source_ip);
    if (params.has_alert !== undefined) q.append("has_alert", params.has_alert);
    return request(`/traffic/events?${q.toString()}`);
  },
  getTrafficStats: () => request("/traffic/stats"),
  clearTrafficHistory: () => request("/traffic/clear-history", { method: "POST" }),
  resetSimulation: () => request("/traffic/reset", { method: "POST" }),

  // IDS API
  getIDSAlerts: (params = {}) => {
    const q = new URLSearchParams();
    if (params.severity) q.append("severity", params.severity);
    if (params.detection_method) q.append("detection_method", params.detection_method);
    if (params.is_acknowledged !== undefined && params.is_acknowledged !== "") q.append("is_acknowledged", params.is_acknowledged);
    if (params.search) q.append("search", params.search);
    if (params.limit) q.append("limit", params.limit);
    if (params.offset !== undefined) q.append("offset", params.offset);
    return request(`/ids/alerts?${q.toString()}`);
  },
  getIDSAlertDetail: (id) => request(`/ids/alerts/${id}`),
  acknowledgeAlerts: (alert_ids) => request("/ids/alerts/acknowledge", { method: "POST", body: JSON.stringify({ alert_ids }) }),
  acknowledgeSingleAlert: (id) => request(`/ids/alerts/${id}/acknowledge`, { method: "POST" }),
  clearAllAlerts: () => request("/ids/alerts/clear", { method: "DELETE" }),
  getIDSThresholds: () => request("/ids/config"),
  updateIDSThresholds: (config) => request("/ids/config", { method: "PUT", body: JSON.stringify(config) }),

  // Anomaly API
  getAnomalyStats: (metric) => {
    const q = metric ? `?metric=${metric}` : "";
    return request(`/anomaly/stats${q}`);
  },
  getAnomalyConfig: () => request("/anomaly/config"),
  updateAnomalyConfig: (settings) => request("/anomaly/config", { method: "PUT", body: JSON.stringify(settings) }),
  getAnomalyAlerts: (limit = 20) => request(`/anomaly/events?limit=${limit}`),

  // Educational API
  getThreats: (category, search) => {
    const q = new URLSearchParams();
    if (category) q.append("category", category);
    if (search) q.append("search", search);
    return request(`/educational/threats?${q.toString()}`);
  },
  getFirewallConcepts: () => request("/educational/firewall-concepts"),

  // Demo & Reset API
  loadDemoConfig: () => request("/demo/load-demo-config", { method: "POST" }),
  loadSampleSimulation: () => request("/demo/load-sample-simulation", { method: "POST" }),
  resetAllData: () => request("/demo/reset-all", { method: "POST" }),
};
