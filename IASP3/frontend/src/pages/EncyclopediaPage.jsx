import React, { useState, useEffect } from "react";
import {
  BookOpen,
  Search,
  Tag,
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Info,
  CheckCircle2,
  Lock,
  Layers,
} from "lucide-react";
import { api } from "../services/api";

const CATEGORIES = ["All", "Intruder", "Virus", "Worm", "Concept"];

export default function EncyclopediaPage() {
  const [threats, setThreats] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      const cat = selectedCategory === "All" ? null : selectedCategory;
      const data = await api.getThreats(cat, search);
      setThreats(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [selectedCategory, search]);

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
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
            Threat Encyclopedia & Malware Reference
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", maxWidth: 750 }}>
            Comprehensive educational catalog detailing intrusion threats, parasitic viruses, autonomous worms, and core defensive mechanisms.
          </p>
        </div>
      </div>

      {/* Filter Tabs and Search Bar */}
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
        {/* Category Tabs */}
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              className={`btn btn-sm ${selectedCategory === cat ? "btn-primary" : "btn-secondary"}`}
              onClick={() => setSelectedCategory(cat)}
            >
              {cat === "All" ? "All Entries" : `${cat}s`}
            </button>
          ))}
        </div>

        {/* Search */}
        <div style={{ position: "relative", minWidth: 260 }}>
          <Search size={16} style={{ position: "absolute", left: 10, top: 10, color: "var(--text-muted)" }} />
          <input
            type="text"
            className="form-input"
            style={{ paddingLeft: "2rem" }}
            placeholder="Search encyclopedia entries, tags..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Threats Grid */}
      <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        {threats.map((t) => {
          const isExpanded = expandedId === t.id;
          return (
            <div
              key={t.id}
              className="sentinel-card"
              style={{
                borderLeft: `4px solid ${
                  t.category === "Virus"
                    ? "var(--danger-red)"
                    : t.category === "Worm"
                    ? "var(--warning-amber)"
                    : t.category === "Intruder"
                    ? "var(--primary-blue)"
                    : "#6366f1"
                }`,
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  cursor: "pointer",
                }}
                onClick={() => toggleExpand(t.id)}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.35rem" }}>
                    <span
                      className={`badge ${
                        t.category === "Virus"
                          ? "badge-critical"
                          : t.category === "Worm"
                          ? "badge-warning"
                          : t.category === "Intruder"
                          ? "badge-low"
                          : "badge-info"
                      }`}
                    >
                      {t.category}
                    </span>
                    <h3 style={{ fontSize: "1.0625rem", fontWeight: 700, color: "var(--navy-dark)" }}>
                      {t.title}
                    </h3>
                  </div>
                  <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.45 }}>
                    {t.summary}
                  </p>
                </div>

                <button style={{ color: "var(--text-muted)", padding: "0.25rem", marginTop: "0.25rem" }}>
                  {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                </button>
              </div>

              {/* Tag Pills */}
              <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap", marginTop: "0.75rem" }}>
                {t.tags?.map((tag, idx) => (
                  <span
                    key={idx}
                    style={{
                      fontSize: "0.6875rem",
                      backgroundColor: "var(--bg-subtle)",
                      color: "var(--text-secondary)",
                      padding: "0.15rem 0.5rem",
                      borderRadius: "4px",
                    }}
                  >
                    #{tag}
                  </span>
                ))}
              </div>

              {/* Expandable Deep Dive Body */}
              {isExpanded && (
                <div
                  style={{
                    marginTop: "1.25rem",
                    paddingTop: "1.25rem",
                    borderTop: "1px solid var(--border-color)",
                    display: "flex",
                    flexDirection: "column",
                    gap: "1rem",
                    fontSize: "0.875rem",
                  }}
                >
                  <div>
                    <h4 style={{ fontWeight: 700, color: "var(--navy-dark)", marginBottom: "0.25rem" }}>
                      Definition & Core Mechanism
                    </h4>
                    <p style={{ color: "var(--text-secondary)", lineHeight: 1.5 }}>{t.definition}</p>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1rem" }}>
                    <div style={{ backgroundColor: "#f8fafc", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
                      <strong style={{ color: "var(--navy-dark)" }}>Propagation & Execution Behavior</strong>
                      <p style={{ color: "var(--text-secondary)", marginTop: "0.25rem", lineHeight: 1.45 }}>
                        {t.propagation_or_behavior}
                      </p>
                    </div>

                    <div style={{ backgroundColor: "#fef2f2", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid #fecaca" }}>
                      <strong style={{ color: "var(--danger-red)" }}>Potential Effects & Impact</strong>
                      <p style={{ color: "#7f1d1d", marginTop: "0.25rem", lineHeight: 1.45 }}>
                        {t.potential_effects}
                      </p>
                    </div>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "1rem" }}>
                    <div style={{ backgroundColor: "#f0fdf4", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid #bbf7d0" }}>
                      <strong style={{ color: "var(--success-green)" }}>Prevention Strategies</strong>
                      <p style={{ color: "#14532d", marginTop: "0.25rem", lineHeight: 1.45 }}>
                        {t.prevention}
                      </p>
                    </div>

                    <div style={{ backgroundColor: "#eff6ff", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid #bfdbfe" }}>
                      <strong style={{ color: "var(--primary-blue)" }}>Detection Measures</strong>
                      <p style={{ color: "#1e3a8a", marginTop: "0.25rem", lineHeight: 1.45 }}>
                        {t.detection}
                      </p>
                    </div>

                    <div style={{ backgroundColor: "#faf5ff", padding: "0.875rem", borderRadius: "var(--radius-sm)", border: "1px solid #e9d5ff" }}>
                      <strong style={{ color: "#7e22ce" }}>Recovery & Containment</strong>
                      <p style={{ color: "#581c87", marginTop: "0.25rem", lineHeight: 1.45 }}>
                        {t.recovery}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
