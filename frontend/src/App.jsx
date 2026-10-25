import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import MainLayout from "./layouts/MainLayout";
import OverviewPage from "./pages/OverviewPage";
import FirewallPage from "./pages/FirewallPage";
import TrafficPage from "./pages/TrafficPage";
import IDSPage from "./pages/IDSPage";
import AnomalyPage from "./pages/AnomalyPage";
import BastionPage from "./pages/BastionPage";
import EncyclopediaPage from "./pages/EncyclopediaPage";
import ConceptsPage from "./pages/ConceptsPage";
import AboutPage from "./pages/AboutPage";

export default function App() {
  return (
    <Router>
      <MainLayout>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/firewall" element={<FirewallPage />} />
          <Route path="/traffic" element={<TrafficPage />} />
          <Route path="/ids" element={<IDSPage />} />
          <Route path="/anomaly" element={<AnomalyPage />} />
          <Route path="/bastion" element={<BastionPage />} />
          <Route path="/threats" element={<EncyclopediaPage />} />
          <Route path="/concepts" element={<ConceptsPage />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </MainLayout>
    </Router>
  );
}
