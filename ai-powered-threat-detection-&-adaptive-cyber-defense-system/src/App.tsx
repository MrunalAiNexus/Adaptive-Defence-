import React, { useState, useEffect } from 'react';
import { LabEntryPage } from './components/LabEntryPage';
import { Navbar } from './components/Navbar';
import { DashboardView } from './components/DashboardView';
import { AnalyzerView } from './components/AnalyzerView';
import { AlertsView } from './components/AlertsView';
import { ForensicsView } from './components/ForensicsView';
import { ResearchModelView } from './components/ResearchModelView';
import { AdaptiveDefenseView } from './components/AdaptiveDefenseView';
import { DissertationReaderView } from './components/DissertationReaderView';
import {
  User,
  UserRole,
  SOCDashboardMetrics,
  AnalyzedEvent,
  SecurityAlert,
  AlertStatus,
  NetworkTelemetry,
  ThreatClass,
  RiskLevel,
  RiskWeightConfig
} from './types';
import { analyzeNetworkFlow, analyzeBatchCsv } from './lib/mlEngine';
import { X, Shield, Terminal, Clock, Sparkles } from 'lucide-react';

export default function App() {
  const [inLab, setInLab] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [currentUser, setCurrentUser] = useState<User>({
    id: 'u-1',
    name: 'Mrunal Urankar',
    role: 'Administrator',
    email: 'mrunal.urankar@research.lab',
  });

  const [metrics, setMetrics] = useState<SOCDashboardMetrics>({
    totalEventsAnalyzed: 0,
    normalCount: 0,
    suspiciousCount: 0,
    maliciousCount: 0,
    criticalAlertsCount: 0,
    overallRiskIndex: 12,
    overallRiskLevel: 'Low',
    modelAccuracy: 0.9842,
    modelRecall: 0.987,
    timelineData: [],
    threatDistribution: [],
    riskDistribution: [],
  });

  const [events, setEvents] = useState<AnalyzedEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [totalEventsCount, setTotalEventsCount] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [activeModalEvent, setActiveModalEvent] = useState<AnalyzedEvent | null>(null);

  const [riskWeights, setRiskWeights] = useState<RiskWeightConfig>({
    mlProbabilityWeight: 0.45,
    threatSeverityWeight: 0.25,
    trafficAnomalyWeight: 0.15,
    behavioralAnomalyWeight: 0.15,
    benignMitigationCredit: 15,
  });

  // Fetch initial data from Express backend (with client-side fallback if server starting)
  const fetchDashboardData = async () => {
    try {
      const res = await fetch('/api/metrics');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch {
      // Backend starting or client-only
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch('/api/alerts');
      if (res.ok) {
        const data = await res.json();
        setAlerts(data);
      }
    } catch {
      // Backend starting
    }
  };

  const fetchEvents = async (page = 1, filters = {}) => {
    try {
      const params = new URLSearchParams({ page: page.toString(), limit: '15', ...filters });
      const res = await fetch(`/api/events?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events);
        setTotalEventsCount(data.total);
        setTotalPages(data.totalPages);
        setCurrentPage(data.page);
      }
    } catch {
      // Fallback
    }
  };

  useEffect(() => {
    fetchDashboardData();
    fetchAlerts();
    fetchEvents(1);
  }, []);

  // Handle single manual event analysis
  const handleAnalyzeEvent = async (telemetry: NetworkTelemetry): Promise<AnalyzedEvent> => {
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(telemetry),
      });
      if (res.ok) {
        const analyzed = await res.json();
        // Refresh dashboard state
        fetchDashboardData();
        fetchAlerts();
        fetchEvents(1);
        return analyzed;
      }
    } catch (e) {
      console.warn('Backend unavailable, using client ML engine fallback', e);
    }

    // Client-side fallback
    const analyzed = analyzeNetworkFlow(telemetry, riskWeights);
    setEvents((prev) => [analyzed, ...prev]);
    setTotalEventsCount((prev) => prev + 1);
    fetchDashboardData();
    return analyzed;
  };

  // Handle batch CSV analysis
  const handleBatchAnalyzeCsv = async (csvContent: string) => {
    try {
      const res = await fetch('/api/analyze/csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csvContent }),
      });
      if (res.ok) {
        const data = await res.json();
        fetchDashboardData();
        fetchAlerts();
        fetchEvents(1);
        return data;
      }
    } catch (e) {
      console.warn('Backend unavailable, using client batch CSV parser fallback', e);
    }

    // Client-side fallback
    const clientEvents = analyzeBatchCsv(csvContent, riskWeights);
    setEvents((prev) => [...clientEvents, ...prev]);
    setTotalEventsCount((prev) => prev + clientEvents.length);
    fetchDashboardData();
    return { totalProcessed: clientEvents.length, events: clientEvents };
  };

  // Handle alert status update
  const handleUpdateAlertStatus = async (id: string, status: AlertStatus, notes?: string) => {
    try {
      await fetch(`/api/alerts/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, notes, assignedTo: currentUser.name }),
      });
      fetchAlerts();
      fetchDashboardData();
    } catch (e) {
      console.warn('Backend unavailable, updating local alert state', e);
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, status, analystNotes: notes, updatedAt: new Date().toISOString() } : a))
      );
    }
  };

  // Handle Forensics filter change
  const handleForensicsFilter = (filters: {
    sourceIp?: string;
    threatType?: ThreatClass;
    severity?: RiskLevel;
    riskMin?: number;
    riskMax?: number;
  }) => {
    fetchEvents(1, filters);
  };

  // Inspect event by ID
  const handleInspectEventById = async (eventId: string) => {
    let found = events.find((e) => e.id === eventId);
    if (!found) {
      try {
        const res = await fetch(`/api/events/${eventId}`);
        if (res.ok) {
          found = await res.json();
        }
      } catch {
        // fallback
      }
    }
    if (found) {
      setActiveModalEvent(found);
    }
    setActiveTab('forensics');
  };

  // Update weights
  const handleUpdateWeights = async (newWeights: RiskWeightConfig) => {
    setRiskWeights(newWeights);
    try {
      await fetch('/api/weights', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newWeights),
      });
    } catch {
      // local state already updated
    }
  };

  const unresolvedCount = alerts.filter((a) => a.status === 'New' || a.status === 'Investigating').length;

  // 1. Lab Entry / Welcome Page
  if (!inLab) {
    return (
      <LabEntryPage
        onEnterLab={(initialTab?: string) => {
          if (initialTab) {
            setActiveTab(initialTab);
          }
          setInLab(true);
        }}
      />
    );
  }

  // 2. SOC Operational Dashboard & Telemetry Console
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500 selection:text-white transition-opacity duration-500 ease-in-out">
      {/* Navigation Bar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentUser={currentUser}
        onRoleChange={(role) => setCurrentUser({ ...currentUser, role })}
        unresolvedAlertCount={unresolvedCount}
        onReturnToLab={() => setInLab(false)}
      />

      {/* Main Content View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'dashboard' && (
          <DashboardView
            metrics={metrics}
            recentEvents={events}
            onSelectEvent={(event) => setActiveModalEvent(event)}
            onNavigateTab={(tab) => setActiveTab(tab)}
            currentUser={{ name: currentUser.name, role: currentUser.role }}
          />
        )}

        {activeTab === 'analyzer' && (
          <AnalyzerView
            onAnalyzeEvent={handleAnalyzeEvent}
            onBatchAnalyzeCsv={handleBatchAnalyzeCsv}
            onViewEventDetails={(event) => setActiveModalEvent(event)}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertsView
            alerts={alerts}
            onUpdateAlertStatus={handleUpdateAlertStatus}
            onInspectEvent={handleInspectEventById}
          />
        )}

        {activeTab === 'forensics' && (
          <ForensicsView
            events={events}
            totalEvents={totalEventsCount}
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={(page) => fetchEvents(page)}
            onFilterChange={handleForensicsFilter}
            onSelectEvent={(event) => setActiveModalEvent(event)}
          />
        )}

        {activeTab === 'research' && <ResearchModelView />}

        {activeTab === 'defenses' && (
          <AdaptiveDefenseView
            weights={riskWeights}
            onUpdateWeights={handleUpdateWeights}
          />
        )}

        {activeTab === 'dissertation' && <DissertationReaderView />}
      </main>

      {/* Modal Inspector for Event Telemetry & Attribution */}
      {activeModalEvent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Shield className="w-5 h-5 text-sky-400" />
                <span className="text-sm font-bold text-white">Event Forensic Inspector: {activeModalEvent.id}</span>
              </div>
              <button
                onClick={() => setActiveModalEvent(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
              <div>
                <span className="text-slate-500 block">SOURCE ADDRESS:</span>
                <span className="text-white font-bold">{activeModalEvent.telemetry.sourceIp}:{activeModalEvent.telemetry.sourcePort}</span>
              </div>
              <div>
                <span className="text-slate-500 block">DESTINATION TARGET:</span>
                <span className="text-white font-bold">{activeModalEvent.telemetry.destinationIp}:{activeModalEvent.telemetry.destinationPort}</span>
              </div>
              <div>
                <span className="text-slate-500 block">PREDICTED THREAT:</span>
                <span className="text-rose-400 font-bold">{activeModalEvent.prediction.predictedClass}</span>
              </div>
              <div>
                <span className="text-slate-500 block">RISK SCORE:</span>
                <span className="text-amber-400 font-bold">{activeModalEvent.riskScore}/100 ({activeModalEvent.riskLevel})</span>
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-bold block mb-1">Explainable AI Attribution:</span>
              <div className="space-y-1.5">
                {activeModalEvent.prediction.topFeatures.map((f) => (
                  <div key={f.featureName} className="bg-slate-950 p-2 rounded border border-slate-800 flex justify-between">
                    <div>
                      <span className="text-white font-bold">{f.displayName}</span>
                      <p className="text-[11px] text-slate-400 font-sans">{f.explanation}</p>
                    </div>
                    <span className={f.impact === 'positive' ? 'text-rose-400' : 'text-emerald-400'}>
                      {f.impact === 'positive' ? `+${(f.contribution * 100).toFixed(0)}%` : 'Mitigating'}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-bold block mb-1">Recommended Adaptive Countermeasure:</span>
              <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1 text-slate-300">
                <div className="font-bold text-amber-400">{activeModalEvent.adaptiveAction.summary}</div>
                <div className="text-[11px] font-sans text-slate-400">{activeModalEvent.adaptiveAction.description}</div>
                <div className="bg-black p-2 rounded text-[11px] text-emerald-400 overflow-x-auto mt-2">
                  <code>{activeModalEvent.adaptiveAction.technicalDetails.commandSimulated}</code>
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setActiveModalEvent(null)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded text-xs transition-colors cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/90 py-4 text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            AdaptiveDefense &bull; Created by Mrunal Urankar
          </div>
          <div className="flex items-center space-x-4 text-slate-400">
            <span>Model: RF-100 Ensemble</span>
            <span>&bull;</span>
            <span>Dataset: NSL-KDD</span>
            <span>&bull;</span>
            <button
              onClick={() => setActiveTab('dissertation')}
              className="hover:text-sky-400 underline cursor-pointer"
            >
              Research & Dissertation Notes
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
