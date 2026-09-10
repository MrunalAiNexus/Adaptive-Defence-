import React, { useState } from 'react';
import {
  Bell,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Filter,
  Save,
  MessageSquare
} from 'lucide-react';
import { SecurityAlert, AlertStatus, RiskLevel } from '../types';

interface AlertsViewProps {
  alerts: SecurityAlert[];
  onUpdateAlertStatus: (id: string, status: AlertStatus, notes?: string) => Promise<void>;
  onInspectEvent: (eventId: string) => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  onUpdateAlertStatus,
  onInspectEvent,
}) => {
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(alerts[0] || null);
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [analystNotes, setAnalystNotes] = useState<string>('');
  const [isUpdating, setIsUpdating] = useState<boolean>(false);

  const filteredAlerts = alerts.filter((a) => {
    if (filterStatus !== 'ALL' && a.status !== filterStatus) return false;
    if (filterSeverity !== 'ALL' && a.severity !== filterSeverity) return false;
    return true;
  });

  const handleSelectAlert = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setAnalystNotes(alert.analystNotes || '');
  };

  const handleStatusChange = async (newStatus: AlertStatus) => {
    if (!selectedAlert) return;
    setIsUpdating(true);
    try {
      await onUpdateAlertStatus(selectedAlert.id, newStatus, analystNotes);
      setSelectedAlert({
        ...selectedAlert,
        status: newStatus,
        analystNotes,
        updatedAt: new Date().toISOString(),
      });
    } finally {
      setIsUpdating(false);
    }
  };

  const handleSaveNotes = async () => {
    if (!selectedAlert) return;
    setIsUpdating(true);
    try {
      await onUpdateAlertStatus(selectedAlert.id, selectedAlert.status, analystNotes);
      setSelectedAlert({
        ...selectedAlert,
        analystNotes,
        updatedAt: new Date().toISOString(),
      });
    } finally {
      setIsUpdating(false);
    }
  };

  const getSeverityBadge = (sev: RiskLevel) => {
    switch (sev) {
      case 'Critical':
        return 'bg-rose-950 text-rose-300 border-rose-600/60';
      case 'High':
        return 'bg-orange-950 text-orange-300 border-orange-600/60';
      case 'Moderate':
        return 'bg-amber-950 text-amber-300 border-amber-600/60';
      case 'Low':
      default:
        return 'bg-emerald-950 text-emerald-300 border-emerald-600/60';
    }
  };

  const getStatusBadge = (status: AlertStatus) => {
    switch (status) {
      case 'New':
        return 'bg-blue-950 text-blue-300 border-blue-600/60';
      case 'Investigating':
        return 'bg-amber-950 text-amber-300 border-amber-600/60';
      case 'Resolved':
        return 'bg-emerald-950 text-emerald-300 border-emerald-600/60';
      case 'False Positive':
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Filter Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold text-white font-mono flex items-center space-x-2">
            <Bell className="w-5 h-5 text-rose-400" />
            <span>SOC Security Incident & Alert Triage Center</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Prioritize verified threats, manage investigation lifecycles, and record forensic analyst notes.
          </p>
        </div>

        {/* Filter Toolbar */}
        <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
          <div className="flex items-center space-x-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Status:</span>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Statuses</option>
              <option value="New">New</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>

          <div className="flex items-center space-x-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
            <span className="text-slate-400">Severity:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Moderate">Moderate</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Split View: Alerts List on Left, Active Triage Card on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Alerts List Table (7 Cols) */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-4 overflow-hidden">
          <div className="flex items-center justify-between mb-3 text-xs font-mono">
            <span className="text-slate-400">
              Showing <strong className="text-white">{filteredAlerts.length}</strong> alerts
            </span>
          </div>

          <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
            <table className="w-full text-left text-xs font-mono text-slate-300">
              <thead className="bg-slate-950 text-[11px] text-slate-400 uppercase sticky top-0 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Alert ID</th>
                  <th className="py-2.5 px-3">Source &rarr; Dest</th>
                  <th className="py-2.5 px-3">Threat</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => handleSelectAlert(alert)}
                    className={`cursor-pointer transition-colors ${
                      selectedAlert?.id === alert.id ? 'bg-sky-950/40 border-l-2 border-sky-400' : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-2.5 px-3">
                      <span className="font-bold text-sky-400">{alert.id}</span>
                      <div className="text-[10px] text-slate-500">{new Date(alert.timestamp).toLocaleTimeString()}</div>
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="text-white">{alert.sourceIp}</div>
                      <div className="text-[10px] text-slate-500">&rarr; {alert.destinationIp}</div>
                    </td>
                    <td className="py-2.5 px-3 font-bold text-slate-200">
                      {alert.threatType}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] border ${getSeverityBadge(alert.severity)}`}>
                        {alert.riskScore}/100
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(alert.status)}`}>
                        {alert.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Selected Alert Triage Workspace (5 Cols) */}
        <div className="lg:col-span-5 font-mono">
          {selectedAlert ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-widest">Alert Details</span>
                  <h2 className="text-base font-bold text-white">{selectedAlert.id}</h2>
                </div>
                <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getSeverityBadge(selectedAlert.severity)}`}>
                  {selectedAlert.severity} ({selectedAlert.riskScore}/100)
                </span>
              </div>

              {/* Status Update Transition Buttons */}
              <div>
                <span className="text-xs text-slate-400 block mb-2">Update Incident Status:</span>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <button
                    disabled={isUpdating}
                    onClick={() => handleStatusChange('Investigating')}
                    className={`p-2 rounded border transition-colors flex items-center justify-center space-x-1.5 cursor-pointer ${
                      selectedAlert.status === 'Investigating'
                        ? 'bg-amber-950 text-amber-300 border-amber-600'
                        : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-amber-600'
                    }`}
                  >
                    <AlertCircle className="w-3.5 h-3.5" />
                    <span>Investigating</span>
                  </button>

                  <button
                    disabled={isUpdating}
                    onClick={() => handleStatusChange('Resolved')}
                    className={`p-2 rounded border transition-colors flex items-center justify-center space-x-1.5 cursor-pointer ${
                      selectedAlert.status === 'Resolved'
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-600'
                        : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-emerald-600'
                    }`}
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Resolved</span>
                  </button>

                  <button
                    disabled={isUpdating}
                    onClick={() => handleStatusChange('False Positive')}
                    className={`p-2 rounded border transition-colors flex items-center justify-center space-x-1.5 cursor-pointer ${
                      selectedAlert.status === 'False Positive'
                        ? 'bg-slate-800 text-slate-300 border-slate-600'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-600'
                    }`}
                  >
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>False Positive</span>
                  </button>

                  <button
                    disabled={isUpdating}
                    onClick={() => handleStatusChange('New')}
                    className={`p-2 rounded border transition-colors flex items-center justify-center space-x-1.5 cursor-pointer ${
                      selectedAlert.status === 'New'
                        ? 'bg-blue-950 text-blue-300 border-blue-600'
                        : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-blue-600'
                    }`}
                  >
                    <span>Reset to New</span>
                  </button>
                </div>
              </div>

              {/* Alert Provenance & Explanation */}
              <div className="bg-slate-950 border border-slate-800 p-3.5 rounded-lg space-y-2 text-xs">
                <div className="flex justify-between text-slate-400">
                  <span>Source Host:</span>
                  <span className="text-white font-bold">{selectedAlert.sourceIp}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Target Host:</span>
                  <span className="text-white font-bold">{selectedAlert.destinationIp}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Threat Classification:</span>
                  <span className="text-rose-400 font-bold">{selectedAlert.threatType}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Assigned Analyst:</span>
                  <span className="text-sky-300">{selectedAlert.assignedTo || 'Unassigned'}</span>
                </div>
              </div>

              {/* Rationale & Recommended Defense */}
              <div className="space-y-1.5 text-xs">
                <span className="text-slate-400 font-bold">Threat Rationale (Explainable AI):</span>
                <p className="bg-slate-950 p-2.5 rounded border border-slate-800 text-slate-300 font-sans text-[11px] leading-relaxed">
                  {selectedAlert.explanation}
                </p>
              </div>

              <div className="space-y-1.5 text-xs">
                <span className="text-amber-400 font-bold">Adaptive Recommended Action:</span>
                <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-slate-200">
                  {selectedAlert.recommendedAction}
                </div>
              </div>

              {/* Analyst Forensic Notes */}
              <div className="space-y-1.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 flex items-center space-x-1">
                    <MessageSquare className="w-3.5 h-3.5 text-sky-400" />
                    <span>Analyst Case Notes:</span>
                  </span>
                  <button
                    onClick={handleSaveNotes}
                    disabled={isUpdating}
                    className="text-sky-400 hover:text-sky-300 flex items-center space-x-1 cursor-pointer"
                  >
                    <Save className="w-3 h-3" />
                    <span>Save Notes</span>
                  </button>
                </div>
                <textarea
                  rows={3}
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                  placeholder="Record forensic notes, containment verification, or firewall log references..."
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => onInspectEvent(selectedAlert.eventId)}
                  className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono transition-colors cursor-pointer border border-slate-700 text-center"
                >
                  Trace Back to Raw Network Flow &rarr;
                </button>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-500">
              Select an alert from the table to review forensic details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
