import React, { useState } from 'react';
import {
  FileSearch,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Database,
  Shield,
  Clock,
  Code
} from 'lucide-react';
import { AnalyzedEvent, ThreatClass, RiskLevel } from '../types';

interface ForensicsViewProps {
  events: AnalyzedEvent[];
  totalEvents: number;
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  onFilterChange: (filters: {
    sourceIp?: string;
    threatType?: ThreatClass;
    severity?: RiskLevel;
    riskMin?: number;
    riskMax?: number;
  }) => void;
  onSelectEvent: (event: AnalyzedEvent) => void;
}

export const ForensicsView: React.FC<ForensicsViewProps> = ({
  events,
  totalEvents,
  currentPage,
  totalPages,
  onPageChange,
  onFilterChange,
  onSelectEvent,
}) => {
  const [sourceIp, setSourceIp] = useState('');
  const [threatType, setThreatType] = useState<string>('ALL');
  const [severity, setSeverity] = useState<string>('ALL');
  const [riskMin, setRiskMin] = useState<number>(0);
  const [riskMax, setRiskMax] = useState<number>(100);
  const [selectedInspectEvent, setSelectedInspectEvent] = useState<AnalyzedEvent | null>(events[0] || null);

  const handleApplyFilter = () => {
    onFilterChange({
      sourceIp: sourceIp.trim() || undefined,
      threatType: threatType !== 'ALL' ? (threatType as ThreatClass) : undefined,
      severity: severity !== 'ALL' ? (severity as RiskLevel) : undefined,
      riskMin: riskMin > 0 ? riskMin : undefined,
      riskMax: riskMax < 100 ? riskMax : undefined,
    });
  };

  const handleResetFilter = () => {
    setSourceIp('');
    setThreatType('ALL');
    setSeverity('ALL');
    setRiskMin(0);
    setRiskMax(100);
    onFilterChange({});
  };

  const getRiskBadgeColor = (level: string) => {
    switch (level) {
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

  return (
    <div className="space-y-6">
      {/* Header & Filter Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 font-mono text-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h1 className="text-lg font-bold text-white flex items-center space-x-2">
              <FileSearch className="w-5 h-5 text-sky-400" />
              <span>Historical Network Flow Forensics & Database</span>
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Trace every prediction back to its raw network telemetry, protocol flags, and model attribution weights.
            </p>
          </div>
          <span className="text-slate-400">
            Total Records: <strong className="text-sky-400 font-bold">{totalEvents}</strong>
          </span>
        </div>

        {/* Filter Toolbar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3 pt-2 border-t border-slate-800">
          <div>
            <label className="text-slate-400 block mb-1">Source IP Address</label>
            <div className="relative">
              <input
                type="text"
                placeholder="e.g. 198.51.100"
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white pr-7 focus:outline-none focus:border-sky-500"
              />
              <Search className="w-3.5 h-3.5 text-slate-500 absolute right-2.5 top-2.5" />
            </div>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Threat Class</label>
            <select
              value={threatType}
              onChange={(e) => setThreatType(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-white focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Threat Classes</option>
              <option value="BENIGN">BENIGN</option>
              <option value="DOS">DOS</option>
              <option value="PROBE">PROBE</option>
              <option value="BRUTE_FORCE">BRUTE_FORCE</option>
              <option value="BOT">BOT</option>
              <option value="WEB_ATTACK">WEB_ATTACK</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Severity Tier</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-white focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Severities</option>
              <option value="Low">Low (0 - 30)</option>
              <option value="Moderate">Moderate (31 - 60)</option>
              <option value="High">High (61 - 80)</option>
              <option value="Critical">Critical (81 - 100)</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Risk Score Range: {riskMin} - {riskMax}</label>
            <div className="flex items-center space-x-2">
              <input
                type="range"
                min="0"
                max="100"
                value={riskMin}
                onChange={(e) => setRiskMin(parseInt(e.target.value, 10))}
                className="w-1/2 accent-sky-500"
              />
              <input
                type="range"
                min="0"
                max="100"
                value={riskMax}
                onChange={(e) => setRiskMax(parseInt(e.target.value, 10))}
                className="w-1/2 accent-sky-500"
              />
            </div>
          </div>

          <div className="flex items-end space-x-2">
            <button
              onClick={handleApplyFilter}
              className="flex-1 bg-sky-600 hover:bg-sky-500 text-white py-1.5 rounded font-medium transition-colors cursor-pointer"
            >
              Apply Filter
            </button>
            <button
              onClick={handleResetFilter}
              className="px-3 bg-slate-800 hover:bg-slate-700 text-slate-300 py-1.5 rounded transition-colors cursor-pointer"
            >
              Reset
            </button>
          </div>
        </div>
      </div>

      {/* Main Forensics Table & Deep-Dive Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 font-mono text-xs">
        {/* Table (7 Cols) */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-4 overflow-hidden">
          <div className="overflow-x-auto max-h-[560px] overflow-y-auto">
            <table className="w-full text-left text-slate-300">
              <thead className="bg-slate-950 text-[11px] text-slate-400 uppercase sticky top-0 border-b border-slate-800">
                <tr>
                  <th className="py-2 px-3">Flow ID</th>
                  <th className="py-2 px-3">Source &rarr; Dest</th>
                  <th className="py-2 px-3">Flag / Proto</th>
                  <th className="py-2 px-3">Threat</th>
                  <th className="py-2 px-3">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {events.map((event) => (
                  <tr
                    key={event.id}
                    onClick={() => {
                      setSelectedInspectEvent(event);
                      onSelectEvent(event);
                    }}
                    className={`cursor-pointer transition-colors ${
                      selectedInspectEvent?.id === event.id ? 'bg-sky-950/40 border-l-2 border-sky-400' : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-2 px-3">
                      <span className="font-bold text-sky-400">{event.id}</span>
                      <div className="text-[10px] text-slate-500">{new Date(event.timestamp).toLocaleTimeString()}</div>
                    </td>
                    <td className="py-2 px-3">
                      <div className="text-white">{event.telemetry.sourceIp}</div>
                      <div className="text-[10px] text-slate-400">&rarr; {event.telemetry.destinationIp}:{event.telemetry.destinationPort}</div>
                    </td>
                    <td className="py-2 px-3">
                      <span className="text-slate-300">{event.telemetry.protocol}</span>
                      <span className="text-slate-500 ml-1">({event.telemetry.connectionState})</span>
                    </td>
                    <td className="py-2 px-3 font-bold text-slate-200">
                      {event.prediction.predictedClass}
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] border ${getRiskBadgeColor(event.riskLevel)}`}>
                        {event.riskScore}/100
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between pt-3 mt-3 border-t border-slate-800 text-xs text-slate-400">
            <span>Page {currentPage} of {totalPages}</span>
            <div className="flex items-center space-x-2">
              <button
                disabled={currentPage <= 1}
                onClick={() => onPageChange(currentPage - 1)}
                className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded hover:bg-slate-800 disabled:opacity-40 cursor-pointer"
              >
                <ChevronLeft className="w-3.5 h-3.5 inline" /> Prev
              </button>
              <button
                disabled={currentPage >= totalPages}
                onClick={() => onPageChange(currentPage + 1)}
                className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded hover:bg-slate-800 disabled:opacity-40 cursor-pointer"
              >
                Next <ChevronRight className="w-3.5 h-3.5 inline" />
              </button>
            </div>
          </div>
        </div>

        {/* Deep-Dive Inspection Drawer (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          {selectedInspectEvent ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-widest">Forensic Packet Trace</span>
                  <div className="text-sm font-bold text-white">{selectedInspectEvent.id}</div>
                </div>
                <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getRiskBadgeColor(selectedInspectEvent.riskLevel)}`}>
                  {selectedInspectEvent.riskScore}/100 ({selectedInspectEvent.riskLevel})
                </span>
              </div>

              {/* Raw Network Flow Features Table */}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2">
                <span className="text-[11px] text-sky-400 font-bold block">Raw Ingested Network Features:</span>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                  <div>Source IP: <span className="text-white font-bold">{selectedInspectEvent.telemetry.sourceIp}</span></div>
                  <div>Dest IP: <span className="text-white font-bold">{selectedInspectEvent.telemetry.destinationIp}</span></div>
                  <div>Protocol: <span className="text-white font-bold">{selectedInspectEvent.telemetry.protocol}</span></div>
                  <div>State Flag: <span className="text-white font-bold">{selectedInspectEvent.telemetry.connectionState}</span></div>
                  <div>Packets: <span className="text-white font-bold">{selectedInspectEvent.telemetry.packetCount}</span></div>
                  <div>Req Freq: <span className="text-white font-bold">{selectedInspectEvent.telemetry.requestFrequency}/s</span></div>
                  <div>Src Bytes: <span className="text-white font-bold">{selectedInspectEvent.telemetry.srcBytes} B</span></div>
                  <div>Dst Bytes: <span className="text-white font-bold">{selectedInspectEvent.telemetry.dstBytes} B</span></div>
                  <div>Duration: <span className="text-white font-bold">{selectedInspectEvent.telemetry.duration}s</span></div>
                  <div>Failed Logins: <span className="text-rose-400 font-bold">{selectedInspectEvent.telemetry.failedLoginAttempts}</span></div>
                  <div>Host Count: <span className="text-white font-bold">{selectedInspectEvent.telemetry.dstHostCount}</span></div>
                  <div>Service: <span className="text-white font-bold">{selectedInspectEvent.telemetry.service}</span></div>
                </div>
              </div>

              {/* Model Decision Provenance */}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1.5">
                <span className="text-[11px] text-emerald-400 font-bold block">ML Inference Engine Provenance:</span>
                <div className="text-[11px] text-slate-400 flex justify-between">
                  <span>Ensemble Classifier:</span>
                  <span className="text-white">{selectedInspectEvent.prediction.modelUsed}</span>
                </div>
                <div className="text-[11px] text-slate-400 flex justify-between">
                  <span>Confidence:</span>
                  <span className="text-white">{(selectedInspectEvent.prediction.confidence * 100).toFixed(1)}%</span>
                </div>
                <div className="text-[11px] text-slate-400 flex justify-between">
                  <span>Inference Latency:</span>
                  <span className="text-emerald-400">{selectedInspectEvent.prediction.inferenceLatencyMs} ms</span>
                </div>
              </div>

              {/* Multi-Factor Mathematical Breakdown */}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1.5">
                <span className="text-[11px] text-amber-400 font-bold block">Risk Scoring Formula Breakdown:</span>
                <p className="text-[10px] text-slate-300 font-sans leading-relaxed">
                  {selectedInspectEvent.riskBreakdown.formulaDescription}
                </p>
              </div>

              {/* JSON Raw Output */}
              <div>
                <span className="text-[11px] text-slate-400 block mb-1">Raw JSON Telemetry:</span>
                <pre className="bg-black border border-slate-800 p-2.5 rounded text-[10px] text-slate-300 overflow-x-auto max-h-36">
                  {JSON.stringify(selectedInspectEvent, null, 2)}
                </pre>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-500">
              Select an event to view forensic telemetry details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
