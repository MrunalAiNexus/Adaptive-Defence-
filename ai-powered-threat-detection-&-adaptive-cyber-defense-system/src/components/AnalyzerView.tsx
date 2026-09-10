import React, { useState } from 'react';
import {
  ShieldAlert,
  UploadCloud,
  FileText,
  Play,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Info,
  Download,
  Terminal
} from 'lucide-react';
import { NetworkTelemetry, AnalyzedEvent, ThreatClass } from '../types';
import { SAMPLE_ATTACK_SCENARIOS, SAMPLE_CSV_CONTENT } from '../lib/sampleDatasets';

interface AnalyzerViewProps {
  onAnalyzeEvent: (telemetry: NetworkTelemetry) => Promise<AnalyzedEvent>;
  onBatchAnalyzeCsv: (csvContent: string) => Promise<{ totalProcessed: number; events: AnalyzedEvent[] }>;
  onViewEventDetails: (event: AnalyzedEvent) => void;
}

export const AnalyzerView: React.FC<AnalyzerViewProps> = ({
  onAnalyzeEvent,
  onBatchAnalyzeCsv,
  onViewEventDetails,
}) => {
  const [activeTab, setActiveTab] = useState<'manual' | 'csv'>('manual');

  // Manual Form State
  const [formData, setFormData] = useState<NetworkTelemetry>({
    timestamp: new Date().toISOString(),
    sourceIp: '198.51.100.44',
    destinationIp: '10.0.2.15',
    sourcePort: 49152,
    destinationPort: 80,
    protocol: 'TCP',
    duration: 0.2,
    srcBytes: 120,
    dstBytes: 0,
    packetCount: 540,
    failedLoginAttempts: 0,
    requestFrequency: 450,
    connectionState: 'S0',
    service: 'http',
    sameSrvRate: 1.0,
    diffSrvRate: 0.0,
    dstHostCount: 255,
    dstHostSrvCount: 255,
  });

  // CSV State
  const [csvInput, setCsvInput] = useState<string>('');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [analyzedResult, setAnalyzedResult] = useState<AnalyzedEvent | null>(null);
  const [batchResults, setBatchResults] = useState<AnalyzedEvent[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Pre-load attack scenario
  const handleLoadScenario = (index: number) => {
    const scenario = SAMPLE_ATTACK_SCENARIOS[index];
    setFormData({
      ...scenario.telemetry,
      timestamp: new Date().toISOString(),
    });
    setAnalyzedResult(null);
    setErrorMsg(null);
  };

  // Submit Manual Telemetry
  const handleManualSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsProcessing(true);
    setErrorMsg(null);
    try {
      const result = await onAnalyzeEvent(formData);
      setAnalyzedResult(result);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to analyze telemetry');
    } finally {
      setIsProcessing(false);
    }
  };

  // Submit CSV Batch
  const handleCsvSubmit = async () => {
    if (!csvInput.trim()) {
      setErrorMsg('Please paste or upload CSV telemetry data.');
      return;
    }
    setIsProcessing(true);
    setErrorMsg(null);
    try {
      const res = await onBatchAnalyzeCsv(csvInput);
      setBatchResults(res.events);
      if (res.events.length > 0) {
        setAnalyzedResult(res.events[0]);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to process CSV');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      setCsvInput(event.target?.result as string);
    };
    reader.readAsText(file);
  };

  const handleLoadSampleCsv = () => {
    setCsvInput(SAMPLE_CSV_CONTENT);
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

  const handleDownloadSampleCsv = () => {
    const blob = new Blob([SAMPLE_CSV_CONTENT], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'nsl_kdd_telemetry_template.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold text-white font-mono flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-sky-400" />
            <span>Security Event Telemetry Analyzer</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingest real network flow features for multi-class ML classification, continuous 0–100 risk scoring, and adaptive defense.
          </p>
        </div>

        {/* Input Mode Selector */}
        <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800 self-start md:self-auto font-mono text-xs">
          <button
            onClick={() => setActiveTab('manual')}
            className={`px-3.5 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
              activeTab === 'manual'
                ? 'bg-sky-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Option 1: Manual Telemetry Entry
          </button>
          <button
            onClick={() => setActiveTab('csv')}
            className={`px-3.5 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
              activeTab === 'csv'
                ? 'bg-sky-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Option 2: Batch CSV Ingestion
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="bg-rose-950/80 border border-rose-700 text-rose-200 text-xs px-4 py-3 rounded-lg flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Main Analyzer Grid: Inputs on Left, Real-Time Inference Results on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Form or CSV Upload (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          {activeTab === 'manual' ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              {/* Quick Attack Scenario Fillers */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono uppercase text-slate-400">
                    Quick Attack Templates (NSL-KDD Benchmarks):
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {SAMPLE_ATTACK_SCENARIOS.map((s, idx) => (
                    <button
                      key={s.name}
                      type="button"
                      onClick={() => handleLoadScenario(idx)}
                      className="px-2.5 py-1 text-[11px] font-mono rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-700 hover:border-sky-500 transition-colors cursor-pointer"
                    >
                      {s.name.split(' (')[0]}
                    </button>
                  ))}
                </div>
              </div>

              {/* Manual Input Form */}
              <form onSubmit={handleManualSubmit} className="space-y-4 text-xs font-mono">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div>
                    <label className="text-slate-400 block mb-1">Source IP</label>
                    <input
                      type="text"
                      value={formData.sourceIp}
                      onChange={(e) => setFormData({ ...formData, sourceIp: e.target.value })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                      required
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Destination IP</label>
                    <input
                      type="text"
                      value={formData.destinationIp}
                      onChange={(e) => setFormData({ ...formData, destinationIp: e.target.value })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                      required
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Source Port</label>
                    <input
                      type="number"
                      value={formData.sourcePort}
                      onChange={(e) => setFormData({ ...formData, sourcePort: parseInt(e.target.value, 10) || 0 })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                      required
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Dest Port</label>
                    <input
                      type="number"
                      value={formData.destinationPort}
                      onChange={(e) => setFormData({ ...formData, destinationPort: parseInt(e.target.value, 10) || 0 })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                      required
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div>
                    <label className="text-slate-400 block mb-1">Protocol</label>
                    <select
                      value={formData.protocol}
                      onChange={(e) => setFormData({ ...formData, protocol: e.target.value as any })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    >
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="ICMP">ICMP</option>
                      <option value="HTTP">HTTP</option>
                      <option value="SSH">SSH</option>
                      <option value="DNS">DNS</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">TCP Flag / State</label>
                    <select
                      value={formData.connectionState}
                      onChange={(e) => setFormData({ ...formData, connectionState: e.target.value as any })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    >
                      <option value="SF">SF (Normal Established)</option>
                      <option value="S0">S0 (SYN without ACK)</option>
                      <option value="REJ">REJ (Connection Rejected)</option>
                      <option value="RSTO">RSTO (Reset by Originator)</option>
                      <option value="SH">SH (SYN with FIN)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Service Type</label>
                    <select
                      value={formData.service}
                      onChange={(e) => setFormData({ ...formData, service: e.target.value as any })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    >
                      <option value="http">http (80/443)</option>
                      <option value="ssh">ssh (22)</option>
                      <option value="ftp">ftp (21)</option>
                      <option value="smtp">smtp (25)</option>
                      <option value="dns">dns (53)</option>
                      <option value="other">other/private</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Duration (sec)</label>
                    <input
                      type="number"
                      step="0.1"
                      value={formData.duration}
                      onChange={(e) => setFormData({ ...formData, duration: parseFloat(e.target.value) || 0 })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div>
                    <label className="text-slate-400 block mb-1">Packet Count</label>
                    <input
                      type="number"
                      value={formData.packetCount}
                      onChange={(e) => setFormData({ ...formData, packetCount: parseInt(e.target.value, 10) || 0 })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Request Freq (req/s)</label>
                    <input
                      type="number"
                      value={formData.requestFrequency}
                      onChange={(e) => setFormData({ ...formData, requestFrequency: parseFloat(e.target.value) || 0 })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Source Payload (Bytes)</label>
                    <input
                      type="number"
                      value={formData.srcBytes}
                      onChange={(e) => setFormData({ ...formData, srcBytes: parseInt(e.target.value, 10) || 0 })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Dest Payload (Bytes)</label>
                    <input
                      type="number"
                      value={formData.dstBytes}
                      onChange={(e) => setFormData({ ...formData, dstBytes: parseInt(e.target.value, 10) || 0 })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
                    <label className="text-rose-400 font-bold block mb-1">Failed Login Attempts</label>
                    <input
                      type="number"
                      min="0"
                      max="50"
                      value={formData.failedLoginAttempts}
                      onChange={(e) => setFormData({ ...formData, failedLoginAttempts: parseInt(e.target.value, 10) || 0 })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-rose-500"
                    />
                    <span className="text-[10px] text-slate-500 block mt-1">Triggers Brute Force & MFA rules</span>
                  </div>

                  <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
                    <label className="text-amber-400 font-bold block mb-1">Dst Host Fan-Out Count</label>
                    <input
                      type="number"
                      min="0"
                      max="255"
                      value={formData.dstHostCount}
                      onChange={(e) => setFormData({ ...formData, dstHostCount: parseInt(e.target.value, 10) || 0 })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-amber-500"
                    />
                    <span className="text-[10px] text-slate-500 block mt-1">High count indicates port scans</span>
                  </div>

                  <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
                    <label className="text-sky-400 font-bold block mb-1">Same Service Rate</label>
                    <input
                      type="number"
                      step="0.05"
                      min="0"
                      max="1"
                      value={formData.sameSrvRate}
                      onChange={(e) => setFormData({ ...formData, sameSrvRate: parseFloat(e.target.value) || 0 })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-sky-500"
                    />
                    <span className="text-[10px] text-slate-500 block mt-1">Homogeneity of target ports</span>
                  </div>
                </div>

                <div className="pt-2 flex items-center justify-between">
                  <span className="text-slate-400 text-xs">
                    Model: <strong className="text-sky-400">Random Forest (100 Trees) + Multi-Factor Scorer</strong>
                  </span>
                  <button
                    type="submit"
                    disabled={isProcessing}
                    className="bg-sky-600 hover:bg-sky-500 text-white px-5 py-2 rounded-lg font-medium flex items-center space-x-2 transition-colors disabled:opacity-50 cursor-pointer shadow-md shadow-sky-900/30"
                  >
                    <Play className="w-4 h-4 fill-white" />
                    <span>{isProcessing ? 'Evaluating ML Pipeline...' : 'Run ML Threat Detection'}</span>
                  </button>
                </div>
              </form>
            </div>
          ) : (
            /* Option 2: CSV Upload View */
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 font-mono text-xs">
              <div className="border-2 border-dashed border-slate-700 rounded-xl p-6 text-center hover:border-sky-500 transition-colors bg-slate-950/50">
                <UploadCloud className="w-8 h-8 text-sky-400 mx-auto mb-2" />
                <h3 className="text-sm font-bold text-white mb-1">Upload Network Telemetry CSV File</h3>
                <p className="text-slate-400 text-xs mb-3">
                  Accepts NSL-KDD and CIC-IDS compliant flow records (headers: sourceIp, destinationIp, protocol, bytes, packets, etc.)
                </p>

                <div className="flex items-center justify-center space-x-3">
                  <label className="bg-sky-600 hover:bg-sky-500 text-white px-4 py-1.5 rounded cursor-pointer transition-colors">
                    Browse File
                    <input type="file" accept=".csv,.txt" onChange={handleFileUpload} className="hidden" />
                  </label>
                  <button
                    type="button"
                    onClick={handleLoadSampleCsv}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-600 px-3.5 py-1.5 rounded transition-colors cursor-pointer"
                  >
                    Load Ready-Made Sample CSV
                  </button>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1 text-slate-400">
                  <span>CSV Telemetry Data Preview:</span>
                  <button
                    type="button"
                    onClick={handleDownloadSampleCsv}
                    className="text-sky-400 hover:text-sky-300 flex items-center space-x-1 cursor-pointer bg-transparent border-0 p-0 text-xs"
                  >
                    <Download className="w-3 h-3" />
                    <span>Download Template (.csv)</span>
                  </button>
                </div>
                <textarea
                  rows={8}
                  value={csvInput}
                  onChange={(e) => setCsvInput(e.target.value)}
                  placeholder="sourceIp,destinationIp,sourcePort,destinationPort,protocol,duration,srcBytes,dstBytes,packetCount,failedLoginAttempts,requestFrequency,connectionState,service..."
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={handleCsvSubmit}
                  disabled={isProcessing || !csvInput.trim()}
                  className="bg-sky-600 hover:bg-sky-500 text-white px-5 py-2 rounded-lg font-medium flex items-center space-x-2 transition-colors disabled:opacity-50 cursor-pointer shadow-md shadow-sky-900/30"
                >
                  <Play className="w-4 h-4 fill-white" />
                  <span>{isProcessing ? 'Processing Batch...' : 'Analyze Batch CSV Telemetry'}</span>
                </button>
              </div>

              {batchResults.length > 0 && (
                <div className="mt-4 p-3 bg-slate-950 rounded border border-slate-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-white">Batch Results: {batchResults.length} Flows Analyzed</span>
                    <span className="text-emerald-400 font-mono">100% Processed</span>
                  </div>
                  <div className="max-h-48 overflow-y-auto divide-y divide-slate-800">
                    {batchResults.map((b) => (
                      <div
                        key={b.id}
                        onClick={() => setAnalyzedResult(b)}
                        className="py-1.5 px-2 hover:bg-slate-900 flex items-center justify-between cursor-pointer rounded"
                      >
                        <span className="text-sky-400 font-bold">{b.telemetry.sourceIp}</span>
                        <span className="text-slate-300">{b.prediction.predictedClass}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] ${getRiskBadgeColor(b.riskLevel)}`}>
                          Score: {b.riskScore}/100
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Real-Time ML Inference & Explainability Output (5 Cols) */}
        <div className="lg:col-span-5 space-y-4 font-mono">
          {analyzedResult ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-widest">Inference Results</span>
                  <div className="text-xs text-slate-400">{analyzedResult.id}</div>
                </div>
                <span className="text-[11px] text-emerald-400 bg-emerald-950/80 border border-emerald-700/60 px-2 py-0.5 rounded font-bold">
                  {analyzedResult.prediction.modelUsed}
                </span>
              </div>

              {/* Class & Category Badge */}
              <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">PREDICTED THREAT:</span>
                  <span className="text-xs text-slate-400">CONFIDENCE:</span>
                </div>

                <div className="flex items-center justify-between mt-1">
                  <div className="flex items-center space-x-2">
                    {analyzedResult.prediction.predictedClass === 'BENIGN' ? (
                      <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                    ) : analyzedResult.prediction.predictedClass === 'PROBE' ? (
                      <AlertTriangle className="w-6 h-6 text-amber-400" />
                    ) : (
                      <Flame className="w-6 h-6 text-rose-500" />
                    )}
                    <span className="text-xl font-bold text-white tracking-wide">
                      {analyzedResult.prediction.predictedClass}
                    </span>
                  </div>
                  <span className="text-lg font-bold text-sky-400">
                    {(analyzedResult.prediction.confidence * 100).toFixed(1)}%
                  </span>
                </div>

                <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                  <span className="text-slate-400">Category Mapping:</span>
                  <span className="text-slate-200 font-bold uppercase">{analyzedResult.prediction.highLevelCategory}</span>
                </div>
              </div>

              {/* Continuous 0 - 100 Risk Score Dial & Gauge */}
              <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-slate-400">MULTI-FACTOR RISK SCORE:</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getRiskBadgeColor(analyzedResult.riskLevel)}`}>
                    {analyzedResult.riskLevel.toUpperCase()}
                  </span>
                </div>

                <div className="flex items-baseline space-x-2">
                  <span className="text-4xl font-bold font-mono text-white">
                    {analyzedResult.riskScore}
                  </span>
                  <span className="text-sm text-slate-400">/ 100</span>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-slate-800 h-2.5 rounded-full mt-3 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      analyzedResult.riskScore <= 30
                        ? 'bg-emerald-500'
                        : analyzedResult.riskScore <= 60
                        ? 'bg-amber-500'
                        : analyzedResult.riskScore <= 80
                        ? 'bg-orange-500'
                        : 'bg-rose-500'
                    }`}
                    style={{ width: `${analyzedResult.riskScore}%` }}
                  ></div>
                </div>

                {/* Mathematical Breakdown Accordion */}
                <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] space-y-1.5 text-slate-400">
                  <div className="flex justify-between">
                    <span>ML Threat Probability Component (45% max):</span>
                    <span className="text-slate-200 font-bold">+{analyzedResult.riskBreakdown.mlProbabilityScore}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Threat Severity Base (25% max):</span>
                    <span className="text-slate-200 font-bold">+{analyzedResult.riskBreakdown.threatSeverityBase}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Traffic Anomaly Index (15% max):</span>
                    <span className="text-slate-200 font-bold">+{analyzedResult.riskBreakdown.trafficAnomalyIndex}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Behavioral / Auth Penalty (15% max):</span>
                    <span className="text-slate-200 font-bold">+{analyzedResult.riskBreakdown.behavioralAnomalyPenalty}</span>
                  </div>
                  {analyzedResult.riskBreakdown.benignMitigationCredit > 0 && (
                    <div className="flex justify-between text-emerald-400">
                      <span>Benign Mitigation Credit:</span>
                      <span className="font-bold">-{analyzedResult.riskBreakdown.benignMitigationCredit}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Explainable AI (XAI) Attribution Box */}
              <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2.5">
                <div className="flex items-center space-x-1.5 text-xs text-sky-400 font-bold">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>EXPLAINABLE AI: KEY ATTRIBUTION DRIVERS</span>
                </div>
                <div className="space-y-2 text-xs">
                  {analyzedResult.prediction.topFeatures.map((feat) => (
                    <div key={feat.featureName} className="bg-slate-900/90 p-2 rounded border border-slate-800">
                      <div className="flex items-center justify-between text-slate-300 font-bold">
                        <span>{feat.displayName}</span>
                        <span className={feat.impact === 'positive' ? 'text-rose-400' : 'text-emerald-400'}>
                          {feat.impact === 'positive' ? `+${(feat.contribution * 100).toFixed(0)}% Risk` : `Mitigating`}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1 font-sans">{feat.explanation}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Adaptive Defense Response */}
              <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 flex items-center space-x-1.5">
                    <Terminal className="w-3.5 h-3.5 text-amber-400" />
                    <span className="font-bold text-amber-400">RECOMMENDED ADAPTIVE DEFENSE</span>
                  </span>
                  <span className="text-[10px] bg-amber-950/80 text-amber-300 border border-amber-800/80 px-1.5 py-0.5 rounded">
                    SIMULATED
                  </span>
                </div>

                <div className="text-sm font-bold text-white">
                  {analyzedResult.adaptiveAction.summary}
                </div>
                <p className="text-xs text-slate-400 font-sans">
                  {analyzedResult.adaptiveAction.description}
                </p>

                <div className="bg-black p-2 rounded border border-slate-800 text-[11px] text-emerald-400 overflow-x-auto">
                  <code>{analyzedResult.adaptiveAction.technicalDetails.commandSimulated}</code>
                </div>

                <div className="text-[10px] text-slate-500">
                  Subsystem: {analyzedResult.adaptiveAction.technicalDetails.subsystem} | Reversion: {analyzedResult.adaptiveAction.technicalDetails.reversionPolicy}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 space-y-3">
              <Info className="w-10 h-10 text-slate-600 mx-auto" />
              <h3 className="text-sm font-bold text-slate-200">Awaiting Telemetry Flow</h3>
              <p className="text-xs text-slate-500 font-sans">
                Select an attack template or upload a network flow CSV on the left to trigger the Random Forest classifier and see real-time risk scoring and Explainable AI breakdown.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
