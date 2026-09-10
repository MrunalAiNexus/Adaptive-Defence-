import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  ArrowRight,
  Layers,
  Cpu,
  Clock,
  Radio,
  SlidersHorizontal,
  ChevronRight
} from 'lucide-react';
import {
  AreaChart,
  Area,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend
} from 'recharts';
import { SOCDashboardMetrics, AnalyzedEvent } from '../types';

interface DashboardViewProps {
  metrics: SOCDashboardMetrics;
  recentEvents: AnalyzedEvent[];
  onSelectEvent: (event: AnalyzedEvent) => void;
  onNavigateTab: (tab: string) => void;
  currentUser?: {
    name: string;
    role: string;
  };
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  metrics,
  recentEvents,
  onSelectEvent,
  onNavigateTab,
  currentUser,
}) => {
  // Risk Level Badge Colors (Restrained enterprise styling)
  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'Critical':
        return {
          bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
          dot: 'bg-rose-500',
        };
      case 'High':
        return {
          bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
          dot: 'bg-amber-500',
        };
      case 'Moderate':
        return {
          bg: 'bg-amber-500/10 border-amber-500/30 text-amber-300',
          dot: 'bg-amber-400',
        };
      case 'Low':
      default:
        return {
          bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
          dot: 'bg-emerald-500',
        };
    }
  };

  const getThreatBadge = (category: string) => {
    switch (category) {
      case 'MALICIOUS':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'SUSPICIOUS':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'NORMAL':
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  const riskBadge = getRiskBadge(metrics.overallRiskLevel);
  const hasTimelineData = metrics.timelineData && metrics.timelineData.length > 0;

  // Active automated defense counts
  const blackholeCount = recentEvents.filter(
    (e) => e.adaptiveAction.actionType === 'ISOLATE_CONTAINER' || e.adaptiveAction.actionType === 'QUARANTINE_IP'
  ).length;
  const rateLimitCount = recentEvents.filter(
    (e) => e.adaptiveAction.actionType === 'RATE_LIMIT'
  ).length;
  const pcapSniffCount = recentEvents.filter(
    (e) => e.adaptiveAction.actionType === 'INCREASE_MONITORING'
  ).length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* 1. Dashboard Header (Compact & Balanced) */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl px-5 py-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
            AdaptiveDefense
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Threat Detection & Multi-Factor Risk Scoring
          </p>
        </div>

        <div className="flex items-center flex-wrap gap-2.5 sm:gap-3">
          {/* User / Administrator Badge */}
          <div className="flex items-center space-x-2.5 bg-slate-950 border border-slate-800/80 px-3 py-1.5 rounded-lg text-xs">
            <div className="w-6 h-6 rounded-md bg-sky-950/80 border border-sky-600/40 flex items-center justify-center text-sky-400 font-bold text-[10px] font-mono">
              MU
            </div>
            <div className="flex flex-col text-left leading-tight">
              <span className="text-white font-semibold">{currentUser?.name || 'Mrunal Urankar'}</span>
              <span className="text-[10px] text-slate-400 font-mono">{currentUser?.role || 'Administrator'}</span>
            </div>
          </div>

          {/* SOC Defense Level */}
          <div 
            onClick={() => onNavigateTab('defenses')}
            className="flex items-center space-x-2 bg-slate-950 border border-slate-800/80 hover:border-sky-500/50 hover:bg-slate-900/60 px-3 py-1.5 rounded-lg text-xs cursor-pointer transition-all"
            title="Configure Adaptive Defense Policies"
          >
            <span className="text-slate-400 font-medium">Defense Level:</span>
            <span className={`inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-xs font-semibold border ${riskBadge.bg}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${riskBadge.dot}`}></span>
              <span>{metrics.overallRiskLevel.toUpperCase()} ({metrics.overallRiskIndex}/100)</span>
            </span>
          </div>

          {/* Action CTA */}
          <button
            onClick={() => onNavigateTab('analyzer')}
            id="dashboard-analyze-cta"
            className="bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium px-3.5 py-2 rounded-lg flex items-center space-x-1.5 transition-colors shadow-sm cursor-pointer"
          >
            <span>Analyze New Traffic</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 2. KPI Cards (Responsive grid: 3 desktop, 2 tablet, 1 mobile) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Total Events */}
        <div 
          onClick={() => onNavigateTab('forensics')}
          role="button"
          tabIndex={0}
          title="Open Forensic Event Log"
          className="bg-slate-900/90 border border-slate-800 hover:border-sky-500/50 hover:bg-slate-900 rounded-xl p-5 flex flex-col justify-between transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 group-hover:text-sky-300 uppercase tracking-wider font-mono flex items-center space-x-1">
              <span>Total Events</span>
              <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
            </span>
            <div className="w-8 h-8 rounded-lg bg-slate-800/60 border border-slate-700/50 flex items-center justify-center text-sky-400 group-hover:border-sky-500/40">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl sm:text-3xl font-bold font-mono text-white tracking-tight">
              {metrics.totalEventsAnalyzed.toLocaleString()}
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
              <span>Network flows ingested & analyzed</span>
              <span className="text-[10px] text-sky-400 opacity-0 group-hover:opacity-100 transition-opacity font-mono">View Log &rarr;</span>
            </div>
          </div>
        </div>

        {/* Normal Traffic */}
        <div 
          onClick={() => onNavigateTab('forensics')}
          role="button"
          tabIndex={0}
          title="Filter Normal traffic in Forensics"
          className="bg-slate-900/90 border border-slate-800 hover:border-emerald-500/50 hover:bg-slate-900 rounded-xl p-5 flex flex-col justify-between transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 group-hover:text-emerald-300 uppercase tracking-wider font-mono flex items-center space-x-1">
              <span>Normal</span>
              <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
            </span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:border-emerald-500/50">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl sm:text-3xl font-bold font-mono text-emerald-400 tracking-tight">
              {metrics.normalCount.toLocaleString()}
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
              <span>{metrics.totalEventsAnalyzed > 0
                ? ((metrics.normalCount / metrics.totalEventsAnalyzed) * 100).toFixed(1)
                : '0.0'}% of total traffic</span>
              <span className="text-[10px] text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity font-mono">Inspect &rarr;</span>
            </div>
          </div>
        </div>

        {/* Suspicious Traffic */}
        <div 
          onClick={() => onNavigateTab('forensics')}
          role="button"
          tabIndex={0}
          title="Filter Suspicious traffic in Forensics"
          className="bg-slate-900/90 border border-slate-800 hover:border-amber-500/50 hover:bg-slate-900 rounded-xl p-5 flex flex-col justify-between transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 group-hover:text-amber-300 uppercase tracking-wider font-mono flex items-center space-x-1">
              <span>Suspicious</span>
              <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
            </span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 group-hover:border-amber-500/50">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl sm:text-3xl font-bold font-mono text-amber-400 tracking-tight">
              {metrics.suspiciousCount.toLocaleString()}
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
              <span>Probes, port scans & anomaly spikes</span>
              <span className="text-[10px] text-amber-400 opacity-0 group-hover:opacity-100 transition-opacity font-mono">Inspect &rarr;</span>
            </div>
          </div>
        </div>

        {/* Malicious Traffic */}
        <div 
          onClick={() => onNavigateTab('forensics')}
          role="button"
          tabIndex={0}
          title="Filter Malicious traffic in Forensics"
          className="bg-slate-900/90 border border-slate-800 hover:border-rose-500/50 hover:bg-slate-900 rounded-xl p-5 flex flex-col justify-between transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 group-hover:text-rose-300 uppercase tracking-wider font-mono flex items-center space-x-1">
              <span>Malicious</span>
              <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
            </span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 group-hover:border-rose-500/50">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl sm:text-3xl font-bold font-mono text-rose-400 tracking-tight">
              {metrics.maliciousCount.toLocaleString()}
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
              <span>Active attacks (DoS, Brute Force, Web)</span>
              <span className="text-[10px] text-rose-400 opacity-0 group-hover:opacity-100 transition-opacity font-mono">Inspect &rarr;</span>
            </div>
          </div>
        </div>

        {/* Critical Alerts */}
        <div 
          onClick={() => onNavigateTab('alerts')}
          role="button"
          tabIndex={0}
          title="Open Alert Center"
          className="bg-slate-900/90 border border-slate-800 hover:border-rose-500/50 hover:bg-slate-900 rounded-xl p-5 flex flex-col justify-between transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 group-hover:text-rose-300 uppercase tracking-wider font-mono flex items-center space-x-1">
              <span>Critical Alerts</span>
              <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
            </span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 group-hover:border-rose-500/50">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl sm:text-3xl font-bold font-mono text-rose-300 tracking-tight">
              {metrics.criticalAlertsCount.toLocaleString()}
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
              <span>Unresolved security alerts requiring triage</span>
              <span className="text-[10px] text-rose-400 opacity-0 group-hover:opacity-100 transition-opacity font-mono">Triage Alerts &rarr;</span>
            </div>
          </div>
        </div>

        {/* ML Accuracy */}
        <div 
          onClick={() => onNavigateTab('research')}
          role="button"
          tabIndex={0}
          title="View ML & Experiment Benchmarks"
          className="bg-slate-900/90 border border-slate-800 hover:border-indigo-500/50 hover:bg-slate-900 rounded-xl p-5 flex flex-col justify-between transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 group-hover:text-indigo-300 uppercase tracking-wider font-mono flex items-center space-x-1">
              <span>ML Accuracy</span>
              <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
            </span>
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 group-hover:border-indigo-500/50">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl sm:text-3xl font-bold font-mono text-indigo-300 tracking-tight">
              {(metrics.modelAccuracy * 100).toFixed(1)}%
            </div>
            <div className="text-xs text-emerald-400 font-mono mt-1 flex items-center justify-between">
              <span>Recall: {(metrics.modelRecall * 100).toFixed(1)}% (100 Trees)</span>
              <span className="text-[10px] text-indigo-400 opacity-0 group-hover:opacity-100 transition-opacity font-mono">Experiments &rarr;</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Threat Activity Timeline */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 sm:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
          <div>
            <h2 className="text-base sm:text-lg font-semibold text-white">
              Threat Activity & Risk Timeline
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Chronological traffic progression, anomaly classification, and moving average risk index
            </p>
          </div>

          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className="flex items-center space-x-1.5 text-slate-300">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <span>Normal</span>
            </span>
            <span className="flex items-center space-x-1.5 text-slate-300">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span>Suspicious</span>
            </span>
            <span className="flex items-center space-x-1.5 text-slate-300">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
              <span>Malicious</span>
            </span>
            <span className="flex items-center space-x-1.5 text-slate-300">
              <span className="w-2.5 h-2.5 rounded-full bg-sky-400"></span>
              <span>Avg Risk</span>
            </span>
          </div>
        </div>

        {hasTimelineData ? (
          <div className="h-64 sm:h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={metrics.timelineData}
                margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="time"
                  stroke="#64748b"
                  tick={{ fontSize: 11, fill: '#94a3b8' }}
                  tickLine={false}
                  axisLine={{ stroke: '#334155' }}
                />
                <YAxis
                  stroke="#64748b"
                  tick={{ fontSize: 11, fill: '#94a3b8' }}
                  tickLine={false}
                  axisLine={{ stroke: '#334155' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5)',
                  }}
                  itemStyle={{ padding: '2px 0' }}
                />
                <Area
                  type="monotone"
                  dataKey="normal"
                  stroke="#10b981"
                  strokeWidth={1.5}
                  fillOpacity={1}
                  fill="url(#colorNormal)"
                  name="Normal"
                />
                <Area
                  type="monotone"
                  dataKey="suspicious"
                  stroke="#f59e0b"
                  strokeWidth={1.5}
                  fillOpacity={1}
                  fill="url(#colorSuspicious)"
                  name="Suspicious"
                />
                <Area
                  type="monotone"
                  dataKey="malicious"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorMalicious)"
                  name="Malicious"
                />
                <Line
                  type="monotone"
                  dataKey="avgRisk"
                  stroke="#38bdf8"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#38bdf8' }}
                  name="Avg Risk Score"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-64 sm:h-72 flex flex-col items-center justify-center text-center p-6 bg-slate-950/40 rounded-lg border border-dashed border-slate-800">
            <div className="w-10 h-10 rounded-full bg-slate-800/80 flex items-center justify-center mb-3">
              <Radio className="w-5 h-5 text-slate-500" />
            </div>
            <p className="text-sm font-semibold text-slate-200">
              No threat activity recorded yet
            </p>
            <p className="text-xs text-slate-400 mt-1 max-w-sm">
              Run traffic analysis to populate the timeline.
            </p>
            <button
              onClick={() => onNavigateTab('analyzer')}
              className="mt-4 px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white transition-colors cursor-pointer"
            >
              Analyze New Traffic
            </button>
          </div>
        )}
      </div>

      {/* 4. Secondary Analytics Row: Attack Family Distribution & Risk Stratification */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Class Distribution */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 sm:p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">
              Threat Class Distribution
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Breakdown across NSL-KDD attack families
            </p>
          </div>

          <div className="h-44 w-full relative flex items-center justify-center my-3">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={metrics.threatDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={48}
                  outerRadius={72}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {metrics.threatDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute flex flex-col items-center pointer-events-none">
              <span className="text-[10px] text-slate-400 uppercase font-mono tracking-wider">Top Class</span>
              <span className="text-xs font-bold font-mono text-white mt-0.5">
                {metrics.threatDistribution[0]?.name || 'BENIGN'}
              </span>
            </div>
          </div>

          {/* Legend Grid */}
          <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-2 border-t border-slate-800/80">
            {metrics.threatDistribution.slice(0, 6).map((item) => (
              <div
                key={item.name}
                className="flex items-center justify-between bg-slate-950/60 px-2.5 py-1 rounded border border-slate-800/60"
              >
                <span className="flex items-center space-x-1.5 truncate">
                  <span
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: item.color }}
                  ></span>
                  <span className="text-slate-300 truncate">{item.name}</span>
                </span>
                <span className="text-slate-400 font-bold ml-1">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Risk Score Stratification (0 - 100) */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 sm:p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">
              Risk Score Stratification
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Continuous multi-factor scoring tier breakdown (0 - 100)
            </p>
          </div>

          <div className="h-44 w-full my-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={metrics.riskDistribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="range" stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} />
                <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" fill="#0284c7" radius={[4, 4, 0, 0]} name="Events" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/80 font-mono">
            <span>Overall Index: {metrics.overallRiskIndex}/100</span>
            <span className="text-sky-400 font-medium">Convex Multi-Factor</span>
          </div>
        </div>

        {/* Simulated SOAR / Adaptive Defenses Console */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 sm:p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-white">
                Simulated Adaptive Defense
              </h2>
              <button
                onClick={() => onNavigateTab('defenses')}
                className="text-xs text-sky-400 hover:text-sky-300 font-medium flex items-center space-x-0.5 cursor-pointer"
              >
                <span>Rules</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Autonomous SOAR containment policies in safe simulation
            </p>
          </div>

          {/* Stat Ticker */}
          <div className="grid grid-cols-3 gap-2.5 my-3">
            <div 
              onClick={() => onNavigateTab('defenses')}
              role="button"
              tabIndex={0}
              title="View Blackhole / iptables quarantine policies in Adaptive Defenses"
              className="bg-slate-950/80 border border-slate-800 hover:border-rose-500/50 hover:bg-slate-900/80 p-2.5 rounded-lg text-center cursor-pointer transition-all"
            >
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Blackholes</span>
              <span className="text-lg font-bold font-mono text-rose-400 mt-0.5 block">
                {blackholeCount}
              </span>
              <span className="text-[9px] text-slate-500 font-mono">iptables drop &rarr;</span>
            </div>

            <div 
              onClick={() => onNavigateTab('defenses')}
              role="button"
              tabIndex={0}
              title="View Throttling / tc rate-limit policies in Adaptive Defenses"
              className="bg-slate-950/80 border border-slate-800 hover:border-amber-500/50 hover:bg-slate-900/80 p-2.5 rounded-lg text-center cursor-pointer transition-all"
            >
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Throttles</span>
              <span className="text-lg font-bold font-mono text-amber-400 mt-0.5 block">
                {rateLimitCount}
              </span>
              <span className="text-[9px] text-slate-500 font-mono">tc rate-limit &rarr;</span>
            </div>

            <div 
              onClick={() => onNavigateTab('defenses')}
              role="button"
              tabIndex={0}
              title="View PCAP sniff policies in Adaptive Defenses"
              className="bg-slate-950/80 border border-slate-800 hover:border-sky-500/50 hover:bg-slate-900/80 p-2.5 rounded-lg text-center cursor-pointer transition-all"
            >
              <span className="text-[10px] text-slate-400 uppercase font-mono block">PCAP Sniffs</span>
              <span className="text-lg font-bold font-mono text-sky-400 mt-0.5 block">
                {pcapSniffCount}
              </span>
              <span className="text-[9px] text-slate-500 font-mono">Rolling buffer &rarr;</span>
            </div>
          </div>

          {/* Latest Execution Trigger */}
          <div 
            onClick={() => onNavigateTab('defenses')}
            role="button"
            tabIndex={0}
            title="Inspect trigger rules in Adaptive Defenses"
            className="bg-slate-950 border border-slate-800 hover:border-slate-700 hover:bg-slate-900/70 rounded-lg p-2.5 text-xs font-mono flex items-center justify-between text-slate-400 cursor-pointer transition-all"
          >
            <div className="flex items-center space-x-2 truncate">
              <span className="w-2 h-2 rounded-full bg-emerald-400 flex-shrink-0"></span>
              <span className="truncate text-slate-300">
                {recentEvents[0]?.adaptiveAction.summary || 'Passive telemetry monitoring active'}
              </span>
            </div>
            <span className="text-[10px] text-sky-400 flex-shrink-0 ml-2">~14ms latency &bull; View Rules &rarr;</span>
          </div>
        </div>
      </div>

      {/* 5. Live Analyzed Network Telemetry Stream Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 sm:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h2 className="text-base sm:text-lg font-semibold text-white">
              Live Analyzed Network Telemetry Stream
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Recent flows scored by the ensemble engine &bull; Click any row to inspect Explainable AI attribution
            </p>
          </div>

          <button
            onClick={() => onNavigateTab('forensics')}
            id="dashboard-full-forensics-btn"
            className="text-xs font-medium text-sky-400 hover:text-sky-300 flex items-center space-x-1 cursor-pointer self-start sm:self-auto"
          >
            <span>Full Forensic Log</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/80 uppercase font-mono text-[11px] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Source &rarr; Dest</th>
                <th className="py-2.5 px-3">Protocol / Svc</th>
                <th className="py-2.5 px-3">Predicted Class</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Containment Action</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {recentEvents.length > 0 ? (
                recentEvents.slice(0, 7).map((event) => (
                  <tr
                    key={event.id}
                    onClick={() => onSelectEvent(event)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-3 text-sky-400 font-semibold">{event.id}</td>
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="text-slate-200">{event.telemetry.sourceIp}</span>
                      <span className="text-slate-500 mx-1">&rarr;</span>
                      <span className="text-slate-400">{event.telemetry.destinationIp}:{event.telemetry.destinationPort}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-300 mr-1.5">
                        {event.telemetry.protocol}
                      </span>
                      <span className="text-slate-400">{event.telemetry.service}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${getThreatBadge(event.prediction.highLevelCategory)}`}>
                        {event.prediction.predictedClass}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded font-semibold border ${getRiskBadge(event.riskLevel).bg}`}>
                        {event.riskScore}/100 ({event.riskLevel})
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 truncate max-w-xs">
                      {event.adaptiveAction.summary}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <span className="text-sky-400 hover:text-sky-300 text-xs font-medium">Inspect &rarr;</span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No recent network flows recorded. Ingest telemetry or run analysis to view live stream.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

