import React, { useState } from 'react';
import {
  Sliders,
  Shield,
  Lock,
  Zap,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Info,
  Terminal,
  Activity
} from 'lucide-react';
import { RiskWeightConfig } from '../types';

interface AdaptiveDefenseViewProps {
  weights: RiskWeightConfig;
  onUpdateWeights: (newWeights: RiskWeightConfig) => void;
}

export const AdaptiveDefenseView: React.FC<AdaptiveDefenseViewProps> = ({
  weights,
  onUpdateWeights,
}) => {
  const [localWeights, setLocalWeights] = useState<RiskWeightConfig>(weights);
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);

  // Simulated Firewall Rule Blocklist State
  const [blockedIps, setBlockedIps] = useState<
    { ip: string; threat: string; risk: number; time: string; action: string }[]
  >([
    {
      ip: '198.51.100.44',
      threat: 'DOS (SYN Flood)',
      risk: 94,
      time: '10:42:15',
      action: 'iptables -I INPUT -s 198.51.100.44 -j DROP',
    },
    {
      ip: '203.0.113.88',
      threat: 'BRUTE_FORCE (SSH Dictionary)',
      risk: 86,
      time: '10:38:02',
      action: 'fail2ban-client set sshd banip 203.0.113.88',
    },
  ]);

  const handleWeightChange = (key: keyof RiskWeightConfig, val: number) => {
    setLocalWeights((prev) => ({
      ...prev,
      [key]: val,
    }));
  };

  const handleSaveWeights = () => {
    onUpdateWeights(localWeights);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 3000);
  };

  const handleResetDefaults = () => {
    const defaults: RiskWeightConfig = {
      mlProbabilityWeight: 0.45,
      threatSeverityWeight: 0.25,
      trafficAnomalyWeight: 0.15,
      behavioralAnomalyWeight: 0.15,
      benignMitigationCredit: 15,
    };
    setLocalWeights(defaults);
    onUpdateWeights(defaults);
  };

  const handleRevokeBlock = (ip: string) => {
    setBlockedIps((prev) => prev.filter((item) => item.ip !== ip));
  };

  const handleAddManualBlock = (e: React.FormEvent) => {
    e.preventDefault();
    const target = e.target as any;
    const ip = target.ip.value;
    if (!ip) return;
    setBlockedIps((prev) => [
      {
        ip,
        threat: 'MANUAL_ANALYST_CONTAINMENT',
        risk: 90,
        time: new Date().toLocaleTimeString(),
        action: `iptables -I INPUT -s ${ip} -j DROP`,
      },
      ...prev,
    ]);
    target.reset();
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header & Safe Simulation Guarantee */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center space-x-2 text-amber-400">
          <Zap className="w-5 h-5" />
          <h1 className="text-sm font-bold uppercase tracking-wider text-white">
            Adaptive Cyber Defense & Simulated SOAR Engine
          </h1>
        </div>
        <p className="text-slate-400 font-sans text-xs">
          Closed-loop feedback control mapping multi-factor risk scores directly into graduated security countermeasures.
        </p>

        {/* Safety Disclaimer Banner */}
        <div className="bg-amber-950/40 border border-amber-800/80 p-3 rounded-lg flex items-center space-x-3 text-amber-300">
          <Lock className="w-5 h-5 flex-shrink-0 text-amber-400" />
          <div className="font-sans text-[11px] leading-relaxed">
            <strong className="font-mono text-amber-200">SAFE SIMULATION GUARANTEE:</strong> To preserve host stability and prevent network isolation in demonstration/academic environments, all active containment commands (`iptables`, `fail2ban`, `tc rate-limit`) are executed in a safe, simulated state machine.
          </div>
        </div>
      </div>

      {/* Graduated Response Policy Tiers Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Tier 1: Low */}
        <div className="bg-slate-900 border border-emerald-900/60 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-emerald-400 font-bold uppercase">Tier 1: Low Risk</span>
            <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 text-[10px] border border-emerald-700/60">
              0 - 30 pts
            </span>
          </div>
          <div className="text-white font-bold">Passive Telemetry Logging</div>
          <p className="text-slate-400 font-sans text-[11px]">
            No traffic disruption. Append flow attributes to audit log; continue baseline statistical profiling.
          </p>
          <div className="bg-slate-950 p-2 rounded border border-slate-800 text-[10px] text-emerald-400">
            <code>action: PASS_THROUGH</code>
          </div>
        </div>

        {/* Tier 2: Moderate */}
        <div className="bg-slate-900 border border-amber-900/60 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-amber-400 font-bold uppercase">Tier 2: Moderate Risk</span>
            <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 text-[10px] border border-amber-700/60">
              31 - 60 pts
            </span>
          </div>
          <div className="text-white font-bold">Deep PCAP Sniffing & Jitter Log</div>
          <p className="text-slate-400 font-sans text-[11px]">
            Initiate rolling 60-second packet capture on origin interface; flag session for heuristic scrutiny.
          </p>
          <div className="bg-slate-950 p-2 rounded border border-slate-800 text-[10px] text-amber-400">
            <code>tcpdump -i eth0 host [IP] -c 100</code>
          </div>
        </div>

        {/* Tier 3: High */}
        <div className="bg-slate-900 border border-orange-900/60 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-orange-400 font-bold uppercase">Tier 3: High Risk</span>
            <span className="px-1.5 py-0.5 rounded bg-orange-950 text-orange-300 text-[10px] border border-orange-700/60">
              61 - 80 pts
            </span>
          </div>
          <div className="text-white font-bold">Token Rate Limit & Step-Up MFA</div>
          <p className="text-slate-400 font-sans text-[11px]">
            Clamp ingress bandwidth to 50Kbps via Linux Traffic Control (`tc`); revoke session cookies and enforce FIDO2 MFA.
          </p>
          <div className="bg-slate-950 p-2 rounded border border-slate-800 text-[10px] text-orange-400">
            <code>tc qdisc add dev eth0 rate 50kbit</code>
          </div>
        </div>

        {/* Tier 4: Critical */}
        <div className="bg-slate-900 border border-rose-900/60 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-rose-400 font-bold uppercase">Tier 4: Critical Risk</span>
            <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 text-[10px] border border-rose-700/60">
              81 - 100 pts
            </span>
          </div>
          <div className="text-white font-bold">Blackhole Quarantine & Paging</div>
          <p className="text-slate-400 font-sans text-[11px]">
            Inject kernel-level iptables DROP rule for 1 hour; isolate workload container to security DMZ; dispatch PagerDuty alert.
          </p>
          <div className="bg-slate-950 p-2 rounded border border-slate-800 text-[10px] text-rose-400">
            <code>iptables -I INPUT -s [IP] -j DROP</code>
          </div>
        </div>
      </div>

      {/* Main Split: Formula Calibration Sliders on Left, Active Quarantines on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Weight Calibration Sliders (6 Cols) */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-1.5">
                <Sliders className="w-4 h-4 text-sky-400" />
                <span>Multi-Factor Risk Scoring Calibration</span>
              </h2>
              <p className="text-[11px] text-slate-400">
                Adjust sensitivity weights for viva presentation and model sensitivity experiments
              </p>
            </div>
            <button
              onClick={handleResetDefaults}
              className="text-xs text-slate-400 hover:text-white flex items-center space-x-1 cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          </div>

          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300">ML Model Probability Weight ($w_1$):</span>
                <span className="text-sky-400 font-bold">{(localWeights.mlProbabilityWeight * 100).toFixed(0)}% (Max 45 pts)</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="0.8"
                step="0.05"
                value={localWeights.mlProbabilityWeight}
                onChange={(e) => handleWeightChange('mlProbabilityWeight', parseFloat(e.target.value))}
                className="w-full accent-sky-500 cursor-pointer"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300">Threat Severity Constant Weight ($w_2$):</span>
                <span className="text-amber-400 font-bold">{(localWeights.threatSeverityWeight * 100).toFixed(0)}% (Max 25 pts)</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="0.5"
                step="0.05"
                value={localWeights.threatSeverityWeight}
                onChange={(e) => handleWeightChange('threatSeverityWeight', parseFloat(e.target.value))}
                className="w-full accent-amber-500 cursor-pointer"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300">Traffic Anomaly Index ($w_3$):</span>
                <span className="text-purple-400 font-bold">{(localWeights.trafficAnomalyWeight * 100).toFixed(0)}% (Max 15 pts)</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.4"
                step="0.05"
                value={localWeights.trafficAnomalyWeight}
                onChange={(e) => handleWeightChange('trafficAnomalyWeight', parseFloat(e.target.value))}
                className="w-full accent-purple-500 cursor-pointer"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300">Behavioral / Failed Logins ($w_4$):</span>
                <span className="text-rose-400 font-bold">{(localWeights.behavioralAnomalyWeight * 100).toFixed(0)}% (Max 15 pts)</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.4"
                step="0.05"
                value={localWeights.behavioralAnomalyWeight}
                onChange={(e) => handleWeightChange('behavioralAnomalyWeight', parseFloat(e.target.value))}
                className="w-full accent-rose-500 cursor-pointer"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300">Benign Mitigation Deduction (M_benign):</span>
                <span className="text-emerald-400 font-bold">-{localWeights.benignMitigationCredit} pts credit</span>
              </div>
              <input
                type="range"
                min="0"
                max="30"
                step="5"
                value={localWeights.benignMitigationCredit}
                onChange={(e) => handleWeightChange('benignMitigationCredit', parseInt(e.target.value, 10))}
                className="w-full accent-emerald-500 cursor-pointer"
              />
            </div>
          </div>

          <div className="pt-2 flex items-center justify-between border-t border-slate-800">
            {savedSuccess ? (
              <span className="text-emerald-400 flex items-center space-x-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Risk weights updated across inference pipeline!</span>
              </span>
            ) : (
              <span className="text-slate-500">Live calibration affects all future flow scoring.</span>
            )}
            <button
              onClick={handleSaveWeights}
              className="bg-sky-600 hover:bg-sky-500 text-white px-4 py-1.5 rounded transition-colors cursor-pointer"
            >
              Apply Weight Formula
            </button>
          </div>
        </div>

        {/* Active Simulated Blackhole Table (6 Cols) */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-1.5">
                <Terminal className="w-4 h-4 text-rose-400" />
                <span>Active Simulated Blackhole Table (SOAR)</span>
              </h2>
              <p className="text-[11px] text-slate-400">
                Hosts currently quarantined by the adaptive defense engine
              </p>
            </div>
            <span className="text-rose-400 font-bold">{blockedIps.length} Quarantined</span>
          </div>

          {/* Quick Manual Block Form */}
          <form onSubmit={handleAddManualBlock} className="flex gap-2">
            <input
              name="ip"
              type="text"
              placeholder="Enter IP to quarantine (e.g. 198.51.100.99)"
              className="flex-1 bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-white focus:outline-none focus:border-rose-500"
            />
            <button
              type="submit"
              className="bg-rose-600 hover:bg-rose-500 text-white px-3 py-1 rounded transition-colors cursor-pointer"
            >
              Block IP
            </button>
          </form>

          {/* Quarantined IP List */}
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {blockedIps.map((item) => (
              <div
                key={item.ip}
                className="bg-slate-950 border border-slate-800 p-3 rounded-lg flex flex-col space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-white font-bold">{item.ip}</span>
                  <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px]">
                    Risk: {item.risk}/100
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 flex justify-between">
                  <span>Trigger: {item.threat}</span>
                  <span>Banned at: {item.time}</span>
                </div>
                <div className="bg-black p-1.5 rounded border border-slate-800 text-[10px] text-emerald-400 font-mono">
                  <code>{item.action}</code>
                </div>
                <div className="flex justify-end pt-1">
                  <button
                    onClick={() => handleRevokeBlock(item.ip)}
                    className="text-xs text-sky-400 hover:text-sky-300 underline cursor-pointer"
                  >
                    Revoke Quarantine (Unblock)
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
