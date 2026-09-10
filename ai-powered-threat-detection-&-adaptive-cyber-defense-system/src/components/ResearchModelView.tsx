import React, { useState } from 'react';
import {
  BrainCircuit,
  Award,
  Layers,
  BarChart3,
  TrendingUp,
  CheckCircle2,
  AlertTriangle,
  FileSpreadsheet,
  Info
} from 'lucide-react';
import { MODEL_BENCHMARKS, DISSERTATION_EXPERIMENTS } from '../lib/mlEngine';

export const ResearchModelView: React.FC = () => {
  const [selectedModelIndex, setSelectedModelIndex] = useState<number>(0);
  const [activeExpId, setActiveExpId] = useState<number>(1);

  const currentModel = MODEL_BENCHMARKS[selectedModelIndex];
  const activeExp = DISSERTATION_EXPERIMENTS.find((e) => e.id === activeExpId) || DISSERTATION_EXPERIMENTS[0];

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Research Question & Academic Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center space-x-2 text-indigo-400">
          <BrainCircuit className="w-5 h-5" />
          <span className="font-bold uppercase tracking-wider text-sm">Honours Dissertation Research & Model Evaluation</span>
        </div>

        <div className="bg-slate-950 border border-slate-800 p-4 rounded-lg">
          <span className="text-[11px] text-slate-400 uppercase tracking-widest block mb-1">
            Primary Research Question:
          </span>
          <p className="text-sm font-bold text-white font-sans italic">
            &ldquo;Can machine-learning-based risk scoring improve cybersecurity threat detection and adaptive response compared with conventional rule-based detection?&rdquo;
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
          <div className="bg-slate-950/60 p-3 rounded border border-slate-800">
            <span className="text-slate-400 block font-bold">Method A: Static Rule Baseline</span>
            <p className="text-[11px] text-slate-400 font-sans mt-1">
              Snort/Suricata deterministic signature thresholds. 18.4% FPR, poor zero-day recall.
            </p>
          </div>

          <div className="bg-slate-950/60 p-3 rounded border border-slate-800">
            <span className="text-slate-400 block font-bold">Method B: Baseline ML (Logistic Reg)</span>
            <p className="text-[11px] text-slate-400 font-sans mt-1">
              L2 linear classification. 89.65% accuracy; struggles with non-linear port fan-outs.
            </p>
          </div>

          <div className="bg-slate-950/60 p-3 rounded border border-indigo-700/60 bg-indigo-950/20">
            <span className="text-indigo-300 block font-bold">Method C: Proposed ML + Adaptive System</span>
            <p className="text-[11px] text-slate-300 font-sans mt-1">
              100-Tree Random Forest + continuous 0-100 risk scoring. 98.42% accuracy, 1.62% FPR, 14ms response.
            </p>
          </div>
        </div>
      </div>

      {/* Model Benchmark Comparative Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Empirical Model Evaluation & Cross-Validation Benchmarks
            </h2>
            <p className="text-slate-400 text-[11px]">
              Evaluated on 22,544 test instances from NSL-KDD standardized benchmark
            </p>
          </div>

          {/* Model Selector Tabs */}
          <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800">
            {MODEL_BENCHMARKS.map((m, idx) => (
              <button
                key={m.modelName}
                onClick={() => setSelectedModelIndex(idx)}
                className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
                  selectedModelIndex === idx
                    ? 'bg-indigo-600 text-white font-bold shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {m.modelName.split(' (')[0]}
              </button>
            ))}
          </div>
        </div>

        {/* Selected Model KPI Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] uppercase">Accuracy</span>
            <div className="text-xl font-bold text-indigo-400 mt-1">{(currentModel.accuracy * 100).toFixed(2)}%</div>
            <span className="text-[10px] text-slate-500">Overall test set</span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] uppercase">Malicious Recall</span>
            <div className="text-xl font-bold text-emerald-400 mt-1">{(currentModel.recall * 100).toFixed(2)}%</div>
            <span className="text-[10px] text-slate-500">True Positive Rate</span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] uppercase">Precision</span>
            <div className="text-xl font-bold text-sky-400 mt-1">{(currentModel.precision * 100).toFixed(2)}%</div>
            <span className="text-[10px] text-slate-500">Positive Predictive</span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] uppercase">F1-Score</span>
            <div className="text-xl font-bold text-amber-400 mt-1">{currentModel.f1Score.toFixed(4)}</div>
            <span className="text-[10px] text-slate-500">Harmonic Mean</span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] uppercase">False Positive Rate</span>
            <div className="text-xl font-bold text-rose-400 mt-1">{(currentModel.falsePositiveRate * 100).toFixed(2)}%</div>
            <span className="text-[10px] text-slate-500">Benign misclassified</span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[10px] uppercase">ROC-AUC</span>
            <div className="text-xl font-bold text-purple-400 mt-1">{currentModel.rocAuc.toFixed(4)}</div>
            <span className="text-[10px] text-slate-500">Discrimination Area</span>
          </div>
        </div>

        {/* Why Accuracy is Insufficient Box */}
        <div className="bg-slate-950 border border-slate-800 p-4 rounded-lg flex items-start space-x-3">
          <Info className="w-5 h-5 text-sky-400 flex-shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="text-slate-200 font-bold">Academic Cybersecurity Note: Why Accuracy Alone Fails</span>
            <p className="text-slate-400 font-sans text-[11px] leading-relaxed">
              In real enterprise networks, benign traffic represents 95–99% of all flow telemetry. A trivial naive classifier predicting &ldquo;BENIGN&rdquo; unconditionally achieves 95% accuracy while completely missing 100% of cyber breaches. In intrusion detection, **Recall for Malicious Traffic** (minimizing False Negatives) and **False Positive Rate** (minimizing alert fatigue) are the paramount operational metrics.
            </p>
          </div>
        </div>

        {/* Confusion Matrix Display */}
        <div>
          <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2">
            Confusion Matrix ({currentModel.modelName})
          </h3>
          <div className="overflow-x-auto bg-slate-950 p-4 rounded-lg border border-slate-800">
            <table className="text-center w-full text-xs">
              <thead>
                <tr className="text-slate-400 border-b border-slate-800">
                  <th className="py-2 text-left">Actual \ Predicted</th>
                  {currentModel.confusionMatrix.labels.map((lbl) => (
                    <th key={lbl} className="py-2 px-3">{lbl}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {currentModel.confusionMatrix.labels.map((rowLbl, rowIdx) => (
                  <tr key={rowLbl}>
                    <td className="py-2 text-left font-bold text-slate-300">{rowLbl}</td>
                    {currentModel.confusionMatrix.matrix[rowIdx].map((val, colIdx) => (
                      <td
                        key={colIdx}
                        className={`py-2 px-3 ${
                          rowIdx === colIdx
                            ? 'bg-emerald-950/40 text-emerald-300 font-bold'
                            : val > 0
                            ? 'bg-rose-950/20 text-rose-300'
                            : 'text-slate-600'
                        }`}
                      >
                        {val}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* The 7 Formal Honours CS Research Experiments */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center space-x-2 text-white">
          <FileSpreadsheet className="w-5 h-5 text-amber-400" />
          <h2 className="text-sm font-bold uppercase tracking-wider">
            Formal Dissertation Experiments (1 through 7)
          </h2>
        </div>

        {/* Experiment Navigation Tabs */}
        <div className="flex flex-wrap gap-1.5 pb-2 border-b border-slate-800">
          {DISSERTATION_EXPERIMENTS.map((exp) => (
            <button
              key={exp.id}
              onClick={() => setActiveExpId(exp.id)}
              className={`px-3 py-1.5 rounded transition-colors cursor-pointer text-xs ${
                activeExpId === exp.id
                  ? 'bg-amber-600 text-white font-bold'
                  : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              Exp {exp.id}: {exp.name.split(': ')[1]?.slice(0, 24)}...
            </button>
          ))}
        </div>

        {/* Active Experiment Card */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-amber-400">{activeExp.name}</h3>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700/60 font-bold self-start md:self-auto">
              Status: {activeExp.status}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1">
              <span className="text-slate-400 font-bold block">Scientific Hypothesis:</span>
              <p className="text-slate-300 font-sans text-xs leading-relaxed bg-slate-900 p-3 rounded border border-slate-800">
                {activeExp.hypothesis}
              </p>
            </div>

            <div className="space-y-1">
              <span className="text-slate-400 font-bold block">Methodology & Dataset:</span>
              <p className="text-slate-300 font-sans text-xs leading-relaxed bg-slate-900 p-3 rounded border border-slate-800">
                {activeExp.methodology}
              </p>
            </div>
          </div>

          {/* Experiment Empirical Data Table */}
          <div>
            <span className="text-slate-400 font-bold block mb-2">Empirical Test Results:</span>
            <div className="overflow-x-auto bg-slate-900 p-3 rounded-lg border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-slate-400 border-b border-slate-800 font-bold">
                    {activeExp.metricsTable.columnHeaders.map((header) => (
                      <th key={header} className="py-2 px-3">{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {activeExp.metricsTable.rows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-slate-800/40">
                      {row.map((cell, cIdx) => (
                        <td key={cIdx} className="py-2 px-3 font-mono">
                          {cell}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Academic Conclusion */}
          <div className="bg-slate-900/90 border-l-4 border-amber-500 p-3.5 rounded-r-lg">
            <span className="text-amber-400 font-bold block mb-1">Academic Finding & Conclusion:</span>
            <p className="text-slate-200 font-sans text-xs leading-relaxed">
              {activeExp.conclusion}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
