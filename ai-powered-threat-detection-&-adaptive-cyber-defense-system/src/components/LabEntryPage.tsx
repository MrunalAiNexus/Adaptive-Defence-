import React, { useState } from 'react';
import { Shield, ArrowRight, Terminal, Lock, Cpu, Radio, Activity } from 'lucide-react';

interface LabEntryPageProps {
  onEnterLab: (targetTab?: string) => void;
}

export const LabEntryPage: React.FC<LabEntryPageProps> = ({ onEnterLab }) => {
  const [isTransitioning, setIsTransitioning] = useState(false);

  const handleEnter = (tab?: string) => {
    setIsTransitioning(true);
    setTimeout(() => {
      onEnterLab(tab);
    }, 400);
  };

  return (
    <div
      className={`fixed inset-0 z-50 flex flex-col justify-between items-center bg-[#050814] text-slate-100 overflow-hidden select-none transition-all duration-500 ease-out ${
        isTransitioning ? 'opacity-0 scale-105 pointer-events-none' : 'opacity-100 scale-100'
      }`}
    >
      {/* Background Subtle Tech Grid & Ambient Radial Glow */}
      <div className="absolute inset-0 pointer-events-none">
        {/* Fine Technical Grid */}
        <div
          className="absolute inset-0 opacity-[0.07]"
          style={{
            backgroundImage: `linear-gradient(to right, #38bdf8 1px, transparent 1px), linear-gradient(to bottom, #38bdf8 1px, transparent 1px)`,
            backgroundSize: '48px 48px',
          }}
        />
        {/* Top/Center Atmospheric Radial Lighting */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-sky-600/10 rounded-full blur-[140px]" />
        <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 w-[500px] h-[350px] bg-indigo-600/5 rounded-full blur-[120px]" />
      </div>

      {/* Top Status Header */}
      <header className="relative w-full max-w-6xl mx-auto px-6 py-6 flex items-center justify-between z-10">
        <div className="flex items-center space-x-2.5">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-[11px] font-mono tracking-widest text-slate-400 uppercase">
            SECURE RESEARCH NODE // LAB-01
          </span>
        </div>

        <div className="hidden sm:flex items-center space-x-4 text-[11px] font-mono text-slate-400">
          <span>MODEL: RF-100 ENSEMBLE</span>
          <span>&bull;</span>
          <span>TELEMETRY: NSL-KDD</span>
          <span>&bull;</span>
          <span className="text-emerald-400">SYSTEM READY</span>
        </div>
      </header>

      {/* Main Centered Content */}
      <main className="relative z-10 flex-1 flex flex-col items-center justify-center text-center px-4 max-w-3xl mx-auto">
        {/* Shield Security Visual */}
        <div className="relative mb-8 group">
          {/* Subtle Outer Glow Ring */}
          <div className="absolute inset-0 rounded-full bg-sky-500/15 blur-xl group-hover:bg-sky-500/25 transition-all duration-700" />
          
          {/* Concentric Decorative Precision Borders */}
          <div className="relative w-24 h-24 sm:w-28 sm:h-28 rounded-2xl bg-slate-950/80 border border-slate-800 flex items-center justify-center shadow-2xl shadow-sky-950/50 backdrop-blur-md">
            {/* Subtle Tech Corner Accents */}
            <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-sky-400/60" />
            <div className="absolute top-1.5 right-1.5 w-1.5 h-1.5 border-t border-r border-sky-400/60" />
            <div className="absolute bottom-1.5 left-1.5 w-1.5 h-1.5 border-b border-l border-sky-400/60" />
            <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-sky-400/60" />

            <div className="w-16 h-16 sm:w-18 sm:h-18 rounded-xl bg-sky-950/40 border border-sky-500/30 flex items-center justify-center">
              <Shield className="w-8 h-8 sm:w-9 sm:h-9 text-sky-400 drop-shadow-[0_0_12px_rgba(56,189,248,0.5)]" />
            </div>
          </div>
        </div>

        {/* Title */}
        <h1 className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tight text-white font-sans uppercase">
          ADAPTIVEDEFENSE
        </h1>

        {/* Subtitle */}
        <h2 className="mt-3 text-xs sm:text-sm md:text-base font-semibold tracking-[0.25em] text-sky-400 font-mono uppercase">
          THREAT DETECTION & MULTI-FACTOR RISK SCORING
        </h2>

        {/* Creator Attribution */}
        <div className="mt-8 flex flex-col items-center">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-widest">
            Created by
          </span>
          <span className="mt-1.5 text-lg sm:text-xl font-bold tracking-wider text-slate-100 font-mono">
            MRUNAL URANKAR
          </span>
        </div>

        {/* Prominent Action Button: ENTER THE LAB → */}
        <div className="mt-10">
          <button
            onClick={() => handleEnter('dashboard')}
            id="enter-lab-button"
            disabled={isTransitioning}
            className="group relative px-8 sm:px-10 py-3.5 sm:py-4 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-sm sm:text-base tracking-widest uppercase transition-all duration-300 shadow-[0_0_30px_-5px_rgba(14,165,233,0.4)] hover:shadow-[0_0_40px_0px_rgba(14,165,233,0.6)] hover:scale-[1.02] active:scale-[0.98] cursor-pointer flex items-center space-x-2.5"
          >
            <span>ENTER THE LAB</span>
            <ArrowRight className="w-4 h-4 sm:w-5 sm:h-5 transform group-hover:translate-x-1 transition-transform" />
          </button>
        </div>

        {/* Supporting Context Text */}
        <p className="mt-5 text-xs text-slate-400 font-mono tracking-wide max-w-md">
          Cybersecurity Threat Detection & Defense Research Environment
        </p>
      </main>

      {/* Bottom Technical Spec Badges */}
      <footer className="relative w-full max-w-4xl mx-auto px-6 py-6 z-10">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-[10px] font-mono text-slate-400">
          <div 
            onClick={() => handleEnter('research')}
            className="bg-slate-900/40 hover:bg-slate-900 border border-slate-800/80 hover:border-sky-500/50 hover:text-sky-300 px-2.5 py-1.5 rounded cursor-pointer transition-all"
            title="Open ML Inference Engine & Benchmarks"
          >
            ML INFERENCE &bull; 98.4% &rarr;
          </div>
          <div 
            onClick={() => handleEnter('defenses')}
            className="bg-slate-900/40 hover:bg-slate-900 border border-slate-800/80 hover:border-sky-500/50 hover:text-sky-300 px-2.5 py-1.5 rounded cursor-pointer transition-all"
            title="Open Convex Risk Engine Formulation"
          >
            CONVEX RISK ENGINE &rarr;
          </div>
          <div 
            onClick={() => handleEnter('defenses')}
            className="bg-slate-900/40 hover:bg-slate-900 border border-slate-800/80 hover:border-sky-500/50 hover:text-sky-300 px-2.5 py-1.5 rounded cursor-pointer transition-all"
            title="Open Adaptive SOAR Policies"
          >
            ADAPTIVE SOAR POLICIES &rarr;
          </div>
          <div 
            onClick={() => handleEnter('forensics')}
            className="bg-slate-900/40 hover:bg-slate-900 border border-slate-800/80 hover:border-sky-500/50 hover:text-sky-300 px-2.5 py-1.5 rounded cursor-pointer transition-all"
            title="Open Real-time Forensics & Telemetry"
          >
            REAL-TIME FORENSICS &rarr;
          </div>
        </div>
      </footer>
    </div>
  );
};
