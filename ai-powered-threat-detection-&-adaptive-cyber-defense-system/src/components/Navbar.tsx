import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  Activity,
  Bell,
  FileSearch,
  BrainCircuit,
  Sliders,
  BookOpen,
  ChevronDown,
  UserCheck,
  Radio
} from 'lucide-react';
import { User, UserRole } from '../types';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  currentUser: User;
  onRoleChange: (role: UserRole) => void;
  unresolvedAlertCount: number;
  onReturnToLab?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  currentUser,
  onRoleChange,
  unresolvedAlertCount,
  onReturnToLab,
}) => {
  const [moreOpen, setMoreOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const moreDropdownRef = useRef<HTMLDivElement>(null);
  const mobileMenuRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (moreDropdownRef.current && !moreDropdownRef.current.contains(target)) {
        setMoreOpen(false);
      }
      if (mobileMenuRef.current && !mobileMenuRef.current.contains(target)) {
        setMobileMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Primary navigation tabs requested in specification
  const primaryTabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'analyzer', label: 'AI + Cyber', icon: Shield },
    { id: 'forensics', label: 'Event Forensics', icon: FileSearch },
    { id: 'research', label: 'ML & Experiments', icon: BrainCircuit },
    { id: 'defenses', label: 'Adaptive Defenses', icon: Sliders },
    { id: 'dissertation', label: 'Dissertation Docs', icon: BookOpen },
  ];

  // Secondary items for narrow viewports
  const secondaryTabs = [
    { id: 'research', label: 'ML & Experiments', icon: BrainCircuit },
    { id: 'defenses', label: 'Adaptive Defenses', icon: Sliders },
    { id: 'dissertation', label: 'Dissertation Docs', icon: BookOpen },
    { id: 'alerts', label: 'Alert Center', icon: Bell, badge: unresolvedAlertCount },
  ];

  return (
    <header className="sticky top-0 z-50 select-none">
      {/* Top Status Bar: System Online & Research Environment */}
      <div className="bg-slate-950 border-b border-slate-800/80 px-4 sm:px-6 py-1 text-[11px] font-mono text-slate-400">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-slate-300 font-medium tracking-wider">
              SYSTEM ONLINE &bull; RF-100 ENSEMBLE ACTIVE &bull; BENCHMARK: NSL-KDD
            </span>
          </div>
          <div className="hidden sm:flex items-center space-x-3 text-slate-400">
            <span>RESEARCH LAB</span>
            {onReturnToLab && (
              <>
                <span>&bull;</span>
                <button
                  onClick={onReturnToLab}
                  className="text-sky-400 hover:text-sky-300 transition-colors cursor-pointer"
                  title="Return to Lab Entry"
                >
                  Lab Entrance &rarr;
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="bg-slate-950/95 backdrop-blur border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-3">
        {/* Left: Brand Identity */}
        <div
          onClick={() => setActiveTab('dashboard')}
          className="flex items-center space-x-2.5 cursor-pointer flex-shrink-0 group"
          id="navbar-brand-logo"
        >
          <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-600/40 flex items-center justify-center group-hover:border-sky-500 transition-colors">
            <Shield className="w-4 h-4 text-sky-400" />
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="font-semibold tracking-tight text-white text-sm sm:text-base">
              AdaptiveDefense
            </span>
            <span className="hidden sm:inline-block text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
              SOC
            </span>
          </div>
        </div>

        {/* Center: Primary Navigation (Desktop full, Tablet condensed with More dropdown) */}
        <nav className="hidden md:flex items-center space-x-1 flex-1 justify-center max-w-2xl px-2">
          {/* Always visible main tabs on desktop */}
          {primaryTabs.slice(0, 3).map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                id={`nav-item-${item.id}`}
                className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all whitespace-nowrap cursor-pointer ${
                  isActive
                    ? 'bg-slate-800 text-white border border-slate-700 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}

          {/* Large desktop views show all 6 tabs directly */}
          <div className="hidden lg:flex items-center space-x-1">
            {primaryTabs.slice(3).map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  id={`nav-item-${item.id}`}
                  className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all whitespace-nowrap cursor-pointer ${
                    isActive
                      ? 'bg-slate-800 text-white border border-slate-700 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>

          {/* Medium/Tablet view (md to lg): More Dropdown for remaining tabs */}
          <div className="relative lg:hidden" ref={moreDropdownRef}>
            <button
              onClick={() => setMoreOpen(!moreOpen)}
              className={`flex items-center space-x-1 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all cursor-pointer ${
                ['research', 'defenses', 'dissertation', 'alerts'].includes(activeTab)
                  ? 'bg-slate-800 text-sky-400 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <span>More</span>
              <ChevronDown className="w-3.5 h-3.5 ml-0.5" />
            </button>

            {moreOpen && (
              <div 
                onMouseDown={(e) => e.stopPropagation()}
                className="absolute left-0 mt-1.5 w-48 bg-slate-900 border border-slate-800 rounded-lg shadow-xl shadow-black/50 py-1 z-50"
              >
                {secondaryTabs.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        setActiveTab(item.id);
                        setMoreOpen(false);
                      }}
                      className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium text-left transition-colors cursor-pointer ${
                        isActive
                          ? 'bg-slate-800 text-white'
                          : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                      }`}
                    >
                      <span className="flex items-center space-x-2">
                        <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                        <span>{item.label}</span>
                      </span>
                      {item.badge !== undefined && item.badge > 0 && (
                        <span className="px-1.5 py-0.2 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-mono font-semibold">
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </nav>

        {/* Right Controls: Alerts Bell, Engine Status, User & Administrator role selector */}
        <div className="flex items-center space-x-2 sm:space-x-3 flex-shrink-0">
          {/* Active Alert Center Shortcut */}
          <button
            onClick={() => setActiveTab('alerts')}
            id="nav-alerts-button"
            title="Alert Center"
            className={`relative p-1.5 rounded-md border text-xs transition-colors cursor-pointer ${
              activeTab === 'alerts'
                ? 'bg-slate-800 border-slate-700 text-sky-400'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Bell className="w-3.5 h-3.5" />
            {unresolvedAlertCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-600 text-[9px] font-bold text-white flex items-center justify-center border border-slate-950">
                {unresolvedAlertCount > 9 ? '9+' : unresolvedAlertCount}
              </span>
            )}
          </button>

          {/* Live Engine Status (hidden on small mobile) */}
          <div className="hidden lg:flex items-center space-x-1.5 px-2 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-emerald-400 font-medium">RF-100 Active</span>
          </div>

          {/* User Profile & Role Switcher */}
          <div className="flex items-center space-x-2 pl-2 border-l border-slate-800">
            <div className="hidden sm:flex flex-col text-right">
              <span className="text-xs text-slate-200 font-medium leading-none">{currentUser.name}</span>
              <span className="text-[10px] text-slate-500 font-mono mt-0.5">{currentUser.role}</span>
            </div>

            <div className="relative">
              <select
                value={currentUser.role}
                onChange={(e) => onRoleChange(e.target.value as UserRole)}
                id="role-switcher-select"
                aria-label="User role"
                className="bg-slate-900 hover:bg-slate-800 text-[11px] text-slate-200 border border-slate-700/80 rounded px-2 py-1 focus:outline-none focus:border-sky-500 cursor-pointer transition-colors"
              >
                <option value="Analyst">Analyst</option>
                <option value="Administrator">Admin</option>
              </select>
            </div>
          </div>

          {/* Mobile Menu Button (< md) */}
          <div className="md:hidden relative" ref={mobileMenuRef}>
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-1.5 rounded-md bg-slate-900 border border-slate-800 text-slate-400 hover:text-white cursor-pointer"
              aria-label="Navigation menu"
            >
              <ChevronDown className="w-4 h-4" />
            </button>

            {mobileMenuOpen && (
              <div 
                onMouseDown={(e) => e.stopPropagation()}
                className="absolute right-0 mt-2 w-52 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl py-1 z-50"
              >
                {primaryTabs.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        setActiveTab(item.id);
                        setMobileMenuOpen(false);
                      }}
                      className={`w-full flex items-center space-x-2 px-3 py-2 text-xs font-medium text-left cursor-pointer transition-colors ${
                        isActive ? 'bg-slate-800 text-sky-400 font-semibold' : 'text-slate-300 hover:bg-slate-800'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
                <div className="border-t border-slate-800 my-1"></div>
                <button
                  onClick={() => {
                    setActiveTab('alerts');
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium text-left cursor-pointer transition-colors ${
                    activeTab === 'alerts' ? 'bg-slate-800 text-sky-400' : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <span className="flex items-center space-x-2">
                    <Bell className="w-3.5 h-3.5" />
                    <span>Alert Center</span>
                  </span>
                  {unresolvedAlertCount > 0 && (
                    <span className="px-1.5 py-0.5 rounded-full bg-rose-600 text-white text-[10px] font-mono">
                      {unresolvedAlertCount}
                    </span>
                  )}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  </header>
  );
};
