import React from 'react';
import { LayoutDashboard, Database, ChartNoAxesCombined, FileSearch, Lightbulb, ShieldCheck, Monitor } from 'lucide-react';
import { Screen } from '../types';
import { targetName } from '../format';
interface Props { currentScreen: Screen; onScreenChange: (screen: Screen) => void; criticalCount: number; scanTargetName?: string; children: React.ReactNode; }
const screens = [
  { id: 'overview', label: 'Overview', title: 'Cryptographic posture', subtitle: 'Discover your cryptographic assets. Plan your next move.', icon: LayoutDashboard },
  { id: 'inventory', label: 'Inventory', title: 'Asset inventory', subtitle: 'Explore the cryptography across your workspace.', icon: Database },
  { id: 'heatmap', label: 'Risk heatmap', title: 'Understand your exposure', subtitle: 'Explore how your threat timeline changes migration urgency.', icon: ChartNoAxesCombined },
  { id: 'detail', label: 'Asset detail', title: 'A closer look', subtitle: 'Trace each finding to its source and explore migration options.', icon: FileSearch },
  { id: 'recommend', label: 'Recommendations', title: 'Plan your migration', subtitle: 'Prioritize replacements and export your scan results.', icon: Lightbulb },
] as const;
export const AppShell: React.FC<Props> = ({ currentScreen, onScreenChange, scanTargetName, children }) => {
  const current = screens.find(s => s.id === currentScreen)!;
  return <div className="app-layout">
    <aside className="app-sidebar">
      <div className="brand">ECDAT<span>KNOW YOUR CRYPTOGRAPHY</span></div>
      <nav aria-label="Main navigation">{screens.map(s => <button key={s.id} aria-current={currentScreen === s.id ? 'page' : undefined} onClick={() => onScreenChange(s.id)}><s.icon size={19} /><span>{s.label}</span></button>)}</nav>
      <div className="sidebar-footer"><ShieldCheck size={24} /><p>Clarity today.<br />Readiness for tomorrow.</p></div>
    </aside>
    <main className="app-main">
      <div className="workspace-label"><Monitor size={17} />Local workspace</div>
      <header className="page-heading"><h1>{current.title}</h1><p>{current.subtitle}</p></header>
      {children}
      <footer className="app-footer"><span><b>ECDAT</b> · Cryptographic asset discovery</span><span title={scanTargetName}>{scanTargetName ? `Workspace: ${targetName(scanTargetName)}` : 'Local workspace'}</span></footer>
    </main>
  </div>;
};
