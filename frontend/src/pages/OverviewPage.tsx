import React from 'react';
import { File, TriangleAlert, Atom, ChartNoAxesCombined, ArrowUpRight } from 'lucide-react';
import { FrontendAsset, RiskTier } from '../types';
import { RiskChip } from '../components/RiskChip';
interface Props { assets: FrontendAsset[]; scansCount?: number; onSelectAsset?: (id: string) => void; }
export const OverviewPage: React.FC<Props> = ({ assets, scansCount = 0, onSelectAsset }) => {
  const counts = Object.fromEntries(['critical','high','medium','low'].map(t => [t, assets.filter(a => a.tier === t).length])) as Record<RiskTier, number>;
  const metrics = [
    { label: 'Total assets', value: assets.length, note: 'Cryptographic assets discovered', icon: File, tone: 'neutral' },
    { label: 'Critical', value: counts.critical, note: 'Require immediate attention', icon: TriangleAlert, tone: 'critical' },
    { label: 'Quantum vulnerable', value: assets.filter(a => a.quantumVulnerable).length, note: 'Flagged by the risk engine', icon: Atom, tone: 'warning' },
    { label: 'Scans', value: scansCount, note: 'Completed in recent history', icon: ChartNoAxesCombined, tone: 'teal' },
  ];
  const top = [...assets].sort((a,b) => (b.autoEsc ? 999 : b.r || 0) - (a.autoEsc ? 999 : a.r || 0)).slice(0, 7);
  return <>
    <div className="metric-grid">{metrics.map(m => <div className={`metric ${m.tone}`} key={m.label}><div><h2>{m.label}</h2><strong>{m.value.toLocaleString()}</strong></div><span className="metric-icon"><m.icon size={24} /></span><p>{m.note}</p></div>)}</div>
    <div className="overview-grid">
      <section className="dashboard-panel"><h2>Risk distribution</h2><p>Share of cryptographic assets by risk level.</p><div className="risk-bars">{(Object.keys(counts) as RiskTier[]).map(t => <div className="risk-row" key={t}><span className="capitalize">{t}</span><div className="risk-track"><div style={{ width: `${assets.length ? counts[t] / assets.length * 100 : 0}%`, background: `var(--risk-${t})` }} /></div><span>{counts[t]} <small>({assets.length ? Math.round(counts[t] / assets.length * 100) : 0}%)</small></span></div>)}</div><div className="risk-note">Risk estimates use the configured threat timeline and inferred asset context.</div></section>
      <section className="dashboard-panel priority-panel"><h2>Priority assets</h2><p>Highest risk cryptographic assets in this workspace.</p><div className="overflow-x-auto"><table><thead><tr><th>Asset</th><th>Algorithm</th><th>Risk</th></tr></thead><tbody>{top.map(a => <tr key={a.id || a.name}><td><button className="asset-link" title={a.loc} onClick={() => onSelectAsset?.(a.id || a.name)}>{a.loc.split('/').pop()}<ArrowUpRight size={12} /></button></td><td>{a.algo}</td><td><RiskChip tier={a.tier || 'low'} /></td></tr>)}</tbody></table></div>{!top.length && <p className="py-8 text-center">Completed scan findings will appear here.</p>}</section>
    </div>
  </>;
};
