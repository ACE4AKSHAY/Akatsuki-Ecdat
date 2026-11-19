import React, { useEffect, useState } from 'react';
import { Route, LoaderCircle } from 'lucide-react';
import { RoadmapResponse } from '../types';
import { fetchRoadmap } from '../api';
import { RiskChip } from '../components/RiskChip';
import { Badge } from '../components/AssessmentBadges';

interface Props {
  scanId?: string;
  onSelectAsset?: (id: string) => void;
}

const PHASE_TONE: Record<string, 'bad' | 'warn' | 'info' | 'neutral'> = {
  immediate: 'bad',
  transition: 'warn',
  target: 'info',
  monitor: 'neutral',
};

export const MigrationRoadmapPage: React.FC<Props> = ({ scanId, onSelectAsset }) => {
  const [data, setData] = useState<RoadmapResponse | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let live = true;
    setData(null); setError('');
    if (!scanId) return;
    fetchRoadmap(scanId)
      .then(result => { if (live) setData(result); })
      .catch(err => { if (live) setError((err as Error).message); });
    return () => { live = false; };
  }, [scanId]);

  if (!scanId) {
    return <div className="empty-state"><Route size={30} /><h2>No completed scan yet</h2><p>Run or select a completed scan to build a phased migration roadmap.</p></div>;
  }
  if (error) return <p role="alert" className="error-panel">{error}</p>;
  if (!data) return <p className="text-ink-soft text-sm flex items-center gap-2"><LoaderCircle size={16} className="animate-spin" />Building roadmap…</p>;

  return (
    <div>
      <div className="metric-grid">
        {data.phases.map(phase => (
          <div className={`metric ${phase.id === 'immediate' ? 'critical' : phase.id === 'transition' ? 'warning' : phase.id === 'target' ? 'teal' : 'neutral'}`} key={phase.id}>
            <div><h2>{phase.label}</h2><strong>{phase.count}</strong></div>
            <p>{phase.description}</p>
          </div>
        ))}
      </div>

      {data.phases.filter(phase => phase.count > 0).map(phase => (
        <section className="dashboard-panel mt-5" key={phase.id}>
          <div className="flex items-center gap-2 flex-wrap">
            <h2>{phase.label}</h2>
            <Badge label={`${phase.count} assets`} tone={PHASE_TONE[phase.id]} />
          </div>
          <p>{phase.description}</p>
          <div className="overflow-x-auto mt-3">
            <table className="w-full border-collapse text-[12.6px]">
              <thead>
                <tr>
                  {['Asset', 'Use', 'Action', 'Readiness', 'HNDL', 'Target', 'Risk'].map(h => (
                    <th key={h} className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong pr-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {phase.items.map(item => (
                  <tr key={item.id} className="hover:bg-paper/50 cursor-pointer" onClick={() => onSelectAsset?.(item.id)}>
                    <td className="py-[9px] pr-3 border-b border-border font-medium text-ink">{item.name}</td>
                    <td className="py-[9px] pr-3 border-b border-border text-ink-soft">{item.usageContext || '—'}</td>
                    <td className="py-[9px] pr-3 border-b border-border text-ink-soft">{item.action || '—'}</td>
                    <td className="py-[9px] pr-3 border-b border-border text-ink-soft">{item.readinessTier || '—'}</td>
                    <td className="py-[9px] pr-3 border-b border-border text-ink-soft">{item.hndlTier || '—'}</td>
                    <td className="py-[9px] pr-3 border-b border-border font-mono text-[11.5px] text-ink-soft">{item.target || '—'}</td>
                    <td className="py-[9px] pr-3 border-b border-border"><RiskChip tier={(item.riskTier || 'low').toLowerCase() as 'critical' | 'high' | 'medium' | 'low'} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  );
};
