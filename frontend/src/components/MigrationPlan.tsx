import React from 'react';
import { FrontendAsset } from '../types';

export const MigrationPlan: React.FC<{ asset: FrontendAsset }> = ({ asset }) => {
  const candidates = asset.candidates || [];
  const playbook = asset.playbook || [];

  return (
    <div className="border border-border rounded-md p-5 bg-surface mt-5">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <h3 className="text-[13px] font-semibold text-ink">Migration plan</h3>
        <span className="text-[11px] text-ink-faint">Guidance only — ECDAT never changes production.</span>
      </div>
      {asset.strategyRationale && <p className="text-[12.5px] text-ink-soft mt-2">{asset.strategyRationale}</p>}

      {candidates.length > 0 && (
        <div className="mt-4">
          <div className="text-[11px] text-ink-faint uppercase tracking-wide mb-2">Ranked candidates</div>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[12.3px]">
              <thead>
                <tr>
                  {['Candidate', 'Fit', 'Maturity', 'Latency', 'Cost', 'Standard'].map(h => (
                    <th key={h} className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong pr-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {candidates.map(c => (
                  <tr key={c.id}>
                    <td className="py-[8px] pr-3 border-b border-border font-medium text-ink">{c.label}</td>
                    <td className={`py-[8px] pr-3 border-b border-border ${c.fit === 'preferred' ? 'text-qubit font-medium' : 'text-ink-soft'}`}>{c.fit}</td>
                    <td className="py-[8px] pr-3 border-b border-border text-ink-soft">{c.maturity}</td>
                    <td className="py-[8px] pr-3 border-b border-border text-ink-soft">{c.latencyImpact || '—'}</td>
                    <td className="py-[8px] pr-3 border-b border-border text-ink-soft">{c.costImpact || '—'}</td>
                    <td className="py-[8px] pr-3 border-b border-border font-mono text-[11.5px] text-ink-soft">{c.standard}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {playbook.length > 0 && (
        <details className="mt-4" open={asset.phase === 'immediate'}>
          <summary className="cursor-pointer text-[12.5px] font-medium text-ink">Phased playbook · {playbook.length} steps</summary>
          <ol className="mt-3 space-y-2">
            {playbook.map(step => (
              <li key={step.order} className="border border-border rounded-sm p-3 bg-paper/40">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-[11px] text-ink-faint">{step.order}</span>
                  <span className="text-[11px] uppercase tracking-wide text-qubit">{step.phase}</span>
                  <span className="text-[11px] text-ink-faint">· {step.ownerRole}</span>
                  {step.blocking && <span className="text-[10.5px] px-[6px] py-[2px] rounded-full bg-risk-medium-bg text-risk-medium">gate</span>}
                </div>
                <p className="text-[12.5px] text-ink mt-1">{step.action}</p>
                <p className="text-[11.5px] text-ink-soft mt-1"><b className="font-medium">Evidence:</b> {step.evidence}</p>
                <p className="text-[11.5px] text-ink-soft"><b className="font-medium">Rollback:</b> {step.rollback}</p>
              </li>
            ))}
          </ol>
        </details>
      )}

      {(asset.blockers?.length || asset.assumptions?.length) ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          {!!asset.blockers?.length && (
            <div>
              <div className="text-[11px] text-ink-faint uppercase tracking-wide mb-1">Blockers</div>
              <ul className="list-disc pl-5 text-[12px] text-ink-soft space-y-1">
                {asset.blockers.map((b, i) => <li key={i}>{b}</li>)}
              </ul>
            </div>
          )}
          {!!asset.assumptions?.length && (
            <div>
              <div className="text-[11px] text-ink-faint uppercase tracking-wide mb-1">Assumptions</div>
              <ul className="list-disc pl-5 text-[12px] text-ink-soft space-y-1">
                {asset.assumptions.map((a, i) => <li key={i}>{a}</li>)}
              </ul>
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
};
