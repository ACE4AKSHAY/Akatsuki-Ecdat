import React from 'react';
import { FrontendAsset } from '../types';

type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

const TONES: Record<Tone, string> = {
  neutral: 'bg-paper text-ink-soft border-border',
  ok: 'bg-risk-low-bg text-risk-low border-transparent',
  warn: 'bg-risk-medium-bg text-risk-medium border-transparent',
  bad: 'bg-risk-critical-bg text-risk-critical border-transparent',
  info: 'bg-qubit-soft text-qubit border-transparent',
};

export const Badge: React.FC<{ label: string; tone?: Tone; title?: string }> = ({ label, tone = 'neutral', title }) => (
  <span title={title} className={`inline-flex items-center gap-1 text-[11px] leading-none py-[5px] px-[8px] rounded-full border ${TONES[tone]}`}>
    {label}
  </span>
);

function classicalTone(status?: string): Tone {
  if (status === 'broken') return 'bad';
  if (status === 'deprecated') return 'warn';
  if (status === 'strong' || status === 'acceptable') return 'ok';
  return 'neutral';
}

function quantumTone(status?: string): Tone {
  if (status === 'vulnerable') return 'bad';
  if (status === 'weakened') return 'warn';
  if (status === 'resistant') return 'ok';
  return 'neutral';
}

function phaseTone(phase?: string): Tone {
  if (phase === 'immediate') return 'bad';
  if (phase === 'transition') return 'warn';
  if (phase === 'target') return 'info';
  return 'neutral';
}

export const AssessmentBadges: React.FC<{ asset: FrontendAsset }> = ({ asset }) => (
  <div className="flex gap-2 flex-wrap">
    {asset.usageContext && <Badge label={`Use: ${asset.usageContext}`} tone="info" title="Inferred cryptographic role" />}
    {asset.action && <Badge label={`Plan: ${asset.action}`} tone={phaseTone(asset.phase)} title={asset.strategyRationale} />}
    {asset.classicalStatus && <Badge label={`Classical: ${asset.classicalStatus}`} tone={classicalTone(asset.classicalStatus)} />}
    {asset.quantumStatus && <Badge label={`Quantum: ${asset.quantumStatus}`} tone={quantumTone(asset.quantumStatus)} />}
    {asset.maturity && asset.maturity !== 'not-applicable' && <Badge label={`Spec: ${asset.maturity}`} tone="neutral" />}
    {asset.readinessTier && <Badge label={`Readiness: ${asset.readinessTier}${asset.readinessScore !== undefined ? ` (${asset.readinessScore}/100)` : ''}`} tone={asset.readinessTier === 'Ready' ? 'ok' : asset.readinessTier === 'Blocked' ? 'bad' : 'warn'} />}
    {asset.hndlApplicable && asset.hndlTier && <Badge label={`HNDL: ${asset.hndlTier}`} tone={asset.hndlTier === 'Critical' ? 'bad' : asset.hndlTier === 'High' ? 'warn' : 'neutral'} title={asset.hndlTier === 'Unknown' ? 'Data lifetime is missing' : 'Harvest-now-decrypt-later exposure'} />}
  </div>
);
