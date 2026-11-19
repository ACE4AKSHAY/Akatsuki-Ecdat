import React from 'react';
import { FrontendAsset } from '../types';

export const ReadinessBreakdown: React.FC<{ asset: FrontendAsset }> = ({ asset }) => {
  const components = Object.entries(asset.readinessComponents || {});
  const facts = asset.certificateFacts;

  if (!components.length && !facts) return null;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
      {components.length > 0 && (
        <div className="border border-border rounded-md p-4 bg-surface">
          <div className="flex items-baseline justify-between">
            <h3 className="text-[13px] font-semibold text-ink">Migration readiness</h3>
            <span className="font-mono text-[13px] text-ink">{asset.readinessScore ?? '—'}/100</span>
          </div>
          <div className="mt-3 space-y-2">
            {components.map(([key, part]) => (
              <div key={key}>
                <div className="flex justify-between text-[11.5px] text-ink-soft">
                  <span>{part.label}</span>
                  <span className="font-mono">{part.score}/{part.maximum}</span>
                </div>
                <div className="risk-track mt-1">
                  <div style={{ width: `${(part.score / Math.max(part.maximum, 1)) * 100}%`, background: part.score === part.maximum ? 'var(--risk-low)' : part.score === 0 ? 'var(--risk-critical)' : 'var(--risk-medium)' }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {facts && (
        <div className="border border-border rounded-md p-4 bg-surface">
          <h3 className="text-[13px] font-semibold text-ink">Certificate facts</h3>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 mt-3 text-[12px]">
            {facts.subject && <><dt className="text-ink-faint">Subject</dt><dd className="text-ink font-mono break-all">{facts.subject}</dd></>}
            {facts.issuer && <><dt className="text-ink-faint">Issuer</dt><dd className="text-ink font-mono break-all">{facts.issuer}</dd></>}
            {facts.notAfter && <><dt className="text-ink-faint">Not after</dt><dd className="text-ink font-mono">{facts.notAfter}{facts.daysToExpiry !== undefined ? ` · ${facts.daysToExpiry}d` : ''}</dd></>}
            {facts.keyAlgorithm && <><dt className="text-ink-faint">Key</dt><dd className="text-ink">{facts.keyAlgorithm}{facts.keySizeBits ? ` ${facts.keySizeBits} bits` : ''}</dd></>}
            {facts.signatureAlgorithm && <><dt className="text-ink-faint">Signature</dt><dd className="text-ink">{facts.signatureAlgorithm}</dd></>}
            <dt className="text-ink-faint">Self-signed</dt><dd className="text-ink">{facts.selfSigned ? 'Yes' : 'No'}</dd>
            {facts.sanCount !== undefined && <><dt className="text-ink-faint">SANs</dt><dd className="text-ink">{facts.sanCount}</dd></>}
          </dl>
        </div>
      )}
    </div>
  );
};
