import React, { useEffect, useState } from 'react';
import { FrontendAsset, AssetDetailResponse } from '../types';
import { RiskChip } from '../components/RiskChip';
import { AssessmentBadges } from '../components/AssessmentBadges';
import { MigrationPlan } from '../components/MigrationPlan';
import { ReadinessBreakdown } from '../components/ReadinessBreakdown';
import { formatYears } from '../format';
import { fetchAssetDetail, updateAssetContext, mapBackendAssetToFrontend } from '../api';

interface AssetDetailPageProps {
  asset: FrontendAsset;
  z: number;
  allAssets?: FrontendAsset[];
  onSelectAsset?: (name: string) => void;
  onAssetUpdated?: (asset: FrontendAsset) => void;
}

const USAGE_OPTIONS = [
  'unknown', 'encryption', 'signing', 'token-signing', 'firmware-signing', 'hashing',
  'integrity', 'password-storage', 'key-establishment', 'transport', 'key-management',
  'certificate', 'data-protection',
];
const ARTIFACT_OPTIONS = ['algorithm', 'certificate', 'protocol', 'library', 'hardware-module', 'cloud-service', 'key-reference'];

export const AssetDetailPage: React.FC<AssetDetailPageProps> = ({
  asset,
  z,
  allAssets = [],
  onSelectAsset,
  onAssetUpdated,
}) => {
  const [detail, setDetail] = useState<AssetDetailResponse | null>(null);
  const [refreshed, setRefreshed] = useState<FrontendAsset | null>(null);
  const [usage, setUsage] = useState(asset.usageContext || 'unknown');
  const [artifact, setArtifact] = useState(asset.artifactType || 'algorithm');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');

  const assetId = asset.id;

  useEffect(() => {
    let live = true;
    setRefreshed(null);
    setDetail(null);
    if (!assetId) return;
    fetchAssetDetail(assetId)
      .then(result => {
        if (!live) return;
        setDetail(result);
        setRefreshed(mapBackendAssetToFrontend(result.asset));
      })
      .catch(() => undefined);
    return () => { live = false; };
  }, [assetId]);

  const shown = refreshed ?? asset;

  useEffect(() => {
    setUsage(shown.usageContext || 'unknown');
    setArtifact(shown.artifactType || 'algorithm');
  }, [shown.usageContext, shown.artifactType]);

  const r = (shown.x + shown.y) / z;
  const isCritical = shown.autoEsc || r >= 1.2;
  const tier = shown.tier || (isCritical ? 'critical' : (r >= 0.9 ? 'high' : (r >= 0.6 ? 'medium' : 'low')));

  async function saveContext() {
    if (!assetId) return;
    setSaving(true); setSaveError('');
    try {
      const result = await updateAssetContext(assetId, {
        usageContext: usage,
        artifactType: artifact as 'algorithm' | 'certificate' | 'protocol',
      });
      const mapped = mapBackendAssetToFrontend(result.asset);
      setDetail(result);
      setRefreshed(mapped);
      onAssetUpdated?.(mapped);
    } catch (error) {
      setSaveError((error as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      {/* Asset Selector Dropdown if multiple exist */}
      {allAssets.length > 1 && (
        <div className="mb-5 flex flex-col md:flex-row md:items-center gap-3">
          <label htmlFor="asset-selector" className="text-[12.5px] text-ink-soft">Select asset to inspect:</label>
          <select
            id="asset-selector"
            value={shown.id || shown.name}
            onChange={(e) => onSelectAsset?.(e.target.value)}
            className="min-w-0 w-full md:flex-1 font-sans text-[13px] py-1 px-2 border border-border-strong rounded-sm bg-surface text-ink focus:border-cipher outline-none"
          >
            {allAssets.map((a) => (
              <option key={a.id || a.name} value={a.id || a.name}>
                {a.name} — {a.loc}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Detail Head */}
      <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
        <div>
          <h2 className="text-[17px] font-semibold text-ink">{shown.name}</h2>
          <p className="text-[12.5px] font-mono text-ink-soft mt-1 break-all">{shown.loc}</p>
        </div>
        <RiskChip tier={tier} />
      </div>
      <AssessmentBadges asset={shown} />

      {/* Ratio Callout */}
      <div
        className={`flex flex-col md:flex-row items-start md:items-center gap-4 justify-between p-4 rounded-md mt-5 mb-5 border border-transparent ${
          isCritical
            ? 'bg-risk-critical-bg text-risk-critical'
            : (tier === 'high' ? 'bg-risk-high-bg text-risk-high' : 'bg-paper text-ink')
        }`}
      >
        <div>
          <div className="text-[12.5px] font-medium opacity-85">Mosca's inequality: X + Y &gt; Z</div>
          <div className="text-[13px] mt-[2px]">
            {formatYears(shown.x)} yrs shelf-life + {formatYears(shown.y)} yrs migration{' '}
            {shown.x + shown.y > z ? '>' : '≤'} {formatYears(z)} yr threat timeline —{' '}
            {shown.autoEsc
              ? 'Classically broken primitive, immediate deprecation required.'
              : (shown.x + shown.y > z ? 'past the threshold, migrate now.' : 'within safety threshold.')}
          </div>
        </div>
        <div className="font-mono text-[20px] font-semibold">
          r = {r.toFixed(2)}
        </div>
      </div>

      {/* Breakdown Grid: X, Y, Z */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-5">
        <div className="border border-border rounded-md p-4 text-center bg-surface">
          <div className="text-[11px] text-ink-faint">X · shelf-life</div>
          <div className="text-[22px] font-semibold mt-[6px] font-mono text-ink">{formatYears(shown.x)} yrs</div>
          <p className="text-xs text-ink-soft mt-2">How long the data must remain confidential.</p>
        </div>
        <div className="border border-border rounded-md p-4 text-center bg-surface">
          <div className="text-[11px] text-ink-faint">Y · migration time</div>
          <div className="text-[22px] font-semibold mt-[6px] font-mono text-ink">{formatYears(shown.y)} yrs</div>
          <p className="text-xs text-ink-soft mt-2">Estimated time needed to complete migration.</p>
        </div>
        <div className="border border-border rounded-md p-4 text-center bg-surface">
          <div className="text-[11px] text-ink-faint">Z · threat timeline</div>
          <div className="text-[22px] font-semibold mt-[6px] font-mono text-ink">{formatYears(z)} yrs</div>
          <p className="text-xs text-ink-soft mt-2">Assumed time until a relevant quantum threat.</p>
        </div>
      </div>

      {/* Recommendation Card */}
      <div className="border border-border rounded-md p-5 bg-surface">
        <h3 className="text-[13px] font-semibold text-ink mb-3">Recommended replacement</h3>
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-4 my-4">
          <div className="flex-1 border border-border rounded-sm p-3 bg-surface">
            <div className="text-[11px] text-ink-faint">Current</div>
            <div className="font-mono text-[14px] mt-1 text-ink">{shown.algo}</div>
          </div>
          <div className="text-ink-faint text-[18px] text-center">→</div>
          <div className="flex-1 border border-qubit rounded-sm p-3 bg-qubit-soft">
            <div className="text-[11px] text-ink-faint">Recommended</div>
            <div className="font-mono text-[14px] mt-1 text-qubit font-semibold">{shown.rec}</div>
          </div>
        </div>
        <div className="flex gap-6 mt-4 text-[12.5px] text-ink-soft flex-wrap">
          <span>
            Complexity: <b className="text-ink font-medium">{shown.complexity}</b>
          </span>
          <span>
            Standard: <b className="text-ink font-medium">{shown.std}</b>
          </span>
          {shown.sizeDelta && (
            <span>
              Size delta: <b className="text-ink font-medium">{shown.sizeDelta}</b>
            </span>
          )}
        </div>

        <div className="border-t border-border mt-4 pt-4">
          <div className="text-[11px] text-ink-faint uppercase tracking-wide mb-2">Confirm how this asset is used</div>
          <div className="flex gap-3 flex-wrap items-end">
            <label className="text-[12px] text-ink-soft">Usage
              <select value={usage} disabled={saving} onChange={e => setUsage(e.target.value)} className="block mt-1 border border-border rounded-sm p-1.5 bg-surface text-ink">
                {USAGE_OPTIONS.map(option => <option key={option} value={option}>{option}</option>)}
              </select>
            </label>
            <label className="text-[12px] text-ink-soft">Artifact
              <select value={artifact} disabled={saving} onChange={e => setArtifact(e.target.value)} className="block mt-1 border border-border rounded-sm p-1.5 bg-surface text-ink">
                {ARTIFACT_OPTIONS.map(option => <option key={option} value={option}>{option}</option>)}
              </select>
            </label>
            <button type="button" disabled={saving || !assetId} onClick={() => void saveContext()} className="text-[12.5px] py-1.5 px-3 rounded-md border border-border-strong bg-surface text-ink hover:border-ink-faint disabled:opacity-50">
              {saving ? 'Re-planning…' : 'Re-plan migration'}
            </button>
          </div>
          {saveError && <p role="alert" className="text-[12px] text-risk-critical mt-2">{saveError}</p>}
        </div>
      </div>

      <ReadinessBreakdown asset={shown} />
      <MigrationPlan asset={shown} />

      {!!detail?.relationships?.length && (
        <div className="border border-border rounded-md p-4 bg-surface mt-5">
          <h3 className="text-[13px] font-semibold text-ink mb-2">Related assets</h3>
          <ul className="text-[12.5px] text-ink-soft space-y-1">
            {detail.relationships.map(rel => (
              <li key={rel.bomRef}>
                <button className="asset-link" onClick={() => onSelectAsset?.(rel.bomRef)}>{rel.name}</button>
                <span className="text-ink-faint"> · {rel.artifactType || 'asset'} · {rel.relation}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
