import React, { useMemo, useState } from 'react';
import { FrontendAsset } from '../types';
import { RangeSlider } from '../components/RangeSlider';
import { RiskChip } from '../components/RiskChip';
import { formatYears } from '../format';
import { buildHeatmapRows, riskTiers } from '../heatmap';

interface HeatmapPageProps {
  assets: FrontendAsset[];
  z: number;
  onZChange: (z: number) => void;
  onSelectAsset?: (assetId: string) => void;
}

export const HeatmapPage: React.FC<HeatmapPageProps> = ({ assets, z, onZChange, onSelectAsset }) => {
  const [selectedCell, setSelectedCell] = useState('');
  const rows = useMemo(() => buildHeatmapRows(assets), [assets]);
  const selected = rows.flatMap(row => row.cells).find(cell => cell.key === selectedCell);
  const criticalCount = assets.filter(asset => asset.tier === 'critical').length;

  return <section className="heatmap-panel" aria-label="Risk heatmap">
    <RangeSlider
      label="Quantum threat timeline (Z)"
      description="Z is the assumed number of years until a quantum computer could break vulnerable cryptography. Use it to compare migration scenarios; it is not a prediction."
      value={z} min={0.5} max={50} step="any" unit="years" onChange={onZChange}
      className="max-w-full"
    />
    <p className="heatmap-summary">At a <b>{formatYears(z)}-year</b> threat timeline, <b className="text-risk-critical">{criticalCount}</b> of {assets.length} assets are Critical.</p>
    <div className="heatmap-heading"><h2>Risk by business criticality</h2><p>Each cell shows an asset count. Select a cell to inspect the findings.</p></div>
    <div className="heatmap-scroll">
      <div className="heatmap-grid" role="group" aria-label="Asset counts by business criticality and risk tier">
        <div className="heatmap-axis">Business<br />criticality ↓</div>
        {riskTiers.map(tier => <div className="heatmap-column" key={tier}><RiskChip tier={tier} /></div>)}
        {rows.map(row => <React.Fragment key={row.label}>
          <div className="heatmap-row-label">{row.label}<small>{row.total} assets</small></div>
          {row.cells.map(cell => <button
            type="button" key={cell.key} className={`heatmap-cell ${cell.assets.length ? `heatmap-${cell.tier}` : 'heatmap-empty'}`}
            disabled={!cell.assets.length} aria-pressed={selectedCell === cell.key}
            aria-label={`${row.label} business criticality, ${cell.tier} risk: ${cell.assets.length} assets`}
            title={`${cell.assets.length} assets; ${cell.assets.filter(asset => asset.autoEsc).length} classically broken and automatically escalated`}
            onClick={() => setSelectedCell(cell.key)}
          ><strong>{cell.assets.length || '—'}</strong><span>{cell.assets.length === 1 ? 'asset' : 'assets'}</span></button>)}
        </React.Fragment>)}
      </div>
    </div>
    <p className="heatmap-note">Columns show the assessed risk tier. Known classically broken algorithms stay Critical at every timeline. X is data confidentiality lifetime; Y is migration duration. Urgency ratio r = (X + Y) / Z.</p>
    {selected && <section className="heatmap-selection" aria-label="Selected heatmap assets">
      <div className="flex items-center justify-between gap-3 mb-3"><h3>{selected.businessCriticality} business criticality · {selected.tier} risk</h3><button type="button" className="text-xs text-ink-soft underline" onClick={() => setSelectedCell('')}>Clear selection</button></div>
      {selected.assets.length ? <div className="heatmap-assets">{selected.assets.map((asset, index) => <button type="button" key={asset.id || index} onClick={() => onSelectAsset?.(asset.id || asset.name)}>
        <div><b>{asset.name}</b><span>{asset.loc}</span><small>X: {formatYears(asset.x)} years · Y: {formatYears(asset.y)} years · r: {(asset.r ?? (asset.x + asset.y) / z).toFixed(2)}</small></div>
        <RiskChip tier={selected.tier} />
      </button>)}</div> : <p className="text-sm text-ink-soft">No assets remain in this cell at the selected timeline.</p>}
    </section>}
  </section>;
};
