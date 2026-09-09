import { FrontendAsset, RiskTier } from './types';
import { computeAssetTier } from './api';

export const riskTiers: RiskTier[] = ['critical', 'high', 'medium', 'low'];
const businessLevels = ['Critical', 'High', 'Medium', 'Low'];

export function buildHeatmapRows(assets: FrontendAsset[]) {
  const levels = assets.some(asset => !businessLevels.includes(asset.businessCriticality || ''))
    ? [...businessLevels, 'Unspecified'] : businessLevels;
  const rows = levels.map(label => ({ label, total: 0, cells: riskTiers.map(tier => ({
    key: `${label}-${tier}`, businessCriticality: label, tier, assets: [] as FrontendAsset[],
  })) }));
  for (const asset of assets) {
    const label = businessLevels.includes(asset.businessCriticality || '') ? asset.businessCriticality : 'Unspecified';
    const row = rows.find(item => item.label === label)!;
    const tier = asset.autoEsc ? 'critical' : asset.tier || computeAssetTier(asset.r ?? (asset.x + asset.y) / (asset.z || 8), false);
    row.cells.find(cell => cell.tier === tier)!.assets.push(asset);
    row.total++;
  }
  return rows;
}
