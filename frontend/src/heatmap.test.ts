import { describe, expect, it } from 'vitest';
import { buildHeatmapRows } from './heatmap';
import { formatYears, targetName } from './format';
import { computeAllAssetsWithZ, mapBackendAssetToFrontend } from './api';

describe('year presentation', () => {
  it.each([[48.556781572165, '48.56'], [7.5, '7.5'], [8, '8'], [0.5, '0.5'], [1.999, '2']])('displays %s with at most two decimals', (value, expected) => {
    expect(formatYears(Number(value))).toBe(expected);
  });
  it('shows a Windows workspace name without the full path', () => {
    expect(targetName('C:\\Users\\Demo User\\project')).toBe('project');
    expect(targetName('/Users/demo/project/')).toBe('project');
  });
});

describe('heatmap grouping', () => {
  const item = mapBackendAssetToFrontend({name:'RSA',ecdatEnrichment:{businessCriticality:'Medium',moscaX:5,moscaY:1,moscaZ:8}});
  it('keeps all overlapping assets accessible in one counted cell', () => {
    const assets = computeAllAssetsWithZ(Array.from({length:44}, (_,index)=>({...item,id:String(index)})),8);
    const rows = buildHeatmapRows(assets);
    const cells = rows.flatMap(row=>row.cells);
    expect(cells.flatMap(cell=>cell.assets)).toHaveLength(44);
    expect(cells.find(cell=>cell.key==='Medium-medium')!.assets).toHaveLength(44);
  });
  it('updates cells after a timeline change while preserving auto-escalation', () => {
    const assets = [{...item,id:'broken',autoEsc:true},{...item,id:'ordinary'}];
    const cells = buildHeatmapRows(computeAllAssetsWithZ(assets,50)).flatMap(row=>row.cells);
    expect(cells.find(cell=>cell.key==='Medium-critical')!.assets.map(a=>a.id)).toEqual(['broken']);
    expect(cells.find(cell=>cell.key==='Medium-low')!.assets.map(a=>a.id)).toEqual(['ordinary']);
  });
  it('keeps assets with missing business criticality in an explicit row', () => {
    const rows=buildHeatmapRows([{...item,businessCriticality:undefined}]);
    expect(rows.find(row=>row.label==='Unspecified')!.total).toBe(1);
  });
});
