import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchLiveAssets, fetchScans, startScan, computeAssetTier, computeAllAssetsWithZ, mapBackendAssetToFrontend, downloadReportUrl, setAccessToken, uploadScan } from './api';
afterEach(() => { setAccessToken(''); vi.unstubAllGlobals(); });
describe('backend integration', () => {
  it('keeps empty results empty', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ok:true,json:async () => ({items:[],pages:1})}));
    expect(await fetchLiveAssets('empty')).toEqual([]);
  });
  it('loads every inventory page', async () => {
    const fetch = vi.fn().mockResolvedValueOnce({ok:true,json:async () => ({items:[{name:'RSA', 'bom-ref':'a'}],pages:2})}).mockResolvedValueOnce({ok:true,json:async () => ({items:[{name:'RSA', 'bom-ref':'b'}],pages:2})});
    vi.stubGlobal('fetch', fetch);
    expect((await fetchLiveAssets('scan')).map(a => a.id)).toEqual(['a','b']);
    expect(fetch.mock.calls[1][0]).toContain('page=2');
  });
  it('surfaces connection failures instead of sample assets', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    await expect(fetchScans()).rejects.toThrow('Cannot reach');
    await expect(fetchLiveAssets('scan')).rejects.toThrow('Cannot reach');
  });
  it('surfaces invalid scan targets', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ok:false,status:422,json:async () => ({detail:'Target missing'})}));
    await expect(startScan('missing')).rejects.toThrow('Target missing');
  });
  it('uses the namespaced API for exports', () => {
    expect(downloadReportUrl('scan/id','pdf')).toBe('/api/reports/scan%2Fid?format=pdf');
  });
  it('preserves location and classification without inventing business units', () => {
    const a = mapBackendAssetToFrontend({name:'SHA-1','bom-ref':'one',occurrences:[{location:'auth.py',line:2}],ecdatEnrichment:{dataClassification:'General',moscaZ:12}});
    expect(a.loc).toBe('auth.py:2'); expect(a.bu).toBe('General'); expect(a.z).toBe(12);
  });
});
describe('risk parity', () => {
  it.each([[.5999,'low'],[.6,'medium'],[.9,'high'],[1.2,'critical']])('maps %s to %s', (r,tier) => expect(computeAssetTier(Number(r),false)).toBe(tier));
  it('preserves escalation and rounds ratios like the API', () => {
    const a=mapBackendAssetToFrontend({name:'MD5',ecdatEnrichment:{moscaX:5,moscaY:.25,autoEscalated:true}});
    const result=computeAllAssetsWithZ([a],20)[0];
    expect(result.tier).toBe('critical'); expect(result.r).toBe(.2625);
  });
});

describe('new input and access modes', () => {
  it('sends the selected Git source type', async () => {
    const fetch=vi.fn().mockResolvedValue({ok:true,json:async()=>({scanId:'git'})}); vi.stubGlobal('fetch',fetch);
    await startScan('https://github.com/example/project','git');
    expect(JSON.parse(fetch.mock.calls[0][1].body).sourceType).toBe('git');
  });
  it('attaches the workspace token to API calls', async () => {
    const fetch=vi.fn().mockResolvedValue({ok:true,json:async()=>[]}); vi.stubGlobal('fetch',fetch);
    setAccessToken('test-only'); await fetchScans();
    expect(fetch.mock.calls[0][1].headers.get('Authorization')).toBe('Bearer test-only');
  });
  it('uploads image inventories as multipart data', async () => {
    const fetch=vi.fn().mockResolvedValue({ok:true,json:async()=>({scanId:'image'})}); vi.stubGlobal('fetch',fetch);
    await uploadScan(new File(['{}'],'image.json'), 'image');
    expect(fetch.mock.calls[0][0]).toBe('/api/scans/upload');
    expect(fetch.mock.calls[0][1].body.get('sourceType')).toBe('image');
  });
});
