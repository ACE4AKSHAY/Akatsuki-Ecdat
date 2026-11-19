import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchLiveAssets, fetchScans, startScan, computeAssetTier, computeAllAssetsWithZ, mapBackendAssetToFrontend, downloadReportUrl, setAccessToken, uploadScan, fetchAssetDetail, updateAssetContext, fetchRoadmap } from './api';
afterEach(() => { setAccessToken(''); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });
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
describe('migration assessment', () => {
  it('maps assessment, readiness and playbook fields', () => {
    const a = mapBackendAssetToFrontend({
      name: 'RSA-2048', 'bom-ref': 'rsa-1',
      ecdatEnrichment: {
        usageContext: 'key-establishment', artifactType: 'algorithm',
        migrationAction: 'hybridize', migrationPhase: 'transition',
        classicalStatus: 'acceptable', quantumStatus: 'vulnerable',
        standardsMaturity: 'final', readinessTier: 'Partial', readinessScore: 42,
        hndlApplicable: true, hndlTier: 'High',
        candidates: [{ id: 'x25519mlkem768', label: 'X25519MLKEM768', fit: 'preferred' }],
        playbook: [{ order: 1, phase: 'prepare', action: 'Inventory endpoints' }],
        blockers: ['Library version must be verified.'],
      },
    });
    expect(a.action).toBe('hybridize');
    expect(a.phase).toBe('transition');
    expect(a.readinessScore).toBe(42);
    expect(a.hndlTier).toBe('High');
    expect(a.candidates?.[0].id).toBe('x25519mlkem768');
    expect(a.playbook?.[0].order).toBe(1);
    expect(a.blockers).toContain('Library version must be verified.');
  });
  it('loads detail and patches context on namespaced routes', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ asset: { name: 'RSA', ecdatEnrichment: {} }, moscaBreakdown: {}, recommendation: {}, assessment: {}, strategy: {}, relationships: [] }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ asset: { name: 'RSA', ecdatEnrichment: { usageContext: 'signing' } }, moscaBreakdown: {}, recommendation: {}, assessment: {}, strategy: {}, relationships: [] }) });
    vi.stubGlobal('fetch', fetch);
    await fetchAssetDetail('asset/1');
    await updateAssetContext('asset/1', { usageContext: 'signing' });
    expect(fetch.mock.calls[0][0]).toContain('/api/assets/asset%2F1');
    expect(fetch.mock.calls[1][0]).toBe('/api/assets/asset%2F1/context');
    expect(fetch.mock.calls[1][1].method).toBe('PATCH');
    expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ usageContext: 'signing' });
  });
  it('fetches a scan roadmap', async () => {
    const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ scanId: 'scan/1', phases: [], total: 0, summary: {} }) });
    vi.stubGlobal('fetch', fetch);
    await fetchRoadmap('scan/1');
    expect(fetch.mock.calls[0][0]).toBe('/api/roadmap/scan%2F1');
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
  it('allows a slow upload to finish beyond the normal API deadline', async () => {
    vi.useFakeTimers();
    vi.spyOn(AbortSignal, 'timeout').mockImplementation(ms => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), ms);
      return controller.signal;
    });
    vi.stubGlobal('fetch', vi.fn((_url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('timeout')));
      setTimeout(() => resolve({ ok: true, json: async () => ({ scanId: 'large-upload' }) }), 30000);
    })));
    const result = uploadScan(new File(['fixture'], 'workspace.zip')).catch(error => error);
    await vi.advanceTimersByTimeAsync(30000);
    expect(await result).toEqual({ scanId: 'large-upload' });
  });
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
