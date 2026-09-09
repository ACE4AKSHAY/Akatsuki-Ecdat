import { FrontendAsset, AssetSummaryResponse, ScanResponse, RiskTier } from './types';

export function computeAssetTier(r: number, autoEsc: boolean): RiskTier {
  if (autoEsc) return 'critical';
  if (r >= 1.2) return 'critical';
  if (r >= 0.9) return 'high';
  if (r >= 0.6) return 'medium';
  return 'low';
}

export function computeAllAssetsWithZ(assets: FrontendAsset[], z: number): FrontendAsset[] {
  return assets.map(a => {
    const r = Number(((a.x + a.y) / (z > 0 ? z : 8.0)).toFixed(4));
    const tier = computeAssetTier(r, a.autoEsc);
    return { ...a, r, tier };
  });
}

// Map backend canonical asset to FrontendAsset
export function mapBackendAssetToFrontend(backendItem: any): FrontendAsset {
  const enc = backendItem.ecdatEnrichment || {};
  const cp = backendItem.cryptoProperties || {};
  const occ = (backendItem.occurrences && backendItem.occurrences[0]) || {};

  return {
    id: backendItem['bom-ref'] || backendItem.id,
    name: backendItem.name || 'Cryptographic Asset',
    type: cp.assetType === 'algorithm' ? 'Algorithm' : (cp.assetType === 'certificate' ? 'Certificate' : 'Protocol'),
    algo: backendItem.name,
    rec: enc.recommendedReplacement || 'Review required',
    std: enc.referenceStandard || '—',
    complexity: enc.migrationComplexity || 'Medium',
    loc: occ.location ? `${occ.location}${occ.line ? `:${occ.line}` : ''}` : 'Unknown location',
    bu: enc.dataClassification || 'Unclassified',
    x: enc.moscaX ?? 5.0,
    y: enc.moscaY ?? 1.0,
    z: enc.moscaZ ?? 8.0,
    autoEsc: enc.autoEscalated ?? false,
    quantumVulnerable: enc.quantumVulnerable ?? true,
    businessCriticality: enc.businessCriticality || 'High',
    exposure: enc.exposure || 'internal-only',
    vulnerabilityReason: enc.vulnerabilityReason,
    sizeDelta: enc.relativeSizeDelta,
  };
}

const API_BASE = '/api';
let accessToken = '';
export function setAccessToken(value: string) { accessToken = value; }
function authorizationHeaders(): Record<string, string> { return accessToken ? { Authorization: `Bearer ${accessToken}` } : {}; }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  Object.entries(authorizationHeaders()).forEach(([name, value]) => headers.set(name, value));
  let res: Response;
  try { res = await fetch(`${API_BASE}${path}`, { ...init, headers, signal: AbortSignal.timeout(15000) }); }
  catch { throw new Error('Cannot reach the backend. Check that the API is running and try again.'); }
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = body?.detail;
    throw new Error(typeof detail === 'string' ? detail : `Request failed (HTTP ${res.status}).`);
  }
  return res.json();
}

export async function fetchLiveAssets(scanId: string, z?: number): Promise<FrontendAsset[]> {
  const assets: FrontendAsset[] = [];
  let page = 1;
  let pages = 1;
  do {
    const params = new URLSearchParams({ scanId, page: String(page), pageSize: '200' });
    if (z !== undefined) params.set('z', String(z));
    const data = await request<AssetSummaryResponse>(`/assets?${params}`);
    assets.push(...data.items.map(mapBackendAssetToFrontend));
    pages = data.pages;
    page++;
  } while (page <= pages);
  return assets;
}

export async function fetchScans(): Promise<ScanResponse[]> {
  const scans: ScanResponse[] = [];
  let page: ScanResponse[];
  do {
    page = await request<ScanResponse[]>(`/scans?limit=200&offset=${scans.length}`);
    scans.push(...page);
  } while (page.length === 200);
  return scans;
}
export const fetchScan = (id: string) => request<ScanResponse>(`/scans/${encodeURIComponent(id)}`);
export const deleteScan = (id: string) => request<{ deletedCount: number }>(`/scans/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const deleteAllScans = () => request<{ deletedCount: number }>('/scans', { method: 'DELETE' });
export const startScan = (target: string, sourceType: 'path' | 'git' | 'image' = 'path') => request<ScanResponse>('/scans', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ target: target.trim(), sourceType }),
});
export const downloadReportUrl = (id: string, format: 'pdf' | 'csv' | 'xlsx' | 'json') =>
  `${API_BASE}/reports/${encodeURIComponent(id)}?format=${format}`;
export const downloadCBOMUrl = (id: string) => `${API_BASE}/cbom/${encodeURIComponent(id)}`;

export function uploadScan(file: File, sourceType: 'upload' | 'image' = 'upload') {
  const data = new FormData(); data.append('file', file); data.append('sourceType', sourceType);
  return request<ScanResponse>('/scans/upload', { method: 'POST', body: data });
}
export async function downloadExport(url: string) {
  const response = await fetch(url, { headers: authorizationHeaders(), signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error('Export failed. Check your access token and scan status.');
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = objectUrl;
  a.download = response.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1] || 'ecdat-report';
  a.click(); setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}
