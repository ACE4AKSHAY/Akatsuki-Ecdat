import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Screen, FrontendAsset, ScanResponse } from './types';
import { computeAllAssetsWithZ, fetchLiveAssets, fetchScans, fetchScan, startScan, uploadScan, setAccessToken, deleteScan, deleteAllScans } from './api';
import { targetName } from './format';
import { AppShell } from './components/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { InventoryPage } from './pages/InventoryPage';
import { HeatmapPage } from './pages/HeatmapPage';
import { AssetDetailPage } from './pages/AssetDetailPage';
import { RecommendationsPage } from './pages/RecommendationsPage';
import { Button } from './components/Button';
import { Input } from './components/Input';
import { FolderOpen, ArrowRight, LoaderCircle, Trash2 } from 'lucide-react';

export const App: React.FC = () => {
  const [screen, setScreen] = useState<Screen>('overview');
  const [z, setZ] = useState(8);
  const [rawAssets, setAssets] = useState<FrontendAsset[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [source, setSource] = useState<'path' | 'git' | 'upload' | 'image'>('path');
  const [file, setFile] = useState<File | null>(null);
  const [tokenInput, setTokenInput] = useState('');
  const [target, setTarget] = useState('seed_corpus');
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [active, setActive] = useState<ScanResponse | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [connected, setConnected] = useState(false);
  const [historyNotice, setHistoryNotice] = useState('');
  const generation = useRef(0);
  const assets = useMemo(() => computeAllAssetsWithZ(rawAssets, z), [rawAssets, z]);
  const selected = assets.find(a => (a.id || a.name) === selectedId) || assets[0];
  const selectAsset = (id: string) => { setSelectedId(id); setScreen('detail'); };

  function showScan(scan: ScanResponse) {
    setActive(scan);
    setScans(history => history.some(item => item.scanId === scan.scanId)
      ? history.map(item => item.scanId === scan.scanId ? scan : item)
      : [scan, ...history]);
  }

  async function loadScan(scan: ScanResponse, token: number) {
    if (token !== generation.current) return;
    setAssets([]); showScan(scan);
    let current = scan;
    while (current.status === 'queued' || current.status === 'running') {
      await new Promise(resolve => setTimeout(resolve, 800));
      if (token !== generation.current) return;
      current = await fetchScan(scan.scanId);
      if (token !== generation.current) return;
      showScan(current);
    }
    if (current.status === 'failed') throw new Error(current.error || 'Scan failed.');
    const fresh = await fetchLiveAssets(current.scanId);
    if (token !== generation.current) return;
    setAssets(fresh); setZ(fresh[0]?.z ?? 8); setConnected(true);
    const history = await fetchScans();
    if (token === generation.current) setScans(history);
  }
  async function refresh() {
    const token = ++generation.current;
    setBusy(true); setError('');
    try {
      const history = await fetchScans();
      if (token !== generation.current) return;
      setScans(history); setConnected(true);
      if (history.length) await loadScan(history[0], token);
      else { setActive(null); setAssets([]); setSelectedId(''); }
    } catch (e) { if (token === generation.current) setError((e as Error).message); }
    finally { if (token === generation.current) setBusy(false); }
  }
  useEffect(() => { void refresh(); return () => { generation.current++; }; }, []);
  async function trigger(event: React.FormEvent) {
    event.preventDefault();
    const token = ++generation.current;
    setBusy(true); setError('');
    try { await loadScan(await (file && (source === 'upload' || source === 'image') ? uploadScan(file, source === 'image' ? 'image' : 'upload') : startScan(target, source === 'upload' ? 'path' : source)), token); }
    catch (e) { setError((e as Error).message); }
    finally { if (token === generation.current) setBusy(false); }
  }
  async function chooseScan(id: string) {
    const scan = scans.find(s => s.scanId === id); if (!scan) return;
    const token = ++generation.current; setBusy(true); setError('');
    try { await loadScan(scan, token); }
    catch (e) { setError((e as Error).message); }
    finally { if (token === generation.current) setBusy(false); }
  }
  async function removeHistory(all: boolean) {
    if (!all && !active) return;
    const selectedScanId = active?.scanId;
    const description = all ? `all ${scans.length} saved scans` : `the selected scan (${targetName(active!.target)})`;
    if (!window.confirm(`Delete ${description}? Saved findings and reports will be removed. Source files, uploaded input copies and downloaded reports will be kept. This cannot be undone.`)) return;
    const token = ++generation.current;
    setBusy(true); setError(''); setHistoryNotice('');
    try {
      const result = all ? await deleteAllScans() : await deleteScan(selectedScanId!);
      setActive(null); setAssets([]); setSelectedId('');
      setScans(history => all ? [] : history.filter(scan => scan.scanId !== selectedScanId));
      setHistoryNotice(`${result.deletedCount} ${result.deletedCount === 1 ? 'scan deleted' : 'scans deleted'}.`);
      const history = await fetchScans();
      if (token !== generation.current) return;
      setScans(history);
      if (history.length) await loadScan(history.find(scan => scan.status === 'completed') || history[0], token);
      else { setScreen('overview'); setZ(8); }
    } catch (e) { if (token === generation.current) setError((e as Error).message); }
    finally { if (token === generation.current) setBusy(false); }
  }
  return <AppShell currentScreen={screen} onScreenChange={setScreen} criticalCount={assets.filter(a => a.tier === 'critical').length} scanTargetName={active?.target}>
    <form className="scan-panel" onSubmit={trigger}>
      <div className="flex items-center gap-3"><FolderOpen size={22} className="text-qubit" /><div><h2>Start a discovery scan</h2><p>Scan code, configurations and artifacts to discover cryptographic assets.</p></div></div>
      <div className="flex gap-3 flex-wrap mt-4 items-center"><label>Input type <select aria-label="Input type" value={source} disabled={busy} onChange={e => { setSource(e.target.value as typeof source); setFile(null); }} className="border border-border rounded-md p-2 ml-2 bg-surface"><option value="path">Local path</option><option value="git">Git repository</option><option value="upload">File or ZIP upload</option><option value="image">Container image or SBOM</option></select></label>
      {(source === 'upload' || source === 'image') && <input key={source} aria-label="Upload scan input" type="file" accept={source === 'image' ? '.json' : undefined} disabled={busy} onChange={e => setFile(e.target.files?.[0] || null)} className="max-w-full" />}</div>
      <div className="scan-controls"><Input aria-label="Scan target" value={target} onChange={e => setTarget(e.target.value)} placeholder="Local file or directory path" disabled={busy || source === 'upload'} /><Button type="submit" disabled={busy || (source === 'upload' ? !file : !file && !target.trim())}>{busy ? <LoaderCircle size={17} className="animate-spin" /> : <ArrowRight size={17} />}{busy ? 'Scanning / loading…' : 'Start scan'}</Button></div>
    </form>
    <details className="mt-3 text-sm text-ink-soft"><summary className="cursor-pointer">Workspace access token</summary><div className="flex gap-2 mt-2"><input aria-label="Workspace access token" type="password" autoComplete="off" value={tokenInput} onChange={e => setTokenInput(e.target.value)} placeholder="Only needed when token protection is enabled" className="min-w-0 flex-1 border border-border rounded-md p-2" /><Button type="button" disabled={busy} onClick={() => { setAccessToken(tokenInput); void refresh(); }}>Connect</Button></div><p className="text-xs mt-1">Held in memory for this tab; re-enter after a reload.</p></details>
    <div className="workspace-status">
      <span role="status">{busy ? `${active?.status || 'Connecting'}${active && active.status !== 'completed' ? ` · ${active.progress}%` : ''}` : error ? 'Action needed' : active ? `${assets.length} assets · ${active.status}` : connected ? 'Connected · ready for your first scan' : 'Disconnected'}</span>
      {scans.length > 0 && <div className="history-controls"><label>Scan history <select aria-label="Scan history" disabled={busy} value={active?.scanId || ''} onChange={e => void chooseScan(e.target.value)}>{scans.map(s => <option key={s.scanId} value={s.scanId}>{targetName(s.target)} · {s.status} · {new Date(s.createdAt.endsWith('Z') ? s.createdAt : s.createdAt + 'Z').toLocaleString()}</option>)}</select></label>
        <button type="button" className="history-delete" disabled={busy || !active || ['queued', 'running'].includes(active.status)} onClick={() => void removeHistory(false)}><Trash2 size={14} />Delete selected</button>
        <button type="button" className="history-delete" disabled={busy || scans.some(scan => ['queued', 'running'].includes(scan.status))} onClick={() => void removeHistory(true)}>Delete all</button>
      </div>}
    </div>
    {historyNotice && <p aria-live="polite" className="text-xs text-ink-soft mb-3">{historyNotice}</p>}
    {error && <div role="alert" className="error-panel">{error}<Button variant="secondary" onClick={() => void refresh()} disabled={busy}>Retry connection</Button></div>}
    {screen === 'overview' && <OverviewPage assets={assets} scansCount={scans.filter(s => s.status === 'completed').length} onSelectAsset={selectAsset} />}
    {!busy && !error && !assets.length && <div className="empty-state"><FolderOpen size={30} /><h2>{active ? 'No cryptographic assets found' : 'Your inventory starts here'}</h2><p>{active ? 'This scan completed with zero findings. Choose another local target to continue.' : 'Start with seed_corpus, the repository’s test workspace, or enter your own local path.'}</p></div>}
    {screen === 'inventory' && <InventoryPage assets={assets} onSelectAsset={selectAsset} />}
    {screen === 'heatmap' && <HeatmapPage assets={assets} z={z} onZChange={setZ} onSelectAsset={selectAsset} />}
    {screen === 'detail' && selected && <AssetDetailPage asset={selected} z={z} allAssets={assets} onSelectAsset={setSelectedId} />}
    {screen === 'recommend' && active?.status === 'completed' && <RecommendationsPage assets={assets} scanId={active.scanId} onSelectAsset={selectAsset} />}
  </AppShell>;
};
