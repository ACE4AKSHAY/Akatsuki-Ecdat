"""Repeatable demo against a running local API; no scanned code is executed."""
import argparse
import json
import os
from pathlib import Path
import time
import httpx

parser = argparse.ArgumentParser()
parser.add_argument('--api', default='http://127.0.0.1:8000')
parser.add_argument('--output', default='demo-results')
parser.add_argument('--git', action='store_true', help='Also scan the original public GitHub repository')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = Path(args.output).resolve(); out.mkdir(parents=True, exist_ok=True)
token = os.getenv('ECDAT_API_TOKEN')
headers = {'Authorization': f'Bearer {token}'} if token else {}
with httpx.Client(base_url=args.api, headers=headers, timeout=30) as client:
    cases = [('workspace', {'sourceType':'path','target':str(root/'demo/workspace')}),
             ('image', {'sourceType':'image','target':str(root/'demo/image-inventory.json')})]
    if args.git:
        cases.append(('git', {'sourceType':'git','target':'https://github.com/ACE4AKSHAY/Akatsuki-Ecdat'}))
    results = []
    for label, payload in cases:
        response = client.post('/scans', json=payload); response.raise_for_status()
        item = response.json(); deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            response = client.get(f"/scans/{item['scanId']}"); response.raise_for_status(); item = response.json()
            if item['status'] in ('completed','failed'): break
            time.sleep(.5)
        if item['status'] != 'completed': raise RuntimeError(item.get('error') or 'Scan timed out')
        inventory = client.get('/assets',params={'scanId':item['scanId'],'pageSize':200}).json()
        item['criticalCount'] = inventory['criticalCount']; results.append(item)
        print(f"{label}: {item['assetCount']} assets, {item['criticalCount']} critical")
        for format in ('pdf','csv','xlsx','json'):
            report = client.get(f"/reports/{item['scanId']}",params={'format':format});report.raise_for_status()
            (out/f'{label}.{format}').write_bytes(report.content)
    (out/'results.json').write_text(json.dumps(results,indent=2))
