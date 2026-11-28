#!/usr/bin/env python3
"""Verify vendored bytes and optionally query OSV. No packages installed or updated.
Exit 0 = requested integrity checks passed; 1 = mismatch/advisory/error;
2 = online scan incomplete due to unresolved dependencies. Offline is NOT a CVE scan.
"""
import argparse, hashlib, json, pathlib, sys, urllib.request
root = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--online', action='store_true', help='Query OSV for exact inventoried versions')
args = parser.parse_args()
inv = json.loads((root/'security/dependency-inventory.json').read_text(encoding='utf-8'))
failed = False
for dep in inv['vendored']:
    path = root / dep['file']
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ''
    if actual != dep['sha256']:
        print('FAIL: vendored bytes changed:', dep['file']); failed = True; continue
    print('PASS: vendored hash:', dep['file'])
    if args.online:
        payload = {'package': {'ecosystem': dep['ecosystem'], 'name': dep['package']}, 'version': dep['version']}
        try:
            request = urllib.request.Request('https://api.osv.dev/v1/query', data=json.dumps(payload).encode('utf-8'), headers={'Content-Type':'application/json'}, method='POST')
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.geturl() != request.full_url: raise ValueError('Unexpected advisory endpoint redirect')
                raw = response.read(2*1024*1024+1)
                if len(raw) > 2*1024*1024: raise ValueError('Advisory response too large')
                result = json.loads(raw)
            if not isinstance(result,dict) or 'error' in result or not isinstance(result.get('vulns',[]),list): raise ValueError('Invalid advisory response')
            ids = [str(x['id']) for x in result.get('vulns', [])]
            print('OSV:', dep['package'], dep['version'], ', '.join(ids) if ids else 'no matching advisory returned (not proof of safety)')
            failed |= bool(ids)
        except Exception as exc:
            print('FAIL: OSV query:', type(exc).__name__); failed = True
print('Unverified bundled component versions:', ', '.join(inv['bundledVersionUnverified']))
print('Manual platform/external advisory review:', '; '.join(inv['platformAndExternal']))
if failed: sys.exit(1)
if args.online and (inv['bundledVersionUnverified'] or inv['platformAndExternal']):
    print('INCOMPLETE: release requires separate provenance and platform/external review.'); sys.exit(2)
if not args.online: print('Offline integrity only: vulnerability lookup not performed.')
