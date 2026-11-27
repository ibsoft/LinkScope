"""Portable source assertions; native named-pipe test runs with --usn-self-test on Windows."""
from pathlib import Path
import subprocess, re
root=Path(__file__).resolve().parents[1]
s=(root/'src/UsnJournal.cs').read_text(); js=(root/'src/app.js').read_text()
transport=s.split('static void AwaitPipe',1)[1].split('static byte[] Encode',1)[0]
assert 'AsyncWaitHandle' not in transport and 'BeginRead' not in transport and 'BeginWrite' not in transport
assert 'Task.WhenAny(operation,Task.Delay(timeout))' in transport
assert 'stream.Dispose();throw new System.TimeoutException' in transport and 'OnlyOnFaulted' in transport
assert 'stream.ReadAsync' in transport and 'stream.WriteAsync' in transport and 'operation.GetAwaiter().GetResult()' in transport
assert 'PipeSelfTest();' in s and 'ReadExact(client,1,100)' in s and 'i<32' in s
assert 'stage+": "+ex.GetType().Name' in s
assert 'missingCanaryPaths.join' in js and 'next.Endpoint.Paths=[...new Set([...next.Endpoint.Paths,...missingCanaryPaths])]' in js
assert 'endpoint-active-scope' in js and 'endpoint-active-scope' in (root/'src/endpoint.html').read_text()
# Execute the actual JS path boundary predicate and actual missing-canary selection expression.
fn=re.search(r'function responseUnder\([^\n]+',js).group(0)
expr=re.search(r'const missingCanaryPaths=(.*?);',js).group(1)
script=fn+'\nconst next={Endpoint:{Paths:["C:\\\\unx"],CanaryPaths:["C:\\\\unx\\\\a.txt","C:\\\\unx2\\\\b.txt","C:\\\\Users\\\\u\\\\Documents\\\\canary.txt"]}};\nconst missingCanaryPaths='+expr+';\nif(missingCanaryPaths.length!==2||!missingCanaryPaths[0].includes("unx2"))process.exit(1);'
subprocess.run(['node','-e',script],check=True)
print('PASS: transport lifecycle source checks, timeout wiring, native regression fixture wiring, active scope UI, actual JS path-boundary/canary selection test.')
print('NOT RUN: Windows named-pipe test, service integration, native NTFS I/O.')

# Both System and System.ServiceProcess are imported; qualify all timeout exceptions.
import re
assert not re.search(r"(?<![\w.])TimeoutException\b", (root / "src/UsnJournal.cs").read_text()), "Ambiguous timeout exception"
