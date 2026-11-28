"""Portable source contracts plus reference cases; Windows self-check is separate."""
from pathlib import Path
from collections import Counter
from ntpath import dirname
r=Path(__file__).resolve().parents[1]
s=(r/'src/EndpointProtection.cs').read_text(); j=(r/'src/app.js').read_text()
assert 'ExtendedEntropyWindowSeconds=300;ExtendedEntropyThreshold=5' in s
assert 'EntropyTransition(n,entropy,Convert.ToDouble(old[1]),c)' in s
assert 'sample>=c.EntropyMinimumSampleBytes&&current>=c.EntropyMinimumCurrent&&current-previous>=c.EntropyMinimumIncrease' in s
assert 'EntropyMinimumSampleBytes=4096;EntropyMinimumCurrent=7.5;EntropyMinimumIncrease=1.0' in s
assert 'if(entropy){' in s and 'extendedEntropy[p]=now' in s
assert s.count('extendedEntropy.Clear();extendedEntropyPeak=0;')==2
assert 'x.Value>=cutoff&&x.Value<=now' in s
assert 'GroupBy(x=>Path.GetDirectoryName(x.Key)??"",StringComparer.OrdinalIgnoreCase)' in s
assert 'if(!rapidSuspect&&peak.Value>=c.ExtendedEntropyThreshold)' in s
extended=s.split('void ExtendedBehavior(',1)[1].split('void Behavior(',1)[0]
assert '"warning"' in extended and 'EndpointResponse.Contain' not in extended
assert 'ExtendedBehavior(db,c,suspect)' in s and 'changed>=threshold&&entropyIncreases>=3' in s
assert 'if(critical&&newIncident&&c.Mode=="contain"&&authorized())' in s
assert 'Extended entropy changes' in j and 'extendedEntropyPeak=extendedEntropyPeak' in s
# Reference-model cases for directory grouping, expiry and case-insensitive deduplication.
def peak(events, now):
    unique={p.lower():t for p,t in events}
    counts=Counter(dirname(p) for p,t in unique.items() if now-300<=t<=now)
    return max(counts.values(),default=0)
base=[(rf'C:\Apache24\Synthetic\Test_{i}.txt',1000-i*50) for i in range(5)]
assert peak(base,1000)==5 and peak(base,1301)==0
assert peak(base[:4]+[(base[0][0].upper(),1000)],1000)==4
assert peak(base[:4]+[(r'C:\Apache24\Other\new.txt',1000)],1000)==4
assert peak(base+[(r'C:\Apache24\Synthetic\future.txt',1001)],1000)==5
print('PASS: V40 source contracts and reference cases; C# Windows self-check added but not executed.')
