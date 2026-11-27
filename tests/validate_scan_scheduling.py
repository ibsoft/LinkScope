"""Portable source checks and reference scheduling fixtures; Windows execution is separate."""
from pathlib import Path
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String, Comment
root=Path(__file__).resolve().parents[1]
s=(root/'src/EndpointProtection.cs').read_text(); u=(root/'src/UsnJournal.cs').read_text(); js=(root/'src/app.js').read_text()
for code in (s,u):
    stack=[]
    for token,value in lex(code,CSharpLexer()):
        if token in String or token in Comment: continue
        for ch in value:
            if ch in '([{': stack.append(ch)
            elif ch in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch]
    assert not stack
# Current bounded priority queue: scope filtering, coalescing, policy epoch and reserved capacity.
enqueue=s.split('void Enqueue(',1)[1].split('bool RetryLocked',1)[0]
assert enqueue.index('Excluded(c,path)')<enqueue.index('watchQueue.TryGetValue')<enqueue.index('watchQueue.Add')
assert 'StringComparer.OrdinalIgnoreCase' in s.split('watchQueue=',1)[1].split(';',1)[0]
assert 'existing.Priority|=priority' in enqueue and 'existing.Last=now' in enqueue
assert 'MaxQueue-PriorityReserve' in enqueue and 'ReferenceEquals(watchPolicy,c)' in enqueue
assert 'watchQueue.Remove(best.Path)' in s and 'watchPolicy=null;watchQueue.Clear()' in s
assert 'RequestReconciliation(c,false)' in s and '()=>RequestReconciliation(c,true)' in s
assert 'if(running){if(journalGap)journalGapDuringScan=true;return;}' in s
assert 'lastScan+c.IntervalSeconds' in s
assert 'if(!rescan&&!journalGapDuringScan)' in s
assert u.index('gap(v.Root,detail);reconcile();')<u.index('db.Exec("BEGIN IMMEDIATE")')
tick=s.split('// Canaries have a dedicated lane',1)[1]
assert tick.index('CheckFile(db,c,canary')<tick.index('ScanWatcher(db,c,stop,authorized,0)')<tick.index('usn.Pending(db,4)')<tick.index('ScanNext(db,c')
assert 'ScanWatcher(db,c,stop,authorized,1)' in tick
assert 'if(CheckFile(db,c,path,stop,authorized,false))usn.Ack(db,path)' in tick
assert 'if(finished&&!HasWatcher(work.Path))usn.Ack(db,work.Path)' in s
assert 'watcherQueueDepth=watchCounts[0]' in s and 'USN pending:' in js and 'Watcher pending:' in js
assert 'priorityQueueDepth=watchCounts[1]' in s and 'Priority arrivals:' in js
# Reference-model fixtures verify expected scheduling invariants, not C# runtime.
def schedule(running, gap, last, now, interval, next_scan, flag=False):
    if running: return next_scan, flag or gap
    return min(next_scan, now if last==0 else max(now,last+interval)), flag
assert schedule(True,False,100,200,300,0)==(0,False)
assert schedule(True,True,100,200,300,0)==(0,True)
assert schedule(False,True,100,200,300,400)==(400,False)
assert schedule(False,True,100,450,300,900)==(450,False)
assert schedule(False,False,0,100,300,900)==(100,False)
print('PASS: source wiring, queue dedup and scope guards, canary priority, scheduled scan fairness, coverage gap preservation, queue metrics, scheduling reference fixtures. Windows runtime not executed.')
