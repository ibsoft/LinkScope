"""Static source checks only; exercise EventLogReader on Windows before deployment."""
from pathlib import Path
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String,Comment
r=Path(__file__).resolve().parents[1]
s=(r/'src/EndpointResponse.cs').read_text()
method=s.split('internal static object ContainmentDiagnostics(',1)[1].split('  static void Confirmed(',1)[0]
audit=method.split('bool securityReadable=false;',1)[1].split('var pathChecks=',1)[0]
assert 'FromMilliseconds(1000)' in audit and 'FromMilliseconds(100)' not in audit
assert 'auditBudgetMs=3000,auditMaxRecords=512' in audit and 'Math.Max(1L,auditBudgetMs-auditTimer.ElapsedMilliseconds)' in audit
assert 'reader.BatchSize=1' in audit and 'inspected<auditMaxRecords&&auditTimer.ElapsedMilliseconds<auditBudgetMs' in audit
assert 'PathType.LogName,"*"' in audit and 'ev.Id!=4663' in audit and 'AddMinutes(-15)' in audit and "Data[@Name='ObjectType']" in audit and 'typeNode.InnerText,"File"' in audit
assert '(mask&0x10046)==0' in audit and 'c.Paths.Any(x=>EndpointProtection.Under(path,x))' in audit and 'EndpointProtection.Excluded(c,path)' in audit
assert audit.index('matched=true;add("File system audit evidence","Pass"')>audit.index('EndpointProtection.Excluded(c,path)')
assert 'if(!matched)' in audit and 'Query completed; no matching' in audit and 'Bounded query incomplete' in audit and 'Audit evidence query inconclusive' in audit
assert 'Not tested' in audit and 'does not prove that auditing is disabled' in audit
assert 'TerminateProcess(' not in method and 'Quarantine(' not in method
assert int((r/'source-build-version.txt').read_text().strip()[1:])>=55
stack=[]
for tok,val in lex(s,CSharpLexer()):
    if tok in String or tok in Comment:continue
    for ch in val:
        if ch in '([{':stack.append(ch)
        elif ch in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch],ch
assert not stack
print('PASS: bounded recent audit query, protected-scope and write-mask gate, no-match vs incomplete evidence, diagnostic isolation, source delimiters (static).')
