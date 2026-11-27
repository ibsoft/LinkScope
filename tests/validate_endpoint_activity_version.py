"""Portable checks of actual acknowledgement SQL and live activity UI states.
Does not run the C# service, Windows PowerShell version generator or render a browser.
"""
from pathlib import Path
import json, re, sqlite3, subprocess, tempfile, xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
src=root/'src'
alerts=(src/'Alerts.cs').read_text()
query=re.search(r'var row=db\.Rows\("(SELECT COALESCE\(MAX\(seq\),0\).*?WHERE category=\'endpoint_protection\')"\)',alerts).group(1)
ack=re.search(r'db\.Exec\("(UPDATE alert_events SET is_read=1 WHERE category=\'endpoint_protection\' AND seq<=\? AND is_read=0)"',alerts).group(1)
db=sqlite3.connect(':memory:')
schema=re.search(r'db\.Exec\("(CREATE TABLE IF NOT EXISTS alert_events\(.*?)"\)',alerts).group(1)
db.execute(schema)
def add(seq,cat,resolved):
    db.execute('INSERT INTO alert_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(seq,str(seq),cat+'/'+str(seq),cat,'warning','Test','Test','r',0,0,resolved,1 if resolved else None))
add(1,'endpoint_protection',1);add(2,'endpoint_protection',0);add(3,'ram',0)
cutoff,unread,active_unread=db.execute(query).fetchone();assert (cutoff,unread,active_unread)==(2,2,1)
add(4,'endpoint_protection',0)
db.execute(ack,(cutoff,))
assert db.execute(query).fetchone()==(4,1,1)
assert db.execute('SELECT seq,is_read,resolved FROM alert_events ORDER BY seq').fetchall()==[(1,1,1),(2,1,0),(3,0,0),(4,0,0)]
assert db.execute('SELECT COUNT(*) FROM alert_events').fetchone()==(4,)
print('PASS: scoped SQLite acknowledgement preserves all history, active incidents, unrelated categories and later unread events')
app=(src/'app.js').read_text()
helpers=app[app.index('let endpointAck=null,'):app.index('function setupEndpointControls(){')]
js='''const assert=require('node:assert/strict');const controls={};const byId=id=>controls[id]??=( {dataset:{},textContent:'',disabled:false});let csrf='admin';\n'''+helpers+'''
const now='2026-11-27T08:42:00Z',base={engineOnline:true,status:'ok',realTime:true,watcherCount:1,queueDepth:0,scanRunning:false,scannedFiles:10,realTimeChecked:1};
function activity(result,age=1){endpointActivity({result:{...base,...result},ageSeconds:age,collectedUtc:now,stale:false},now);return byId('endpoint-live').dataset.state;}
assert.equal(activity({}),'watching');assert.equal(activity({scanRunning:true}),'scanning');assert.equal(activity({queueDepth:2}),'queued');assert.equal(activity({lastRealTimeScanUtc:'2026-11-27T08:41:57Z'}),'activity');assert.equal(activity({lastRealTimeScanUtc:'2026-11-27T08:41:30Z'}),'watching');assert.equal(activity({engineOnline:false,scanRunning:true}),'warning');assert.equal(activity({scanRunning:true},21),'waiting');assert.equal(activity({status:'disabled'}),'disabled');assert.equal(activity({realTime:false}),'idle');assert.equal(activity({watcherCount:0}),'warning');assert.equal(activity({status:'partial'}),'warning');endpointAck={unread:0,through:1,activeUnread:0};endpointAckControls();assert.equal(byId('endpoint-ack-previous').disabled,true);endpointAck={unread:2,through:3,activeUnread:1};endpointAckControls();assert.equal(byId('endpoint-ack-previous').disabled,false);assert.match(byId('endpoint-ack-previous').textContent,/2/);
'''
subprocess.run(['node','-e',js],check=True)
print('PASS: live UI state logic in Node.js (not visual rendering)')
web=(src/'Web.cs').read_text();toast=(src/'toast.js').read_text();ep=(src/'EndpointProtection.cs').read_text();telemetry=(src/'Telemetry.cs').read_text()
assert 'r.Path=="/ui/endpoint-ack"&&session!=null' in web and 'ReadEndpointThrough(input.through)' in web
assert 'session==null||!Access.Equal(session.Csrf,r.Header("X-CSRF-Token"))' in web
assert 'item.category===category&&item.alertSequence!=null&&item.alertSequence<=cutoff' in toast
assert 'complete&&online&&!running' in ep and 'SELECT 1 FROM endpoint_outbox LIMIT 1' in ep and 'WHERE active=1' in ep
assert 'alerts.ReconcileEndpointFindings(ids)' in ep and 'successfulTick' in telemetry
assert 'lastRealTimeScan=lastFileScan' in ep and 'realTimeChecked++' in ep
assert 'if(!full)' in ep and 'lastFileScan=History.Now()' in ep
assert 'prefers-reduced-motion:reduce' in (src/'theme.css').read_text()
print('PASS: authenticated/CSRF-protected route, category-only toast dismissal, reconciliation gating and telemetry wiring (source assertions)')
for page in src.glob('*.html'):
    text=page.read_text();assert text.count('{{version}}')==1 and 'Copyright 2026 - IBSoft' in text,page.name
assert 'WebUtility.HtmlEncode(BuildVersion)' in web and 'Program.Resource("build-version.txt")' in web
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'};project=ET.parse(root/'LinkScope.csproj')
assert any(e.attrib.get('Name')=='GenerateLinkScopeVersion' and e.attrib.get('BeforeTargets')=='PrepareForBuild' for e in project.findall('.//m:Target',ns))
assert '/resource:obj\\LinkScopeVersion.txt,build-version.txt' in (root/'Build.cmd').read_text()
script=(root/'tools/Write-BuildVersion.ps1').read_text();assert 'merge-base' in script and '--first-parent' in script and '--merges' in script and 'merge_commit_sha -eq $head' in script
# Exercise the Git merge-message selection algorithm with genuine merge commits.
# PowerShell itself is not available here, so this checks the same regex and Git commands, not execution of the PS script.
merge_regex=re.search(r"-cmatch '(\^Merge pull request [^']+)'",script).group(1)
version_regex=re.search(r"\$pattern = '([^']+)'",script).group(1)
with tempfile.TemporaryDirectory() as temp:
    def git(*args):return subprocess.check_output(['git','-C',temp,*args],text=True,stderr=subprocess.DEVNULL).strip()
    git('init','-b','main');git('config','user.email','test@example.invalid');git('config','user.name','Test');git('commit','--allow-empty','-m','Initial')
    git('checkout','-b','v_1.0.1');git('commit','--allow-empty','-m','release work');git('checkout','main');git('merge','--no-ff','-m','Merge pull request #1 from example/v_1.0.1','v_1.0.1')
    old=git('rev-parse','HEAD')
    git('checkout','-b','v_1.0.2');git('commit','--allow-empty','-m','release work');git('checkout','main');git('merge','--no-ff','-m','Merge pull request #2 from example/v_1.0.2','v_1.0.2')
    git('checkout','-b','bugfix');git('commit','--allow-empty','-m','bugfix work');git('checkout','main');git('merge','--no-ff','-m','Merge pull request #3 from example/bugfix','bugfix')
    def resolve():
        base=git('merge-base','HEAD','refs/heads/main')
        for msg in git('log','--first-parent','--merges','--format=%s',base).splitlines():
            match=re.fullmatch(merge_regex,msg)
            if match and re.fullmatch(version_regex,match.group(1)):return match.group(1)
        return 'unversioned'
    assert resolve()=='v_1.0.2';git('checkout','--detach',old);assert resolve()=='v_1.0.1'
print('PASS: every page version placeholder, embedded-resource build wiring and real Git merge-history selection (portable equivalent)')
