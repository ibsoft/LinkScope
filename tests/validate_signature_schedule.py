"""Actual JavaScript settings state and SQL/source checks; Windows C# self-test required for the scheduler/task."""
from pathlib import Path
import json, re, sqlite3, subprocess
root=Path(__file__).resolve().parents[1];src=root/'src'
app=(src/'app.js').read_text(); ep=(src/'EndpointProtection.cs').read_text(); program=(src/'Program.cs').read_text(); html=(src/'settings.html').read_text(); endpoint=(src/'endpoint.html').read_text()
policy=json.loads((src/'default.json').read_text())['Endpoint']
# The backend preserves this installer-owned flag independently of the browser form.
assert 'next.Endpoint.ProfileDefaultsApplied=settings.Endpoint.ProfileDefaultsApplied' in (src/'Web.cs').read_text()
policy.pop('ProfileDefaultsApplied')
assert not policy['SignatureScheduleEnabled'] and policy['SignatureScheduleFrequency']=='daily' and policy['SignatureScheduleTime']=='03:00'
for field in ('Enabled','Frequency','Time','Weekday','MonthDay'):
    assert html.count('id="EndpointSignatureSchedule'+field+'"')==1,field
    assert 'SignatureSchedule'+field in ep
# Actual settings functions, with simple DOM fixtures.
functions=app[app.index('const endpointFlags='):app.index('let endpointResponseSuggestions=')]+app[app.index('function readEndpoint(){'):app.index('\nasync function loadSettings(){')]
js=r'''
const assert=require('node:assert/strict');const els={};const byId=id=>els[id]??={value:'',checked:false,disabled:false,hidden:false,textContent:''};const integrityLines=id=>String(byId(id).value).split(/\r?\n/).filter(Boolean);
'''+functions+r'''
const defaults=POLICY;fillEndpoint({Endpoint:defaults});assert.equal(byId('EndpointSignatureScheduleEnabled').checked,false);assert(byId('signature-schedule-fields').hidden);assert(byId('EndpointSignatureScheduleTime').disabled);assert.deepEqual(readEndpoint(),defaults);
byId('EndpointSignatureScheduleEnabled').checked=true;byId('EndpointSignatureScheduleFrequency').value='weekly';byId('EndpointSignatureScheduleWeekday').value='5';byId('EndpointSignatureScheduleTime').value='04:30';signatureScheduleFields();assert(!byId('signature-weekday-field').hidden);assert(byId('signature-monthday-field').hidden);assert(!byId('EndpointSignatureScheduleWeekday').disabled);assert(byId('EndpointSignatureScheduleMonthDay').disabled);
let saved=readEndpoint();assert.equal(saved.SignatureScheduleEnabled,true);assert.equal(saved.SignatureScheduleFrequency,'weekly');assert.equal(saved.SignatureScheduleWeekday,5);assert.equal(saved.SignatureScheduleTime,'04:30');fillEndpoint({Endpoint:saved});assert.deepEqual(readEndpoint(),saved);
byId('EndpointSignatureScheduleFrequency').value='monthly';byId('EndpointSignatureScheduleMonthDay').value='31';signatureScheduleFields();assert(byId('signature-weekday-field').hidden);assert(!byId('signature-monthday-field').hidden);assert.equal(readEndpoint().SignatureScheduleMonthDay,31);byId('EndpointSignatureScheduleEnabled').checked=false;signatureScheduleFields();assert(byId('signature-schedule-fields').hidden);assert.equal(readEndpoint().SignatureScheduleEnabled,false);
console.log('PASS: actual settings JS roundtrip, optional schedule, daily/weekly/monthly, hidden inputs and preserved choices');
'''.replace('POLICY',json.dumps(policy))
# The fake DOM retains numbers as numbers, whereas the real DOM stringifies .value;
# the settings reader explicitly normalizes numbers for the persisted configuration.
subprocess.run(['node','-e',js],check=True)
body=ep.split('object ScheduledSignatures(',1)[1].split('internal object Tick(',1)[0]
for marker in ('!c.SignatureScheduleEnabled','!Program.ServiceMode||c.Port!=3310','if(now>=r.Next)','!authorized()','state.Busy||state.CoolingDown','Program.QueueSignatureUpdate()','Scheduled signature update request failed','lastScheduledRequestUtc=','nextRunUtc='):
    assert marker in body,marker
assert body.index('r.Next=NextScheduleEpoch(c,now);r.LastRequest=now;')<body.index('Program.QueueSignatureUpdate()')
assert 'lock(signatureQueueGate)' in program and 'History.Now()-lastQueuedSignature<60' in program
assert 'TimeZoneInfo.ConvertTimeToUtc' in ep and 'zone.IsInvalidTime(candidate)' in ep and 'DateTime.DaysInMonth' in ep
assert 'SignatureScheduleEnabled&&Port!=3310' in ep
assert 'SignatureScheduleRecord="signature_schedule_v1"' in ep
conn=sqlite3.connect(':memory:');conn.execute('CREATE TABLE endpoint_metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL)')
put=re.search(r'db\.Exec\("(INSERT OR REPLACE INTO endpoint_metadata\(name,value\) VALUES\(\?,\?\))"',ep).group(1)
get=re.search(r'db\.Rows\("(SELECT value FROM endpoint_metadata WHERE name=\?)"',ep).group(1)
record={'Policy':'daily|03:00|1|1','Next':1795758000,'LastRequest':1795671600,'Status':'Update requested'}
conn.execute(put,('signature_schedule_v1',json.dumps(record)));assert json.loads(conn.execute(get,('signature_schedule_v1',)).fetchone()[0])==record
record['Next']+=86400;conn.execute(put,('signature_schedule_v1',json.dumps(record)));assert conn.execute('SELECT count(*) FROM endpoint_metadata').fetchone()[0]==1
assert 'signatureSchedule=signatureSchedule' in ep and 'endpoint-signature-schedule' in endpoint
for p in ('report.js','AiEvidence.cs'):
    assert 'signatureSchedule' in (src/p).read_text()
assert 'CheckSignatureSchedule();' in (src/'SelfCheck.cs').read_text()
print('PASS: persisted schedule SQL, fixed task and cooldown, opt-in gates, reporting/API/AI source integration; C# runtime calendar/task tests pending')
