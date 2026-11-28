"""Portable report-generation smoke test (real PDF library, synthetic data), and AI source contracts. No Windows service or AI provider is exercised."""
from pathlib import Path
import tempfile,subprocess,os,json
from playwright.sync_api import sync_playwright
src=Path(__file__).resolve().parents[1]/'src'
ai=(src/'AiEvidence.cs').read_text();assist=(src/'AiAssist.cs').read_text();web=(src/'Web.cs').read_text()
for term in ['WebAssessment','WebSecurity(endpointWrapper,rules.Endpoint)','web_server_protection','reportedCounts','configuredPathsOmitted','lastKnownFindingsPresent','rootCoverage','usnVolumes','coverageDetails','activeSampleOmitted']:
    assert term in ai,term
assert 'WebAssessment(ep,settings.Endpoint)' in web
assert 'evidenceSchema=2,coverage=evidence.Coverage()' in assist
assert 'Heuristics are suspicious, not confirmed malware' in assist
assert 'if(session.IsAdmin){try{delivery=outputs.State();}' in web
now=1795878000; stamp='2026-11-28T15:00:00Z'; target={'Address':'127.0.0.1','Name':'Synthetic loopback'}
health={'monitorHost':'TEST HOST','generatedUtc':stamp,'categories':{'endpoint_protection':{'collectedUtc':stamp,'ageSeconds':2,'result':{'status':'partial','items':[{'change':'Suspicious web script','severity':'warning','path':r'C:\Web\sample.php','detail':'Synthetic review indicator','lastUtc':stamp}],'recentIncidents':[{'change':'Web process audit history gap','severity':'warning','path':'Security log','utc':stamp}]}},'data_integrity':{'status':'disabled','result':{'status':'disabled','items':[]}}},'alerts':[]}
assessment={'assessment':'Requires attention','endpointEnabled':True,'enabled':True,'processAuditEnabled':True,'collectedUtc':stamp,'fresh':True,'telemetryPolicyMatches':True,'sharedScannerStatus':'partial','sharedBaselineVerified':False,'configuredPathsCovered':False,'lastScriptCheckUtc':stamp,'processAuditState':'Unavailable','reportedCounts':{'suspiciousScripts':1,'inspectionIssues':None,'processFindings':0,'auditIssues':1},'configuredPaths':[r'C:\Web'],'limitations':'Synthetic test; no comprehensive web-shell verdict.','scriptInspectionLimitBytes':4194304,'activeSnapshotTruncated':True}
assessment['historicalAuditLimitation']='Historical events cannot be recovered; current policy reverified.'
manifest={'now':now,'targets':[target],'probeAlertCount':3,'webAssessment':assessment,'disabledInventory':['services'],'connections':{'now':now,'total':2,'rows':[{'protocol':'TCP','local':'127.0.0.1:80','remote':'127.0.0.1:5000','state':'Established'}]},'delivery':{'queued':1},'logging':{'local':'Ready'},'logSummary':{'rows':[]},'aiVerdict':{'answer':'Synthetic legacy verdict','evidenceUtc':'2026-11-27T15:00:00Z','completedUtc':'2026-11-27T15:00:10Z','provider':'test','model':'test'}}
sections=[dict(target=target['Address'],targets=[target],range='day',now=now,start=now-86400,end=now,step=300,interval=10,points=[],rates=[],events=[],resourceUsage=[])]
with tempfile.TemporaryDirectory() as d,sync_playwright() as pw:
    b=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage']); page=b.new_page();page.set_content('<html><body></body></html>');page.add_script_tag(path=str(src/'pdf-lib.min.js'));page.add_script_tag(path=str(src/'charts.js'))
    # No external assets; emulate missing icon without waiting on network.
    page.evaluate('()=>{window.Image=class {set src(v){this.onerror?.();}}}')
    page.add_script_tag(content=(src/'report.js').read_text().replace('return {exportAll};','return {exportAll,build};'))
    result=page.evaluate('async ([s,h,m])=>Array.from(await LinkScopeReport.build(s,h,[],[],m))',[sections,health,manifest]);pdf=Path(d)/'synthetic.pdf';pdf.write_bytes(bytes(result));
    text=subprocess.check_output(['pdftotext','-layout',str(pdf),'-'],text=True)
    for term in ['Web Server Protection - supplemental detection and coverage','Requires attention','Suspicious scripts: 1','Inspection issues: unavailable','Synthetic review indicator','Web process audit history gap','STALE OR LEGACY VERDICT','Native active connections','Alert delivery, logging and SIEM','Disabled optional categories: services','Historical audit limitation (current monitoring recovered):','Historical events cannot be recovered; current policy reverified.']:
        assert term in ' '.join(text.split()),term
    subprocess.run(['pdfdetach','-save','1','-o',str(Path(d)/'data.json'),str(pdf)],check=True)
    attached=json.loads((Path(d)/'data.json').read_text());assert attached['webAssessment']['reportedCounts']['inspectionIssues'] is None;assert attached['webAssessment']['reportedCounts']['suspiciousScripts']==1;assert attached['windows']==health;assert attached['connections']['total']==2;assert attached['webAssessment']['historicalAuditLimitation']==assessment['historicalAuditLimitation']
    b.close()
print('PASS: V80 report PDF, raw attachment, legacy verdict advisory, active and historical finding distinction, missing counters and AI source contracts (synthetic telemetry).')
