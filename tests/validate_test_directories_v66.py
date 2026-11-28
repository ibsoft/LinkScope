"""Saved test directory contract; static source and Chromium UI tests only."""
from pathlib import Path
import json, os, re
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]; src=root/'src'
cs=(src/'EndpointProtection.cs').read_text(); response=(src/'EndpointResponse.cs').read_text(); web=(src/'Web.cs').read_text(); js=(src/'app.js').read_text(); html=(src/'endpoint.html').read_text(); settings=(src/'settings.html').read_text()
assert json.loads((src/'default.json').read_text())['Endpoint']['TestPaths']==[]
for key in ('TestPaths=new string[0]','TestPaths=Normalize(TestPaths)','if(TestPaths.Any(x=>File.Exists(x)||!ResponsePaths.Contains(x,StringComparer.OrdinalIgnoreCase)','testPaths=c.TestPaths'):
    assert key in cs,key
assert 'c.TestPaths.Contains(root,StringComparer.OrdinalIgnoreCase)' in response
assert 'c.TestPaths.Contains(directory,StringComparer.OrdinalIgnoreCase)' in response
assert web.count('!settings.Endpoint.TestPaths.Contains(input.directory,StringComparer.OrdinalIgnoreCase)')==2
assert 'epAuditControls(responseFresh?paths:[],r.testPaths)' in js
assert 'EndpointTestPaths' in settings and 'EndpointSuggestedTest' in settings
assert 'C:\\YourDisposableTestFolder' not in html and 'Apache24' not in html and 'Ransomware-Test' not in html
assert 'ep-manual-lab-command' in html
css='\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css'))
def prepare(h):
    h=re.sub(r'<script\b[^>]*>.*?</script>','',h,flags=re.S|re.I);h=re.sub(r'<link\b[^>]*>','',h,flags=re.I)
    return h.replace('</head>','<style>'+css+'</style></head>').replace('{{brand}}','LinkScope').replace('{{version}}','V66').replace('{{admin-hidden}}','')
js=js[:js.rindex('LinkScopeBusy.run(')]
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768})
    page.set_content(prepare(html));page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";setupEndpointWorkspace();')
    test=r"D:\Applications\O'Brien Lab";other=r'E:\Scratch\Audit Test';prod=r'D:\Applications';denied=r'F:\Denied';file=r'G:\Data\file.exe'
    rows=[dict(path=x,status='warning' if x==denied else 'ok',detail='Denied' if x==denied else 'File read and delete access granted; no file was changed.' if x==file else 'Directory list and delete-child access granted.') for x in [prod,test,other,denied,file]]
    def apply(paths):page.evaluate('([rows,paths])=>epAuditControls(rows,paths)',[rows,paths])
    def options():return {id:page.locator('#'+id+' option').evaluate_all('(xs)=>xs.map(x=>x.value).filter(Boolean)') for id in ['ep-suite-directory','ep-audit-directory','ep-external-directory','ep-protection-directory']}
    for empty in (None,[]):
        apply(empty);assert all(not x for x in options().values());assert page.locator('#ep-suite-run').is_disabled()
    apply([prod,test.lower(),denied,file]);assert all(x==[test] for x in options().values());assert page.locator('#ep-suite-directory').input_value()==test
    assert page.locator('#ep-external-directory').input_value()==test
    assert "-LabRoot 'D:\\Applications\\O''Brien Lab'" in page.locator('#ep-manual-lab-command').text_content()
    apply([test,other]);assert all(set(x)=={test,other} for x in options().values());page.evaluate('(value)=>{byId("ep-external-directory").value=value;epAuditControls();}',other);assert other in page.locator('#ep-manual-lab-command').text_content()
    apply([other]);assert all(x==[other] for x in options().values());assert page.locator('#ep-suite-directory').input_value()==other
    apply([]);assert all(not x for x in options().values());assert page.locator('#ep-suite-run').is_disabled();assert test not in page.locator('#ep-manual-lab-command').text_content()
    # The settings editor round-trips the saved list and can add eligible response paths.
    page.set_content(prepare(settings));page.add_script_tag(content=js)
    cfg=json.loads((src/'default.json').read_text());cfg['Endpoint']['Paths']=[prod,other];cfg['Endpoint']['ResponsePaths']=[prod,test,other];cfg['Endpoint']['TestPaths']=[test]
    page.evaluate('(cfg)=>{fillEndpoint(cfg);updateResponseSuggestions();}',cfg)
    assert page.evaluate('readEndpoint().TestPaths')==[test]
    vals=page.locator('#EndpointSuggestedTest option').evaluate_all('(xs)=>xs.map(x=>x.value).filter(Boolean)');assert set(vals)=={test,other}
    page.evaluate('(value)=>{byId("EndpointSuggestedTest").value=value;addResponseSuggestion("EndpointSuggestedTest","EndpointTestPaths");}',other)
    assert page.evaluate('readEndpoint().TestPaths')==[test,other]
    del cfg['Endpoint']['TestPaths'];page.evaluate('(cfg)=>fillEndpoint(cfg)',cfg);assert page.evaluate('readEndpoint().TestPaths')==[]
    browser.close()
print('PASS: V66 saved policy, no fallback on missing/empty settings, parent/file/denied exclusion, arbitrary folders, PowerShell quoting, removal, auto-selection and settings round-trip (mock UI/static checks).')
