"""Chromium UI regression tests for the supplemental dashboard; simulated telemetry."""
from pathlib import Path
import os,re
from playwright.sync_api import sync_playwright
src=Path(__file__).resolve().parents[1]/'src'
h=(src/'endpoint.html').read_text();h=re.sub(r'<script\b[^>]*>.*?</script>','',h,flags=re.S|re.I);h=re.sub(r'<link\b[^>]*>','',h,flags=re.I);h=h.replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V79');h=h.replace('</head>','<style>'+'\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css','toast.css'))+'</style></head>')
js=(src/'app.js').read_text();js=js[:js.rindex('LinkScopeBusy.run(')]
base=dict(status='ok',engineOnline=True,engineRecoveryPending=False,signatureFreshness='Current',activeMalware=0,activeHeuristic=0,activeScanIssues=0,coverageIssueCount=0,violations=0,items=[],fullScanComplete=True,scanRunning=False,protectedPaths=[r'C:\Web'],rootCoverage=[dict(path=r'C:\Web',state='Watching')],pendingAlertDelivery=0,canaryCount=0,canaries=[],mode='monitor')
web=dict(enabled=True,paths=[r'C:\Web\Portal'],processAuditEnabled=True,processAuditState='Available — reviewed through captured watermark',lastScriptCheckUtc='2026-11-28T15:00:00Z',suspiciousScripts=0,inspectionIssues=0,processFindings=0,auditIssues=0)
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu'])
    page=browser.new_page(viewport={'width':1366,'height':900});page.set_content(h);page.add_script_tag(content=js+'\nsetupEndpointWorkspace();')
    page.evaluate('r=>window.base=r',base);page.evaluate('w=>window.web=w',web)
    panel=page.locator('#ep-web-protection');cards=panel.locator('.ep-kpi')
    page.locator('[data-ep-tab=web]').click()
    def show(expected,overrides=None,web_overrides=None,age=1):
        page.evaluate('([r,w,a])=>endpointOverview({result:{...base,...r,webProtection:{...web,...w}},ageSeconds:a},[])',[overrides or {},web_overrides or {},age]);assert panel.get_attribute('data-state')==expected,panel.inner_text()
    show('ok');assert cards.count()==4
    notice='Historical process audit policy outage: current monitoring recovered; historical coverage remains incomplete.'
    show('ok',web_overrides={'historicalAuditLimitation':notice});assert notice in page.locator('#ep-web-history').inner_text()
    show('review',web_overrides={'historicalAuditLimitation':notice,'auditIssues':1});assert notice in page.locator('#ep-web-history').inner_text()
    show('unknown',web_overrides={'historicalAuditLimitation':notice},age=31);assert page.locator('#ep-web-history').inner_text()==''
    show('ok')
    assert all(c.get_attribute('data-state')=='ok' for c in cards.all())
    show('verifying',{'scanRunning':True,'fullScanComplete':False});assert cards.nth(0).get_attribute('data-state')=='verifying'
    show('review',{'status':'partial','coverageIssueCount':1});assert cards.nth(1).get_attribute('data-state')!='ok'
    show('review',web_overrides={'suspiciousScripts':1});assert cards.nth(0).get_attribute('data-state')=='review'
    show('review',web_overrides={'enabled':False,'processFindings':1});assert cards.nth(2).get_attribute('data-state')=='review'
    show('unknown',web_overrides={'enabled':False});assert all(c.get_attribute('data-state')=='unknown' for c in cards.all())
    show('ok',web_overrides={'processAuditEnabled':False});assert cards.nth(2).get_attribute('data-state')=='unknown';assert cards.nth(3).get_attribute('data-state')=='unknown'
    show('verifying',web_overrides={'processAuditState':'Backlog — continuing review'});assert cards.nth(2).get_attribute('data-state')=='verifying'
    show('review',web_overrides={'processAuditState':'Unavailable'})
    show('unknown',web_overrides={'inspectionIssues':None});assert cards.nth(1).get_attribute('data-state')=='unknown'
    show('verifying',web_overrides={'lastScriptCheckUtc':None})
    show('verifying',web_overrides={'paths':[r'C:\WebOther']})
    show('verifying',{'rootCoverage':[]})
    show('unknown',age=31);assert cards.count()==0
    show('unknown',age=-1);assert cards.count()==0
    show('unknown',{'status':'disabled'});assert cards.count()==0
    show('ok');page.evaluate('window.firstCard=document.querySelector("#ep-web-kpis article")');show('ok');assert page.evaluate('firstCard===document.querySelector("#ep-web-kpis article")')
    for theme in ['light','dark']:
        page.evaluate('t=>document.documentElement.dataset.theme=t',theme)
        for width in [390,768,1366]:
            page.set_viewport_size({'width':width,'height':900});show('ok',web_overrides={'paths':[r'C:\Web' + chr(92) + 'LongDirectory'*20]})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),(theme,width)
            assert panel.locator('.ep-web-links').evaluate_all('(groups)=>groups.every(g=>[...g.children].every(b=>{const x=b.getBoundingClientRect(),p=g.getBoundingClientRect();return x.left>=p.left-1&&x.right<=p.right+1&&x.height>=40}))'),(theme,width)
    show('ok');page.locator('#ep-web-protection [data-ep-go=scan]').click();assert page.locator('[data-ep-tab=scan]').get_attribute('aria-pressed')=='true'
    page.locator('[data-ep-tab=web]').click();page.locator('#ep-web-evidence').click();assert page.locator('#endpoint-alert-diagnostics').is_visible();assert page.locator('#endpoint-alert-diagnostics').get_attribute('open') is not None
    browser.close()
print('PASS: V79 web dashboard status gates, stable cards, responsive themes, long paths, aligned controls, scanner and evidence navigation; simulated telemetry.')
