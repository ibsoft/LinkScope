"""Exercise actual coverage renderer in Chromium; Windows provider not executed."""
from pathlib import Path
from playwright.sync_api import sync_playwright
import os
root=Path(__file__).resolve().parents[1]
app=(root/'src/app.js').read_text(); cs=(root/'src/EndpointProtection.cs').read_text(); web=(root/'src/Web.cs').read_text(); html=(root/'src/endpoint.html').read_text()
assert 'localWatcherDiagnostic=error' in cs and 'privilegedWatcherDiagnostic=helper==null?null:' in cs
assert 'else if(uncoveredWatchers.Length==0)Resolve(db,"Protected paths","Watcher coverage incomplete")' in cs
for name,file,mime in [('app-endpoint-protection-v34.js','app.js','application/javascript'),('app-endpoint-coverage-v34.css','app.css','text/css')]:
    assert f'/assets/{name}' in html and f'Asset("/assets/{name}","{file}","{mime}")' in web
renderer=app[app.index('function endpointRootPresentation('):app.index('function endpointActivity(')]
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage'])
    page=browser.new_page(viewport={'width':390,'height':844})
    page.set_content('<main><div id="coverage" class="endpoint-root-coverage"></div></main>')
    for sheet in ['app.css','theme.css']: page.add_style_tag(content=(root/'src'/sheet).read_text())
    page.add_script_tag(content="const element=(tag,text)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;};function healthBadge(value,kind){const b=element('span',value);b.className='health-badge '+kind;return b;}\n"+renderer+"\nwindow.renderCoverage=(r,fresh)=>renderEndpointRootCoverage(document.querySelector('#coverage'),r,fresh);")
    sample={'path':r'C:\Users\Example','state':'Watching','localWatcher':False,'privilegedWatcher':True,'journal':True,'localWatcherDiagnostic':'FileNotFoundException: Error reading directory','privilegedWatcherDiagnostic':'Privileged recursive watcher active'}
    def render(row=sample,fresh=True,status='partial'): page.evaluate('([row,fresh,status])=>renderCoverage({status,rootCoverage:[row]},fresh)',[row,fresh,status])
    render();badge=page.locator('.health-badge'); assert badge.inner_text()=='Real-time monitoring active' and 'ok' in badge.get_attribute('class')
    assert 'automatic fallback' in page.locator('.endpoint-coverage-meta').inner_text()
    error=page.get_by_text('Local watcher diagnostic: FileNotFoundException: Error reading directory',exact=True)
    assert not error.is_visible(); page.get_by_text('Technical diagnostics',exact=True).click(); assert error.is_visible()
    render(); assert error.is_visible(); render(dict(sample,journal=False)); assert error.is_visible()
    # Actual runtime DOM; exceptions are inserted as text, never executable markup.
    render(dict(sample,localWatcherDiagnostic='<img src=x onerror=alert(1)>')); assert page.locator('#coverage img').count()==0
    for state,local,system,journal,label,kind in [
        ('Watching',True,False,True,'Real-time monitoring active','ok'),
        ('Journal only',False,False,True,'Journal-only monitoring','review'),
        ('Initializing',False,False,False,'Monitoring initializing','review'),
        ('Uncovered',False,False,False,'Monitoring unavailable','fail'),
        ('Excluded',True,True,True,'Excluded by policy','review'),
        ('Scheduled only',True,True,True,'Scheduled only','info'),
        ('Watching',False,False,True,'Monitoring status unverified','review')]:
        render(dict(sample,state=state,localWatcher=local,privilegedWatcher=system,journal=journal))
        assert badge.inner_text()==label and kind in badge.get_attribute('class')
    render(fresh=False);assert 'Awaiting fresh' in page.locator('#coverage').inner_text() and badge.count()==0
    render(status='disabled');assert page.locator('#coverage').inner_text()=='Endpoint Protection disabled' and badge.count()==0
    render();page.evaluate("document.documentElement.dataset.theme='dark'")
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    browser.close()
print('PASS: Chromium coverage rendering, fallback, collapsed exceptions, refresh state, stale/disabled states, journal-only, uncovered, excluded, scheduled, safe text and mobile width. Native Windows watcher not tested.')
