"""Chromium: actual Settings HTML and reset handlers, with mocked service requests."""
from pathlib import Path
from playwright.sync_api import sync_playwright
import re, os
root=Path(__file__).resolve().parents[1]; src=root/'src'
html=(src/'settings.html').read_text(); endpoint=(src/'endpoint.html').read_text(); app=(src/'app.js').read_text()
assert 'href="/settings#endpoint-history-reset"' in endpoint
assert '<span {{admin-hidden}}> · <a href="/settings#endpoint-history-reset"' in endpoint
assert html.index('id="endpoint-history-reset"') < html.index('id="EndpointMaxFileMiB"')
assert html.count('id="EndpointHistoryReset"')==1
body=re.search(r'<body\b[^>]*>.*?</body>',html,re.S).group(0)
body=re.sub(r'<script\b[^>]*>.*?</script>','',body,flags=re.S)
body=re.sub(r'<header\b[^>]*>.*?</header>','',body,flags=re.S)
confirm=app[app.index('let activeConfirmation'):app.index("let csrf='';")]
handlers=app[app.index('let endpointHistoryResetBusy'):app.index('function settingsPage(){')]
reveal=app[app.index('function revealCategory(){'):app.index('async function start(){')]
js="""const byId=id=>document.getElementById(id); const element=(tag,text)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;};const page='settings';let csrf='test',config={Endpoint:{Enabled:true}},formDirty=false;const notice=(t)=>{window.lastNotice=t};const failure=(e)=>{window.lastError=String(e)};window.posts=[];window.resetState={state:'Idle'};async function request(url,body){if(body){window.posts.push({url,body});window.resetState={state:'Queued'}}return window.resetState;}
"""+confirm+handlers+reveal+"\nbyId('EndpointHistoryReset').onclick=resetEndpointHistory;window.refreshReset=refreshEndpointHistoryReset;refreshEndpointHistoryReset();"
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage'])
    p=browser.new_page(viewport={'width':390,'height':844}); errors=[];p.on('pageerror',lambda err:errors.append(str(err)))
    p.set_content(body);p.add_style_tag(content=(src/'app.css').read_text());p.add_style_tag(content=(src/'theme.css').read_text());p.add_script_tag(content=js)
    p.evaluate("location.hash='endpoint-history-reset'");p.wait_for_function("document.getElementById('endpoint-settings').open")
    b=p.locator('#EndpointHistoryReset'); assert b.is_visible() and b.is_enabled()
    b.click();p.get_by_role('button',name='Cancel',exact=True).click();assert p.evaluate('posts.length')==0
    b.click();p.get_by_role('button',name='Delete endpoint history',exact=True).click();p.wait_for_function('posts.length===1');p.wait_for_function("document.getElementById('EndpointHistoryReset').disabled")
    assert p.evaluate('posts[0]')=={'url':'/ui/endpoint-history-reset','body':{'confirmation':'RESET ENDPOINT HISTORY'}}
    p.evaluate("window.resetState={state:'Completed',id:'test'};refreshReset()")
    p.wait_for_function("document.getElementById('EndpointHistoryResetStatus').textContent.includes('completed')")
    assert b.is_enabled();assert not errors,errors
    browser.close()
print('PASS: admin shortcut, early Settings placement, actual deep-link expansion, cancel sends no request, explicit confirmation sends one POST, queued and completed UI states (mocked backend).')
