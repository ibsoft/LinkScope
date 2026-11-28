"""Offline browser regression for settings layout and help. No live server needed."""
from pathlib import Path
import re, json, os
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]; src=root/'src'
html=(src/'settings.html').read_text(); js=(src/'app.js').read_text(); web=(src/'Web.cs').read_text()
assets=dict(re.findall(r'Asset\("/assets/([^"\n]+)","([^"\n]+)","text/css"\)',web))
css=[]
for url in re.findall(r'<link\b[^>]*href="/assets/([^"\n]+\.css)"[^>]*>',html): css.append((src/assets.get(url,url)).read_text())
body=re.search(r'<body\b[^>]*>.*?</body>',html,re.S).group(0)
body=re.sub(r'<script\b[^>]*>.*?</script>','',body,flags=re.S)
body=body.replace('{{brand}}','LinkScope').replace('{{version}}','V43')
setup=js[js.index('function setupSettingsHelp(){'):js.index('function settingsPage(){')]
quick=js[js.index('function ensureSettingsQuickLinks('):js.index('function decorateHealthSection(')]
code="const byId=id=>document.getElementById(id);const element=(tag,text)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;};\n"+setup+quick+"\nsetupSettingsHelp();ensureSettingsQuickLinks([...document.querySelectorAll('details.settings-category')]);"
fixture='<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>'+ '\n'.join(css)+'</style></head>'+body.replace('</body>','<script>'+code+'</script></body>')+'</html>'
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu'])
    page=browser.new_page(viewport={'width':1366,'height':768});errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
    page.set_content(fixture,wait_until="domcontentloaded")
    assert page.locator('details.settings-category[open]').count()==0
    assert page.locator('.settings-quick-link').count()==page.locator('details.settings-category').count()==16
    assert 'Unixfor' not in page.locator('#BrandLabel').get_attribute('placeholder')
    assert json.loads((src/'default.json').read_text())['BrandLabel']==''
    page.get_by_role('button',name='Endpoint Protection',exact=True).click()
    assert page.locator('#endpoint-settings').evaluate('(e)=>e.open')
    assert page.get_by_role('button',name='Endpoint Protection',exact=True).get_attribute('aria-expanded')=='true'
    help=page.locator('[data-setting-help="help-EndpointEntropyMinimumCurrent"]')
    for width in (1366,1024,768,390,320):
        page.set_viewport_size({'width':width,'height':768})
        for theme in ('light','dark'):
            page.locator('html').evaluate('(e,t)=>e.dataset.theme=t',theme)
            help.click();assert page.locator('#setting-help-dialog').evaluate('(e)=>e.open')
            assert 'not proof of ransomware' in page.locator('#setting-help-content').inner_text()
            box=page.locator('#setting-help-dialog').bounding_box();assert box['x']>=0 and box['x']+box['width']<=width+1,(width,theme,box)
            page.keyboard.press('Escape');assert not page.locator('#setting-help-dialog').evaluate('(e)=>e.open')
            assert help.evaluate('(e)=>document.activeElement===e')
            assert page.locator('#EndpointEntropyMinimumCurrent').bounding_box()['height']==page.locator('#EndpointEntropyMinimumIncrease').bounding_box()['height']
            for b in page.locator('.settings-quick-link').all():
                box=b.bounding_box();assert box['x']>=0 and box['x']+box['width']<=width+1,(width,theme,box)
    assert not errors,errors
    print('PASS: 16 named shortcuts, all categories closed initially, empty default brand, help dialog, focus restoration, matched input heights and shortcut containment across five widths and two themes.')
    browser.close()
