"""Offline Chromium checks using actual Settings markup, styles and accordion handlers.
Does not exercise the live Windows backend or submit any real configuration.
"""
from pathlib import Path
import re, os
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]; SRC=ROOT/'src'
html=(SRC/'settings.html').read_text(); app=(SRC/'app.js').read_text()
assets=dict(re.findall(r'Asset\("/assets/([^"\n]+)","([^"\n]+)","text/css"\)',(SRC/'Web.cs').read_text()))
css=[]
for url in re.findall(r'<link\b[^>]*href="/assets/([^"\n]+\.css)"[^>]*>',html):
    css.append((SRC/assets.get(url,url)).read_text())
body=re.search(r'<body\b[^>]*>.*?</body>',html,re.S).group(0)
body=re.sub(r'<script\b[^>]*>.*?</script>','',body,flags=re.S)
body=re.sub(r'<header\b[^>]*>.*?</header>','',body,flags=re.S)
body=body.replace('{{brand}}','LinkScope').replace('{{version}}','v_test')
# Execute the actual event-handler source used by settingsPage and revealCategory.
accordion=app.split('function settingsPage(){',1)[1].split("    byId('configForm').addEventListener('input'",1)[0]
reveal=app.split('function revealCategory(){',1)[1].split("window.addEventListener('linkscope-reveal'",1)[0]
script="const byId=id=>document.getElementById(id);const page='settings';\n"+accordion+'\nfunction revealCategory(){'+reveal+'\nwindow.addEventListener("hashchange",revealCategory);'
fixture='<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>'+ '\n'.join(css)+'</style></head>'+body.replace('</body>','<script>'+script+'</script></body>')+'</html>'
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu'])
    page=browser.new_page(viewport={'width':1440,'height':900}); errors=[]; page.on('pageerror',lambda err:errors.append(str(err)))
    page.set_content(fixture,wait_until='domcontentloaded')
    categories=page.locator('details.settings-category'); assert categories.count()==16
    assert page.locator('details.settings-category[open]').count()==1
    page.locator('#settings-expand-all').click();assert page.locator('details.settings-category[open]').count()==16
    pin=page.locator('#EndpointTrustedEngineSha256'); pin.fill('a'*64)
    page.locator('#settings-collapse-all').click();assert page.locator('details.settings-category[open]').count()==0
    page.locator('#endpoint-settings>summary').click();assert pin.input_value()=='a'*64
    page.locator('#endpoint-settings>summary').click();assert page.locator('details.settings-category[open]').count()==0
    # Native form validation opens a collapsed category before trying to focus its field.
    endpoint_port=page.locator('#EndpointPort'); endpoint_port.evaluate('(el)=>{el.value="";el.reportValidity()}')
    assert page.locator('#endpoint-settings').evaluate('(el)=>el.open')
    page.evaluate("location.hash='siem'");page.wait_for_timeout(100);assert page.locator('#siem').evaluate('(el)=>el.open')
    page.evaluate("location.hash='EndpointTrustedEnginePath'");page.wait_for_timeout(100);assert page.locator('#endpoint-settings').evaluate('(el)=>el.open')
    page.locator('#settings-expand-all').click()
    cases=0
    for width in (1440,1024,768,660,390,320):
        page.set_viewport_size({'width':width,'height':900})
        for theme in ('light','dark'):
            page.locator('html').evaluate('(el,t)=>el.dataset.theme=t',theme)
            for input_id,button_id in [('EndpointSuggestedResponse','EndpointAddSuggestedResponse'),('EndpointSuggestedExecutable','EndpointAddSuggestedExecutable'),('EndpointTrustedEngineSha256','EndpointUseDetectedEngine')]:
                control=page.locator('#'+input_id).bounding_box(); button=page.locator('#'+button_id).bounding_box()
                assert control and button,(width,theme,input_id)
                if width>660:
                    assert abs((control['y']+control['height'])-(button['y']+button['height']))<1,(width,theme,input_id,control,button)
                    assert button['x']>=control['x']+control['width']+10,(width,theme,input_id,'overlap')
                else:
                    assert button['y']>=control['y']+control['height']+5,(width,theme,input_id,'stacking')
                    assert abs(button['x']-control['x'])<1 and abs(button['width']-control['width'])<1,(width,theme,input_id,'mobile width')
                assert button['x']+button['width']<=width+0.5,(width,theme,input_id,'button overflow')
                cases+=1
            color=page.locator('#endpoint-settings>summary').evaluate('(el)=>getComputedStyle(el).backgroundColor')
            if theme=='dark':assert color=='rgb(32, 53, 65)',color
    assert not errors,errors
    print('PASS: 16 categories, expand/collapse, retained edits, native invalid-field reveal, deep links, and',cases,'field/button layouts across six viewport widths and two themes.')
    browser.close()
