"""Exercise the six-step workflow with real Chromium and mocked API responses."""
from pathlib import Path
import re, os
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
html=(src/'endpoint.html').read_text();js=(src/'app.js').read_text();css='\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css'))
html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('</head>','<style>'+css+'</style></head>').replace('{{brand}}','LinkScope').replace('{{version}}','V58')
js=js[:js.rindex('LinkScopeBusy.run(')]
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(html.replace('{{admin-hidden}}',''))
    page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";setupEndpointWorkspace();')
    page.evaluate(r'''()=>{window.calls=[];request=async(path,data)=>{calls.push({path,data});return {utc:'2026-11-28T07:00:00Z',checks:[{name:'Containment policy',state:'Review',evidence:'Protect mode'},{name:'Security log readability',state:'Pass',evidence:'Record 1'},{name:'Lab writer correlation',state:data.marker?'Pass':'Not tested',evidence:'Matching writer'},{name:'Lab process identity',state:data.marker?'Pass':'Not tested',evidence:'Query only'},{name:'Live quarantine and termination',state:'Not tested',evidence:'No termination'}]}};renderContainmentReadiness({ageSeconds:1,collectedUtc:'2026-11-28T07:00:00Z',result:{responseCheckedUtc:'2026-11-28T06:59:50Z',lastSignatureCheckUtc:'2026-11-28T06:59:50Z',status:'partial',mode:'protect',engineOnline:true,signatureFreshness:'Current',responseEngineStatus:'Ready',testPaths:['C:\Test'],responsePathsReadiness:[{path:'C:\Test',status:'ok',detail:'Directory list and delete-child access granted.'}],canaries:[]}});}''')
    page.locator('[data-ep-tab=tests]').click()
    def go(n):
        page.locator(f'[data-test-step="{n}"]').click();assert page.locator('[data-test-panel]:visible').count()==1;assert page.locator(f'[data-test-panel="{n}"]').is_visible();assert page.locator(f'[data-test-step="{n}"]').get_attribute('aria-current')=='step'
    assert page.locator('[data-test-panel="1"]').is_visible();assert page.locator('#ep-step-back').is_disabled()
    page.locator('#ep-step-next').click();assert page.locator('[data-test-panel="2"]').is_visible()
    page.locator('#ep-test-run').click();page.locator('#ep-test-status').get_by_text('Diagnostics completed',exact=False).wait_for();assert page.evaluate('calls[0].data.marker')=='';assert 'to review' in page.locator('#ep-step-state-2').inner_text() and 'Required check was not returned' in page.locator('#ep-test-results').inner_text();assert 'Lab writer correlation' not in page.locator('#ep-test-results').inner_text()
    go(4);page.locator('[data-test-panel="4"] details summary').click();assert page.locator('#ep-writer-run').is_disabled();marker=r'C:\Test\LinkScope-Containment-Lab-0123456789abcdef0123456789abcdef\audit-marker.txt';page.locator('#ep-test-marker').fill(marker);page.locator('#ep-writer-run').click();page.locator('#ep-writer-status').get_by_text('Writer diagnostics completed',exact=False).wait_for();assert page.evaluate('calls[1].data.marker')==marker;assert 'query-only identity' in page.locator('#ep-step-state-4').inner_text();assert 'Containment policy' not in page.locator('#ep-writer-results').inner_text()
    go(6);assert page.locator('#ep-step-state-5').inner_text()=='Not run';assert 'Not run' in page.locator('#ep-test-review').inner_text();assert page.locator('#ep-step-next').is_hidden();assert page.evaluate('new Set([...document.querySelectorAll("[id]")].map(e=>e.id)).size===document.querySelectorAll("[id]").length')
    for theme in ('light','dark'):
        page.evaluate('t=>document.documentElement.dataset.theme=t',theme)
        for width in (1440,1024,768,390,320):
            page.set_viewport_size({'width':width,'height':800})
            for i in range(1,7):
                go(i);assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),(theme,width,i)
    page.set_viewport_size({'width':1366,'height':900});page.evaluate('document.documentElement.dataset.theme="light"');go(1)
    if os.environ.get('V58_SCREENSHOT'):page.locator('#ep-test-center').screenshot(path=os.environ['V58_SCREENSHOT'])
    # Viewer markup should keep existing admin restrictions.
    viewer=browser.new_page();viewer.set_content(html.replace('{{admin-hidden}}','hidden'));viewer.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};setupEndpointWorkspace();');assert viewer.locator('[data-ep-tab=tests]').is_hidden();viewer.evaluate('selectEndpointView("tests");epSelectStep(2,false)');assert viewer.locator('#ep-test-run').is_hidden();viewer.evaluate('epSelectStep(3,false)');assert viewer.locator('#ep-audit-probe').is_hidden();viewer.evaluate('epSelectStep(4,false)');assert viewer.locator('#ep-writer-run').is_hidden();browser.close()
print('PASS: six-stage navigation, separate read-only/external requests, session review, no manual auto-pass, viewer control visibility, all stages 320–1440 px light/dark (mock API)')
