"""Browser regression checks against real page assets, mocked service data.
Requires Python playwright + Chromium; does not exercise Windows server/API or setup.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
import json, os
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'
PAGES={'/':'dashboard','/system':'system','/integrity':'integrity','/endpoint':'endpoint','/alerts':'alerts','/logs':'logs','/audit':'audit','/ai':'ai','/settings':'settings','/users':'users','/account':'account'}
# Use actual server routes (audit is /audit in this release).
import re
web=(SRC/'Web.cs').read_text()
assert 'Asset("/audit","audit.html"' in web
CSP="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"
def render_page(s,admin=True):
    for key,value in {'brand':'LinkScope','version':'v_test','admin-hidden':'' if admin else 'hidden','account-identity':'admin · Admin' if admin else 'viewer · Viewer','unread-count':'25','unread-hidden':'','unread-label':'25 unread monitoring alerts'}.items():s=s.replace('{{'+key+'}}',value)
    return s
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu'])
    context=browser.new_context(viewport={'width':1536,'height':900},service_workers='block')
    page=context.new_page()
    requests=[]
    def handle(route):
        from urllib.parse import urlparse
        path=urlparse(route.request.url).path
        if path in PAGES or path=='/login':
            f=SRC/(PAGES.get(path,'login')+'.html')
            route.fulfill(status=200,body=render_page(f.read_text()),content_type='text/html',headers={'Content-Security-Policy':CSP});return
        if path.startswith('/assets/'):
            name=path.split('/')[-1];name={'toast-pale-v2.css':'toast.css','theme-pale-v2.css':'theme.css','theme-nowrap-v3.css':'theme.css','theme-nowrap-v3.js':'theme.js','theme-version-v4.css':'theme.css','theme-version-v4.js':'theme.js','app-endpoint-v4.js':'app.js','app-endpoint-v5.js':'app.js','app-endpoint-v6.js':'app.js','theme-navigation-v7.css':'theme.css','theme-workspace-v11.css':'theme.css','app-login-v7.js':'app.js','app-response-defaults-v10.js':'app.js','app-quarantine-v12.js':'app.js','app-settings-v12.css':'app.css','toast-endpoint-v4.js':'toast.js','toast-mfa-v5.js':'toast.js','theme-stable-v9.js':'theme.js','toast-stable-v6.js':'toast.js','navigation-v11.css':'navigation.css','navigation-v12.css':'navigation.css','navigation-v14.css':'navigation.css','navigation-v16.css':'navigation.css','app-security-details-v16.css':'app.css','app-security-details-v16.js':'app.js','report-quarantine-v10.js':'report.js','report-signature-schedule-v11.js':'report.js','app-signature-schedule-v17.js':'app.js'}.get(name,name)
            if name=='linkscope.ico': route.fulfill(path=str(ROOT/name),content_type='image/x-icon');return
            if (SRC/name).exists():
                mime={'.css':'text/css','.js':'application/javascript','.png':'image/png'}.get((SRC/name).suffix,'application/octet-stream')
                route.fulfill(path=str(SRC/name),content_type=mime);return
        if path=='/ui/session':
            route.fulfill(json={'admin':True,'authenticated':True,'username':'admin','role':'Admin','mfaEnabled':True,'csrf':'test','brandLabel':''});return
        if path=='/ui/alerts':
            route.fulfill(json={'admin':True,'authenticated':True,'username':'admin','role':'Admin','mfaEnabled':True,'brandLabel':'','feed':{'alerts':[],'unread':25,'cursor':0,'more':False}});return
        if path=='/ui/report': requests.append(path)
        route.fulfill(status=503,json={'error':'Mocked backend unavailable'})
    page.route('**/*',handle)
    for path in PAGES:
        page.set_viewport_size({'width':1536,'height':900});page.goto('http://127.0.0.1:9876'+path,wait_until='domcontentloaded');page.locator('#ls-theme-switch').wait_for()
        for w in (1536,1440,1366,1280,1024,768,390,320):
            page.set_viewport_size({'width':w,'height':900});page.wait_for_timeout(60)
            head=page.locator('.ls-header-inner');nav=page.locator('#ls-main-nav');toggle=page.locator('#ls-menu-toggle');tools=page.locator('.ls-tools')
            assert head.bounding_box()['height']<=60,(path,w,head.bounding_box())
            assert head.evaluate('(n)=>getComputedStyle(n).display')=='grid'
            visible=[page.locator('.ls-header-inner .brand'),tools]
            if toggle.is_visible(): visible.append(toggle)
            else: visible.append(nav)
            boxes=[x.bounding_box() for x in visible]
            assert max(b['y']+b['height']/2 for b in boxes)-min(b['y']+b['height']/2 for b in boxes)<=1,(path,w,boxes)
            assert tools.evaluate('(n)=>getComputedStyle(n).flexWrap')=='nowrap'
            assert tools.is_visible() and tools.bounding_box()['x']+tools.bounding_box()['width']<=w,(path,w,'tools overflow')
            assert page.locator('.ls-brand-icon').is_visible(),(path,w,'missing icon')
            assert page.locator('#global-export').text_content().strip()=='Report'
            assert page.locator('#ls-main-nav svg[data-fa]').count()==8
            assert page.locator('.ls-tools .ls-icon svg[data-fa],.ls-tools #ls-theme-switch svg[data-fa]:visible').count()==3
            if not toggle.is_visible():
                assert w>=1300,(path,w,'unexpected full menu')
                assert nav.evaluate('(n)=>n.scrollWidth<=n.clientWidth+1'),(path,w,'overflow')
                assert nav.bounding_box()['x']+nav.bounding_box()['width']<=tools.bounding_box()['x']+1
            else:
                assert toggle.is_visible() and not nav.is_visible(),(path,w,'mobile toggle')
                toggle.click();assert nav.is_visible() and nav.locator('a').count()==8
                assert toggle.locator('svg[data-fa=times]').count()==1
                r=nav.bounding_box();assert r['x']>=0 and r['x']+r['width']<=w,(path,w,r)
                assert all(a.bounding_box()['height']>=44 for a in nav.locator('a').all()),(path,w,'touch size')
                page.keyboard.press('Escape');assert not nav.is_visible() and toggle.get_attribute('aria-expanded')=='false'
        assert page.locator('.ls-account-menu #global-export').count()==1
        assert page.locator('#ls-main-nav a[href="/settings"]').count()==0
        print('PASS:',path,'8 viewport widths, keyboard menu and utility icons')
    page.set_viewport_size({'width':390,'height':844});page.goto('http://127.0.0.1:9876/endpoint');page.locator('#ls-menu-toggle').wait_for();page.locator('.ls-account summary').click();page.locator('#global-export').click();page.wait_for_timeout(300)
    assert requests and not page.locator('.ls-account-menu').is_visible() and page.url.endswith('/endpoint'),('report link',requests,page.url)
    # Theme still persists; login still has no navigation.
    page.locator('#ls-theme-switch').click();assert page.locator('html').get_attribute('data-theme')=='dark'
    page.goto('http://127.0.0.1:9876/system');assert page.locator('html').get_attribute('data-theme')=='dark'
    page.goto('http://127.0.0.1:9876/login');assert not page.locator('#ls-main-nav').count()
    print('PASS: Report invokes existing export pipeline, theme persistence, login has no menu')
    browser.close()
