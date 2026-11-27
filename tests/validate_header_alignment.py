"""Offline Chromium header layout test; no navigation or Windows backend needed.
Requires Python playwright and Chromium. Uses actual page CSS and server header
markup, with sample substitutions for the server-rendered account fields.
"""
from pathlib import Path
import re, os, base64
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]; SRC=ROOT/'src'
PAGES=tuple(os.environ.get('LINKSCOPE_HEADER_TEST_PAGES','dashboard,system,integrity,endpoint,alerts,logs,audit,ai,settings,users,account').split(','))
ASSETS=dict(re.findall(r'Asset\("/assets/([^"\n]+)","([^"\n]+)","text/css"\)',(SRC/'Web.cs').read_text()))
ICON='data:image/x-icon;base64,'+base64.b64encode((ROOT/'linkscope.ico').read_bytes()).decode()
VALUES={'brand':'LinkScope','admin-hidden':'','account-identity':'admin · Admin','unread-count':'3','unread-hidden':'','unread-label':'3 unread monitoring alerts','version':'v_test'}

def fixture(name,admin):
    html=(SRC/(name+'.html')).read_text()
    body_html=re.search(r'<body\b[^>]*>.*?</body>',html,re.S).group(0)
    # Keep the complete page markup, including forms, tables and footer,
    # while omitting backend-dependent scripts.
    body_html=re.sub(r'<script\b[^>]*>.*?</script>','',body_html,flags=re.S|re.I)
    header=body_html
    for key,value in VALUES.items():
        header=header.replace('{{'+key+'}}','hidden' if not admin and key=='admin-hidden' else value)
    header=header.replace('/assets/linkscope.ico',ICON)
    css=[]
    for url in re.findall(r'<link\b[^>]*href="/assets/([^"\n]+\.css)"[^>]*>',html):
        css.append((SRC/ASSETS.get(url,url)).read_text())
    # Execute only the existing shared theme/menu script, after parsing.
    return '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>'+ '\n'.join(css)+'</style></head>'+header.replace('</body>','<script>'+(SRC/'theme.js').read_text()+'</script></body>')+'</html>'

def center(r): return r['y']+r['height']/2
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu'])
    page=browser.new_page(viewport={'width':1485,'height':300})
    cases=0
    for name in PAGES:
      for admin in (True,False):
        page.set_content(fixture(name,admin),wait_until='domcontentloaded')
        for width in (1920,1485,1366,1300,1280,768,390,320):
          page.set_viewport_size({'width':width,'height':300})
          page.wait_for_timeout(60)
          for theme in ('light','dark'):
            page.locator('html').evaluate('(el,t)=>el.dataset.theme=t',theme)
            bar=page.locator('.ls-header-inner'); nav=page.locator('#ls-main-nav'); toggle=page.locator('#ls-menu-toggle')
            brand=page.locator('.ls-header-inner .brand'); tools=page.locator('.ls-tools')
            br=bar.bounding_box(); by=center(br)
            assert br['height']<=60,(name,width,'header height',br)
            assert abs(center(brand.bounding_box())-(by-3))<.6,(name,width,'brand')
            assert abs(center(tools.bounding_box())-by)<.6,(name,width,'tools')
            logo=page.locator('.ls-brand-icon').bounding_box();text=page.locator('.ls-brand-name').bounding_box()
            assert abs(center(logo)-(by-3))<.6 and abs(center(text)-(by-3))<.6,(name,width,'brand icon/text')
            controls=page.locator('.ls-tools .ls-icon, .ls-tools #ls-theme-switch').all()
            rects=[c.bounding_box() for c in controls]
            assert len(rects)==3 and all(abs(center(r)-by)<.6 for r in rects),(name,width,'utility alignment')
            assert all(r['x']>=0 and r['x']+r['width']<=width+.5 for r in rects),(name,width,'utility overflow')
            assert all(abs(r['height']-rects[0]['height'])<.1 for r in rects)
            for c in controls:
                glyph=c.locator('svg:visible');assert glyph.count()==1,(name,width,'one utility glyph')
                gr=glyph.bounding_box();cr=c.bounding_box()
                assert abs(center(gr)-by)<.6 and abs(gr['x']+gr['width']/2-(cr['x']+cr['width']/2))<.6,(name,width,'utility glyph alignment',gr,cr)
            main=page.locator('main');mr=main.bounding_box()
            assert abs(mr['x']-br['x'])<.6 and abs(mr['width']-br['width'])<.6,(name,width,'shared workspace',mr,br)
            bodyrect=page.locator('body').bounding_box()
            assert abs(br['x']-(bodyrect['x']+(bodyrect['width']-br['width'])/2))<1,(name,width,'workspace center',br,bodyrect)
            if width>=768:
                assert abs(br['x']+br['width']/2-width/2)<1,(name,width,'symmetric scrollbar gutters',br)
            # Match actual content edges, not only the outer container boxes.
            for edge in ('paddingLeft','paddingRight'):
                bp=bar.evaluate('(el,p)=>parseFloat(getComputedStyle(el)[p])',edge)
                mp=main.evaluate('(el,p)=>parseFloat(getComputedStyle(el)[p])',edge)
                assert abs(bp-mp)<.6,(name,width,'shared content gutter',edge,bp,mp)
            if not toggle.is_visible():
              links=nav.locator('a:visible').all(); assert links
              rows=[a.bounding_box() for a in links]; nb=nav.bounding_box()
              assert all(abs(center(r)-by)<.6 and abs(r['height']-rects[0]['height'])<.1 for r in rows),(name,width,'link alignment')
              assert all(abs(center(a.locator('svg').bounding_box())-by)<.6 for a in links),(name,width,'icon alignment')
              assert all(abs(center(a.locator('.ls-nav-label').bounding_box())-by)<.6 for a in links),(name,width,'label alignment')
              assert all(abs(a.locator('.ls-nav-label').bounding_box()['height']-20)<.1 for a in links),(name,width,'label line height')
              assert rows[0]['x']>=nb['x']-.5 and rows[-1]['x']+rows[-1]['width']<=nb['x']+nb['width']+.5,(name,width,'nav overflow')
              assert abs(rows[0]['x']-nb['x'])<1,(name,width,'nav starts at left')
              bb=brand.bounding_box();gap=rows[0]['x']-(bb['x']+bb['width'])
              assert 11<=gap<=13,(name,width,'brand-to-menu gap',gap)
              assert rows[-1]['x']+rows[-1]['width']<=tools.bounding_box()['x']-11,(name,width,'utility separation')
              assert rows[-1]['x']+rows[-1]['width']<=nb['x']+nb['width']+.5,(name,width,'compact links fit')
              assert brand.evaluate('(el)=>getComputedStyle(el).fontSize')=='29px'
              assert brand.evaluate('(el)=>getComputedStyle(el).fontWeight')=='700'
              gaps=[b['x']-(a['x']+a['width']) for a,b in zip(rows,rows[1:])]
              assert gaps and all(abs(g-4)<.6 for g in gaps),(name,width,'compact fixed spacing',gaps)
            else:
              assert not nav.is_visible() and all(r['height']>=44 for r in rects),(name,width,'compact layout')
              assert abs(center(toggle.bounding_box())-by)<.6,(name,width,'toggle alignment')
              toggle.click();assert nav.is_visible(),(name,width,'open menu')
              assert all(a.bounding_box()['height']>=44 for a in nav.locator('a:visible').all())
              page.keyboard.press('Escape');assert not nav.is_visible(),(name,width,'close menu')
            # Inspect actual SVG paint, not just the geometry of its enclosing button.
            account=page.locator('.ls-tools .ls-account');account.locator('summary').click()
            menu=account.locator('.ls-account-menu')
            assert menu.is_visible(),(name,width,theme,'account menu not visible')
            colors=menu.locator('a:visible,button:visible').evaluate_all("""els=>els.map(el=>{
              const svg=el.querySelector('svg'),shape=svg?.querySelector('path,circle,rect');
              if(!svg||!shape)return null;
              const stroke=svg.getAttribute('stroke')==='currentColor';
              return {label:getComputedStyle(el).color,icon:getComputedStyle(svg).color,paint:stroke?getComputedStyle(shape).stroke:getComputedStyle(shape).fill};
            })""")
            assert colors and all(x and x['label']==x['icon']==x['paint']==colors[0]['label'] for x in colors),(name,width,theme,'dropdown paint mismatch',colors)
            account.locator('summary').click()
            cases+=1
      print('PASS',name,flush=True)
    print('PASS:',cases,'full-page offline header layout cases (desktop/mobile, light/dark, Admin/Viewer)')
    browser.close()
