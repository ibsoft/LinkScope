"""Check real account-menu SVG paint in Chromium for every authenticated template.
Uses real header HTML and CSS assets in an isolated browser, not the Windows server. Requires Playwright/Chromium.
"""
from pathlib import Path
import os, re, xml.etree.ElementTree as ET
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'
PAGES={'/':'dashboard','/system':'system','/integrity':'integrity','/endpoint':'endpoint','/alerts':'alerts','/logs':'logs','/audit':'audit','/ai':'ai','/settings':'settings','/users':'users','/account':'account'}
assets=dict(re.findall(r'Asset\("(/assets/[^"\n]+)","([^"\n]+)","[^"\n]+"\)',(SRC/'Web.cs').read_text()))
for route, name in PAGES.items():
    html=(SRC/(name+'.html')).read_text()
    menu=re.search(r'<div class="ls-account-menu">(.*?)</div>',html,re.S).group(1)
    icons=re.findall(r'<svg\b.*?</svg>',menu,re.S)
    assert len(icons)==6,(name,len(icons))
    for icon in icons:
        svg=ET.fromstring(icon)
        assert (svg.get('fill'),svg.get('stroke'),svg.get('viewBox'),svg.get('stroke-width'))==('none','currentColor','0 0 24 24','1.8'),name
    assert '/assets/navigation-v24.css' in html
assert assets['/assets/navigation-v24.css']=='navigation.css'

with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage'])
    context=browser.new_context(service_workers='block',viewport={'width':1440,'height':900})
    page=context.new_page()
    for route,name in PAGES.items():
        # Render the actual header and all page styles in their original cascade
        # order without HTTP or application scripts. This isolates CSS paint.
        html=(SRC/(name+'.html')).read_text()
        styles=[]
        for url in re.findall(r'<link rel="stylesheet" href="([^"]+)"',html):
            styles.append((SRC/assets.get(url,url.split('/')[-1])).read_text())
        header=re.search(r'<header class="ls-header">.*?</header>',html,re.S).group()
        for k,v in {'brand':'LinkScope','version':'test','admin-hidden':'','account-identity':'admin · Admin','unread-count':'0','unread-hidden':'hidden','unread-label':'No unread alerts'}.items():
            header=header.replace('{{'+k+'}}',v)
        page.set_content('<!doctype html><html><head><style>'+ '\n'.join(styles)+'</style></head><body data-page="'+name+'">'+header+'</body></html>')
        for width in (1440,390):
            page.set_viewport_size({'width':width,'height':900})
            for theme,expected in [('light','rgb(23, 51, 60)'),('dark','rgb(225, 237, 243)')]:
                page.evaluate('t=>{document.documentElement.dataset.theme=t; document.querySelector(".ls-account").open=true}',theme)
                items=page.locator('.ls-account-menu :is(a,button)')
                assert items.count()==6
                for item in items.all():
                    if item.is_visible(): item.hover()
                    result=item.evaluate('''n=>{const svg=n.querySelector('svg'),s=getComputedStyle(svg),c=getComputedStyle(n).color;return {color:c,svg:s.color,stroke:s.stroke,fill:s.fill,w:s.width,h:s.height,shapes:[...svg.children].map(p=>{const q=getComputedStyle(p);return [q.color,q.stroke,q.fill]})}}''')
                    assert result['color']==result['svg']==result['stroke']==expected,(name,width,theme,result)
                    assert result['fill']=='none' and result['w']==result['h']=='16px',(name,result)
                    assert all(c==st==expected and f=='none' for c,st,f in result['shapes']),(name,result)
        print('PASS:',name,'six consistent icons; light/dark; desktop/mobile')
    browser.close()
