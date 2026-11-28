from pathlib import Path
import os,re
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
html=(src/'alerts.html').read_text();html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=re.sub(r'\{\{[^}]+\}\}','',html)
css='\n'.join((src/f).read_text() for f in ('app.css','toast.css','theme.css','navigation.css'))
html=html.replace('</head>','<style>'+css+'</style></head>')
fixture={'id':'alert-fixture','sequence':1,'category':'endpoint_protection','severity':'warning','title':'Possible ransomware activity (extended observation)','message':'C:\\Apache24\\test · 7 entropy changes <img src=x onerror=alert(1)>','sinceUtc':'2026-11-28T07:00:00Z','resolved':False,'read':False}
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(html);page.evaluate('()=>{for(const key of ["localStorage","sessionStorage"]){const m=new Map();Object.defineProperty(window,key,{value:{getItem:k=>m.get(k)??null,setItem:(k,v)=>m.set(k,v),removeItem:k=>m.delete(k)},configurable:true});}}')
    page.evaluate('a=>{window.calls=[];window.LinkScopeBusy={begin:()=>()=>{},run:async(_,f)=>f()};window.LinkScopePages={controls:()=>({root:document.createElement("div"),update:()=>{}})};window.fetch=async(path,opt)=>{calls.push([path,opt?.method]);const session={admin:true,authenticated:true,csrf:"test",username:"admin",mfaEnabled:true,feed:{alerts:[],unread:1,cursor:1}};const body=String(path).includes("/search")?{alerts:[a],through:1,page:1,size:25,pages:1,total:1,unread:1,categories:[a.category]}:session;return {ok:true,json:async()=>body};};}',fixture)
    page.add_script_tag(content=(src/'toast.js').read_text());page.locator('#history-list tr').wait_for();page.locator('#history-list tr td').first.click();dialog=page.locator('#ls-alert-detail');assert dialog.is_visible();assert dialog.locator('pre').inner_text()==fixture['message'];assert dialog.locator('img').count()==0;assert 'not a confirmed malware signature' in dialog.inner_text();assert 'Recommended investigation' in dialog.inner_text();assert not page.evaluate('calls.some(x=>x[1]==="POST")');page.keyboard.press('Escape');assert not dialog.is_visible();page.locator('.ls-alert-detail-button').focus();page.keyboard.press('Enter');assert dialog.is_visible()
    for theme in ('light','dark'):
        page.evaluate('t=>document.documentElement.dataset.theme=t',theme)
        for width in (320,390,768,1366):
            page.set_viewport_size({'width':width,'height':740});assert dialog.evaluate('d=>d.getBoundingClientRect().width <= innerWidth && d.scrollWidth <= d.clientWidth+1'),(theme,width)
    dialog.get_by_role('button',name='Close',exact=True).click();assert not dialog.is_visible();assert page.locator('#history-list tr.unread').count()==1
    page.evaluate('()=>LinkScopeToast.openAlert({title:"Unknown alert",category:"unknown",severity:"info",resolved:true})');assert 'No detailed evidence was stored' in dialog.inner_text();assert 'does not establish a more specific cause' in dialog.inner_text();browser.close()
print('PASS: actual Alert History row/modal, keyboard close/open, unchanged acknowledgement, safe literal evidence, missing-data fallback, responsive modal (320–1366 px, light/dark).')
