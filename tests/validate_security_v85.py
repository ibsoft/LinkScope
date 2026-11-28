"""Portable source contracts and actual browser-generated request nonces. Native C# self-test is separate."""
from pathlib import Path
import os,re,subprocess
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]; src=root/'src'
web=(src/'Web.cs').read_text(); http=(src/'Http.cs').read_text(); access=(src/'Access.cs').read_text(); program=(src/'Program.cs').read_text()
assert 'active.Count>=24||n>=12' in web and 'requestRate.Allow(ip)' in web
assert web.index('if(!session.IsAdmin&&!ViewerAllowed')<web.index('session.ConsumeMutation')
assert web.index('if(value==null)throw')<web.index('access.Logout(r.Cookie(CookieName()))')
assert 'mutations.Contains(nonce)' in access and 'mutations.Count>=4096' in access
assert 'peers.Count>=1024' in http and 'Stopwatch.StartNew()' in http
assert 'r.Header("Upgrade")!=null' in http and '48*1024' in http
assert 'PolicyPath' in http and 'next.Validate();next.ValidateConfig(cfg)' in http and 'AdminPasswords.Installed.Revision()==null' in http
assert 'ProductionTransportPolicy.Initialize(c)' in program and 'CheckCertificateRevocationList=true' in program
assert 'ProductionTransportPolicy.ValidateConfiguration(next)' in web
for f in ['AiProvider.cs','SiemSender.cs']:
 s=(src/f).read_text(); assert 'OutboundGuard.ValidateHttp(destination)' in s and 'if(strict)req.Proxy=null' in s and 'AllowAutoRedirect=false' in s
for f in ['SmtpTransport.cs','SyslogSender.cs']:
 s=(src/f).read_text(); assert 'OutboundGuard.ValidateAddresses' in s and 'ProductionTransportPolicy.Check' in s and 'SslProtocols.Tls12,true' in s
for f in ['app.js','ai.js','dashboard.js','toast.js','users.js']:
 s=(src/f).read_text(); assert "'X-Request-Nonce':Array.from(crypto.getRandomValues(new Uint8Array(16))" in s; subprocess.run(['node','--check',str(src/f)],check=True)
assert 'Check(replay,"duplicate mutation rejected")' in (src/'SelfCheck.cs').read_text()
js=(src/'app.js').read_text().split('const notice=',1)[0]
with sync_playwright() as pw:
 browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page();page.set_content('<body data-page="endpoint"></body>');page.add_script_tag(content=js)
 values=page.evaluate('''async()=>{csrf='test';const nonces=[];window.fetch=async(path,opt)=>{if(opt.method==='POST'){if(opt.headers['X-CSRF-Token']!=='test')throw Error('missing CSRF');nonces.push(opt.headers['X-Request-Nonce']);}return new Response('{}');};for(let i=0;i<20;i++)await request('/ui/endpoint-scan',{});await request('/ui/endpoint');return nonces;}''')
 assert len(values)==20 and len(set(values))==20 and all(re.fullmatch('[a-f0-9]{32}',x) for x in values)
 browser.close()
subprocess.run(['python',str(root/'tools/Check-Dependencies.py')],check=True)
print('PASS: security source contracts, browser mutation nonces, local dependency integrity; native enforcement requires Windows self-test.')
