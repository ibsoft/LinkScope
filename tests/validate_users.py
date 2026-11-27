#!/usr/bin/env python3
"""Portable checks: real QR decoding, source/resource assertions. Not C# runtime validation."""
from pathlib import Path
import subprocess,json,re,base64,hmac,hashlib,struct,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];src=ROOT/'src'
# Decode the locally bundled QR output rather than only checking that a canvas is drawn.
uri='otpauth://totp/LinkScope:viewer-test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=LinkScope&algorithm=SHA1&digits=6&period=30'
js=f'global.window={{}};require({json.dumps(str(src/"local-qr.js"))});console.log(JSON.stringify(window.LinkScopeQR({json.dumps(uri)})));'
qr=json.loads(subprocess.check_output(['node','-e',js],text=True));assert len(qr)==len(qr[0]) and len(qr)>=21
try:
 import cv2,numpy as np
 image=np.pad(np.where(np.array(qr),0,255).astype('uint8'),4,constant_values=255)
 image=np.repeat(np.repeat(image,8,axis=0),8,axis=1)
 result,_,_=cv2.QRCodeDetector().detectAndDecode(image);assert result==uri,(result,uri)
 print('PASS: real locally generated authenticator QR decoded to exact otpauth URI')
except ImportError:
 print('SKIP: QR image decoder unavailable; matrix generation passed')
# Independent RFC reference vector; actual C# implementation is tested by Windows --self-test.
k=b'12345678901234567890';mac=hmac.new(k,struct.pack('>Q',1),hashlib.sha1).digest();offset=mac[-1]&15;assert (int.from_bytes(mac[offset:offset+4],'big')&0x7fffffff)%1000000==287082
web=(src/'Web.cs').read_text();accounts=(src/'UserAccounts.cs').read_text();access=(src/'Access.cs').read_text();passwords=(src/'AdminPasswords.cs').read_text()
assert 'if(!session.IsAdmin&&!ViewerAllowed(r.Path,post))Deny();' in web
assert 'if(session==null){if(post)Deny();' in web
assert 'bool view=session!=null;' in web
reads=re.search(r'ViewerReads=new HashSet<string>\(StringComparer.Ordinal\)\{([^}]+)\}',web).group(1)
assert all('"'+x+'"' not in reads for x in ['/users','/ui/users','/ui/settings','/ui/tokens','/audit','/ui/audit','/ui/ai','/ui/restart'])
assert 'post?route=="/auth/logout"||route=="/ui/account"' in web
assert 'Reauthenticate(session,input,ip);access.Users.Manage(session,input)' in web
assert 'X-CSRF-Token' in web and 'request' not in re.search(r'static object Public\(ManagedUser u\).*?;}',accounts).group(0)
public=re.search(r'static object Public\(ManagedUser u\).*?;}',accounts).group(0);assert all(x not in public for x in ['u.Password.Hash','u.Password.Salt','u.LegacyRevision','MfaProtected=','u.Revision'])
assert '600000, HashAlgorithmName.SHA256' in passwords and 'password.Length < 12' in passwords
assert 'ProtectedData.Protect' in accounts and 'DataProtectionScope.LocalMachine' in accounts and 'n>last' in accounts and 'u.LastStep=step;Save(records)' in accounts
assert 'Users.Revision(s.Username)' in access and 'ChangeRequired' in access and 'MfaRequired' in access
assert 'username=="admin"||username==actor.Username' in accounts and 'actor.IsAdmin' in accounts
assert 'AuditActor=actor==null?"Unauthenticated":actor.Username' in web
assert 'Cache-Control: no-store' in (src/'Http.cs').read_text()
for f in ['users.js','toast.js','app.js','local-qr.js']:subprocess.run(['node','--check',str(src/f)],check=True)
for page in ['users','account']:
 html=(src/(page+'.html')).read_text();assert 'class="ls-version-footer"' in html and '{{version}}' in html and '/assets/local-qr.js' in html
xml=ET.parse(ROOT/'LinkScope.csproj');ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
items={n.get('Include') for n in xml.findall('.//m:EmbeddedResource',ns)}
for f in ['users.html','account.html','users.js','users.css','local-qr.js']:
 assert 'src\\'+f in items and '/resource:src\\'+f+','+f in (ROOT/'Build.cmd').read_text()
assert 'src\\UserAccounts.cs' in {n.get('Include') for n in xml.findall('.//m:Compile',ns)} and (src/'UserAccounts.cs').is_file()
assert 'CheckManagedAccounts(dir)' in (src/'SelfCheck.cs').read_text()
print('PASS: role/CSRF gates, password derivation and MFA replay source checks, audit attribution, resource parity and JavaScript syntax')
print('Pending: Windows compilation, C# self-tests, browser login/enrollment, authorization and DPAPI runtime validation.')
