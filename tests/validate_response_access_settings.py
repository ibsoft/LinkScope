"""Portable checks of the fixed-action ClamD query ACL helper and settings markup.
Does not execute Windows ACL, installer, process or ClamAV operations.
"""
from pathlib import Path
from html.parser import HTMLParser
import re, sqlite3, subprocess, json
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'
read=lambda n:(SRC/n).read_text()
response=read('EndpointResponse.cs'); worker=read('ClamUpdateWorker.cs'); program=read('Program.cs'); task=read('hardware-task.ps1'); scanner=read('EndpointProtection.cs'); app=read('app.js'); web=read('Web.cs'); html=read('settings.html'); css=read('app.css')
helper=response.split('internal static bool RefreshClamPeerAccess(',1)[1].split('internal static string CheckResponseEngine',1)[0]
assert 'identity.IsSystem' in helper
assert 'const uint QueryLimited=0x1000' in response
assert 'AceQualifier.AccessAllowed,(int)QueryLimited,serviceSid,false,null' in helper
assert 'SetKernelObjectSecurity(proc,DaclInformation,updated)' in helper
assert 'LiveImage(proc,expected)' in helper and 'StandardClamdResponsePid()!=pid' in helper
assert 'if(acl==null)' in helper and 'acl.InsertAce' in helper and 'RemoveAce' not in helper
assert '.Kill(' not in helper and 'TerminateProcess' not in helper
registered=worker.split('internal static uint StandardClamdResponsePid()',1)[1].split('static uint ServicePid',1)[0]
for marker in ['NativeService("clamd",ClamdExe)','LoopbackOnly()','VerifyClamPath(ClamdExe)','ClamCommand("PING")','ClamdPid()!=pid']:
    assert marker in registered,marker
entry=program.split('static int RefreshInstalledClamPeerAccess()',1)[1].split('static int UpdateInstalledSignatures()',1)[0]
for marker in ['id.IsSystem','Assembly.GetExecutingAssembly().Location,ServiceExe','RegisteredCommand(),ServiceCommand(ServiceExe)','maintenance.lock','policy.Mode=="monitor"','policy.Port!=3310','policy.TrustedEnginePath,standard','RefreshClamPeerAccess(ServiceSid())']:
    assert marker in entry,marker
assert "$peerAction.Path=$exe" in task and "$peerAction.Arguments='--clam-peer-access-installed'" in task
assert "$peerDef.Principal.UserId='SYSTEM'" in task and "$peerTrigger.Repetition.Interval='PT1M'" in task
assert "RegisterTaskDefinition($peerName,$peerDef,6,'SYSTEM',$null,5,'D:P(A;;GA;;;SY)(A;;GA;;;BA)')" in task
assert '--clam-peer-access-installed' not in web
assert 'Unregister-ScheduledTask -TaskPath \'\\\' -TaskName $peerName' in task
# The destructive operation still verifies the actual connected peer and rechecks the file hash.
quarantine=response.split('internal static string Quarantine(',1)[1].split('internal static string Contain(',1)[0]
assert 'Confirmed(EndpointProtection.Command(c.Port,"INSTREAM",stream,stop,tcp=>VerifyEngine(c,tcp)))' in quarantine
assert 'if(hash!=expected)' in quarantine and 'if(!authorized()||stop.WaitOne(0))' in quarantine
assert 'VerifyHandle(handle,path)' in quarantine and 'SetFileInformationByHandle' in quarantine
assert 'responseEngineStatus' in scanner and 'CheckResponseReadiness(db,c,stop,now,force)' in scanner
assert 'Resolve(db,p,"Malware quarantined");Resolve(db,p,"Quarantine withheld or failed")' in scanner
assert 'ResponseRetryAllowed(db,p,hash)' in scanner
assert 'Convert.ToInt64(prior[0])<responseVerifiedEpoch' in scanner
assert 'StartsWith("IOException: Cannot inspect ClamD peer process"' in scanner
assert 'Response engine verification unavailable' in scanner
for name in ['AiEvidence.cs','report.js','app.js']:
    assert 'responseEngineStatus' in read(name),name
# Exercise native settings markup structure and make sure all controls remain in their original form.
class Settings(HTMLParser):
    def __init__(self):super().__init__();self.ids=[];self.categories=[];self.forms=[];self.depth=0
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if 'id' in a:self.ids.append(a['id'])
        if tag=='details' and 'settings-category' in a.get('class','').split():self.categories.append(a['id'])
        if tag=='form':self.depth+=1;assert self.depth==1;self.forms.append(a.get('id'))
    def handle_endtag(self,tag):
        if tag=='form':self.depth-=1
parser=Settings();parser.feed(html)
assert len(parser.categories)==16 and len(set(parser.categories))==16
assert len(parser.ids)==len(set(parser.ids))
assert parser.forms==['configForm','tokenForm'] and parser.depth==0
assert len(re.findall(r'<details class="settings-category"[^>]*\sopen(?:\s[^>]*)?>',html))==1
for name in ('EndpointSuggestedResponse','EndpointSuggestedExecutable','EndpointTrustedEngineSha256'):
    assert re.search(r'<div class="settings-field-action"><label class="field">[^<]*<(?:select|input) id="'+name+'"',html),name
assert 'form.addEventListener(\'invalid\'' in app and "if(location.hash)revealCategory();" in app
assert 'settings-expand-all' in html and 'settings-collapse-all' in html
assert 'grid-template-columns:minmax(0,1fr) auto;align-items:end' in css
assert '[data-theme=dark] body[data-page=settings] .settings-category[open]>summary' in css
print('PASS: SYSTEM-only fixed standard ClamD helper, query-only ACL, fail-closed quarantine verification, response diagnostics, repair cooldown and all 16 accessible settings categories (source checks).')
print('Pending Windows test: actual ACL changes, task execution, ClamD restarts, quarantine and C# compilation.')
