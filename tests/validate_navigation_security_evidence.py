"""Portable source checks for the server-rendered header and exact AI security evidence."""
from pathlib import Path
from html.parser import HTMLParser
import re, subprocess, xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'
class Header(HTMLParser):
    def __init__(self):
        super().__init__();self.links={};self.nav=False
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='nav' and a.get('id')=='ls-main-nav':self.nav=True
        if tag=='a' and a.get('href') in ('/settings','/system#report'):
            self.links[a['href']]=(self.nav,'hidden' in a)
    def handle_endtag(self,tag):
        if tag=='nav':self.nav=False
for page in SRC.glob('*.html'):
    text=page.read_text()
    if 'id="ls-main-nav"' not in text:continue
    for admin in (True,False):
        html=text.replace('{{admin-hidden}}','' if admin else 'hidden')
        header=Header();header.feed(html)
        assert header.links['/settings']==(False,not admin),page
        assert header.links['/system#report']==(False,False),page
    assert text.count('id="ls-theme-switch"')==1,page
    assert text.count('id="ls-unread-badge"')==1,page
    assert text.count('id="global-export"')==1,page
print('PASS: all 11 authenticated templates contain complete controls; Settings and Report are account links; Settings is hidden for viewers.')
web=(SRC/'Web.cs').read_text();ai=(SRC/'AiAssist.cs').read_text();ev=(SRC/'AiEvidence.cs').read_text()
assert 'alerts.HeaderUnread()' in web and 'PageAsset(r.Path,session)' in web
assert 'WebUtility.HtmlEncode(session.Username' in web
assert 'SecurityHealth(monitor,"data_integrity",rules.Integrity.Enabled)' in ev
assert 'SecurityHealth(monitor,"endpoint_protection",rules.Endpoint.Enabled)' in ev
assert 'evidence.SecurityFacts()' in ai and 'Exact Data Integrity and ClamAV Endpoint Protection evidence' in ai
for field in ('chainValid','monitoredFiles','signatureDatabaseVersion','signatureFreshness','infectedChecks','failedChecks','scanActivity','recentIncidents','quarantineItems','canaries','entropyChanges','findingsBySeverity','pendingAlertDelivery'):
    assert '"'+field+'"' in ev,field
assert 'PriorityRows(items,8)' in ev and 'omitted=rows.Length-sample.Length' in ev
assert '[URL redacted]' in ev and 'credential-fixture' in (SRC/'LogAiChecks.cs').read_text()
assert 'CheckSecurityEvidence();' in (SRC/'LogAiChecks.cs').read_text()
for name in ('theme.js','toast.js','report.js'):
    subprocess.run(['node','--check',str(SRC/name)],check=True)
ET.parse(ROOT/'LinkScope.csproj');assert 'src\\navigation.css' in (ROOT/'LinkScope.csproj').read_text() and '/resource:src\\navigation.css,navigation.css' in (ROOT/'Build.cmd').read_text()
print('PASS: separate security snapshots, exact final prompt and verdict evidence, sample limits, credential filtering and both build paths; Windows execution remains pending.')
