"""Static assertions for automatic ClamAV setup, not Windows integration tests."""
from pathlib import Path
import base64, re, xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
setup=(root/'setup/Setup.cs').read_text(); clam=(root/'setup/ClamSetup.cs').read_text(); wizard=(root/'setup/wizard.ps1').read_text()
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
project=ET.parse(root/'setup/LinkScope.Setup.csproj')
assert set(n.attrib['Include'] for n in project.findall('.//m:Compile',ns)) == {'Setup.cs','EndpointPermissions.cs','ClamSetup.cs','ClamSignature.cs',r'..\src\CanaryTemplates.cs',r'..\src\ClamUpdateWorker.cs'}
batch=(root/'setup/BuildSetup.cmd').read_text()
for key in ['ClamSetup.cs','System.ServiceProcess.dll','/target:winexe']:assert key in batch,key
assert project.find('.//m:Reference[@Include="System.ServiceProcess"]',ns) is not None
assert 'internal static partial class Setup' in setup and 'internal static partial class Setup' in clam
assert 'if(verb=="--check-clamav")return CheckClamAvForWizard();' in setup
assert 'if(before!=ClamMissing && before!=ClamPartial)return ConfigureClamAv(log)' in setup
assert 'if(installed!=0)return installed' in setup
assert 'if(verb=="--configure-clamav")return ConfigureClamAv(log)' in setup
for key in ['TCPAddr 127.0.0.1','TCPSocket 3310','StreamMaxLength 100M','MaxFileSize 100M','MaxScanSize 200M','AlertExceedsMax yes','BytecodeSecurity TrustSigned','DatabaseMirror database.clamav.net','TestDatabases yes','Checks 24','NotifyClamd','LogFileMaxSize 10M','LogRotate yes']:
    assert key in clam,key
for key in ['StandardRegistryPaths','NativeService','VerifyClamTree','ReparsePoint','FileMode.CreateNew','File.Replace(temp,path,backup)','File.Move(temp,path)','FreshClamProcessPresent','if(ServiceImage(name)==null)RunClamTool','--install-service','start= auto','GetExtendedTcpTable','QueryServiceStatusEx','LoopbackOnly','OwnsConnection','ClamCommand("PING")','ClamCommand("VERSION")','ClamCommand("INSTREAM")','CheckClamAv(log)','WaitForStatus','CreateNoWindow=true','900000','DatabaseCustomURL','ClamStale']:
    assert key in clam,key
for code in [0,3,4,5,6,7,8,9]: assert re.search(r'^\s*'+str(code)+r' \{',wizard,re.M),code
for key in ['--configure-clamav','--install-clamav','--check-clamav','Check again','3010','1641','-Verb RunAs','Configure / repair ClamAV']:
    assert key in wizard,key
# Wizard must launch a script file, not an oversized encoded command.
assert '-ExecutionPolicy Bypass -File' in setup and '-EncodedCommand' not in setup
assert 'FileShare.Read' in setup and 'FileMode.CreateNew' in setup
assert '--uninstall-clamav' in setup and '--uninstall-clamav' in wizard
assert 'ClamMsiProducts' in clam and 'IsRemovableClamService' in clam
assert 'AddSeconds(25)' in wizard and '$checkTimer.Add_Tick' in wizard and 'DoEvents' not in wizard and 'WaitForExit(100)' not in wizard and '$script:checking' in wizard
assert '3010' in clam and '1602' in clam
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String, Comment
for filename in ['Setup.cs','ClamSetup.cs','ClamSignature.cs']:
    stack=[]
    for token,value in lex((root/'setup'/filename).read_text(),CSharpLexer()):
        if token in String or token in Comment:continue
        for c in value:
            if c in '([{':stack.append(c)
            elif c in ')]}':assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[c],(filename,c)
    assert not stack,(filename,stack)
assert (root/'CLAMAV-SETUP.md').is_file()
print('PASS: ClamAV setup source/build inclusion, readiness-state branches, loopback configuration, service/update safeguards, wizard command length, and C# delimiter checks. Not Windows compilation or runtime tests.')

# Regression: retained configuration alone must not block reinstall after MSI removal.
missing_branch=clam.split('if(!installed) {',1)[1].split('log.WriteLine("ClamAV binaries detected:',1)[0]
assert 'File.Exists(ClamdConfig)' not in missing_branch and 'File.Exists(FreshConfig)' not in missing_branch
assert 'ClamServices().Count!=0' in missing_branch
assert 'Repair / reinstall ClamAV' in wizard and '$script:clamCheck -in @(3,8)' in wizard
assert 'add_ThreadException' in wizard
