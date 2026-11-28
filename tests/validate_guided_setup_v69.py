"""Portable wiring/ordering checks; not a Windows execution or installer certification."""
from pathlib import Path
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import Comment,String
r=Path(__file__).resolve().parents[1]
w=(r/'setup/wizard.ps1').read_text(); s=(r/'setup/Setup.cs').read_text(); c=(r/'setup/ClamSignature.cs').read_text(); d=(r/'src/DesktopApp.cs').read_text()
assert "$form.Add_Shown({Set-Stage 0 '';Show-Page 'home';Update-State})" in w
assert '$install.Add_Click' in w and "Update-State $true 'install'" in w
assert all(x in w for x in ['Installation plan','Antivirus engine','LinkScope service','Readiness checks','Installation report','Advanced / manual','Save report...','AutoScrollMinSize','TableLayoutPanel'])
# Every pre-existing elevated action remains available (including standalone PWA/shortcut maintenance).
for verb in ['--upgrade','--upgrade-pwa','--desktop-app','--register-pwa','--uninstall','--install-clamav','--configure-clamav','--update-clamav','--clamav-providers','--uninstall-clamav','--endpoint-permissions','--check-clamav']:
    assert verb in w and verb in s,verb
assert "$script:clamCheck -in @(3,4,5,7,8,9)" in w
flow=w.split('function Complete-Operation {',1)[1].split('$install.Add_Click',1)[0]
assert 'if($rc -eq 0 -and $script:clamCheck -eq 0){Start-CoreInstall;return}' in flow
assert '$script:serviceRunning -and $script:usnRunning -and $script:clamCheck -eq 0 -and $rc -eq 0' in flow
assert 'if($script:rebootRequired){Stop-Automatic' in flow and 'if($rc -ne 0 -and $rc -ne 21)' in flow
assert "'--install-clamav-online'" in w and 'FindTrustedGpg();' in s
assert s.index('DownloadOfficialClamPair(stage,log)') < s.index('VerifyClamPackage(stage,package,log)') < s.index('ProductName(package)')
for term in ['https://api.github.com/repos/Cisco-Talos/clamav/releases/latest','AllowAutoRedirect=false','AllowedClamAssetUri(uri)','requireDigest','Official release asset digest mismatch','FileMode.CreateNew','Incomplete official asset download','FindTrustedGpg()','TalosFingerprint']:
    assert term in c,term
# Only browser app mode on desktop, no service binary as shortcut target. URL fallback is Start menu only.
assert 'Invoke(link,"TargetPath",BindingFlags.SetProperty,browser)' in d
assert 'Invoke(link,"Arguments",BindingFlags.SetProperty,"--app=' in d
assert 'Same(folder,desktop)&&browser==null' in d and 'Start menu URL fallback only' in d
assert 'RemoveLegacyServiceLinks(shell,folder)' in d and 'legacy=Same(Path.GetFullPath(target),expected)' in d
assert 'if(legacy){File.Delete(path)' in d and 'File.Delete(expected)' not in d
assert 'create_desktop_shortcut=false' in d
assert 'Test-AppShortcut $path' in w and 'if($link.TargetPath -notin $browsers' in w
assert '$pwa.Checked=$false' in w and '$registerPwa.Add_Click' in w and '$desktopRepair.Add_Click' in w
assert 'No service executable shortcut is created.' in w
for src in (s,c,d):
    stack=[]
    for tok, val in lex(src,CSharpLexer()):
        if tok in Comment or tok in String:continue
        for ch in val:
            if ch in '([{':stack.append(ch)
            elif ch in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch]
    assert not stack
print('PASS: guided automatic sequencing, full manual operation inventory, readiness/failure gates, official package verification ordering, app-only desktop launcher and legacy link cleanup; Windows runtime not executed.')
