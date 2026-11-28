"""Portable checks of V51 source wiring; Windows self-tests and UAC are separate."""
from pathlib import Path
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String, Comment
r=Path(__file__).resolve().parents[1]
selfcheck=(r/'src/SelfCheck.cs').read_text(); p=(r/'src/Program.cs').read_text(); w=(r/'setup/wizard.ps1').read_text(); c=(r/'src/ClamUpdateWorker.cs').read_text(); s=(r/'setup/ClamSetup.cs').read_text(); e=(r/'src/EndpointProtection.cs').read_text()
migration=selfcheck.split('static void CheckExplicitEndpointScope',1)[1].split('static void CheckEndpoint(',1)[0]
assert 'GetProperties()' in migration and '(object)a.Clone()' in migration and 'a.SequenceEqual(b,StringComparer.Ordinal)' in migration and 'Object.Equals(before,after)' in migration
assert 'property.Name=="ProfileDefaultsApplied"' in migration and 'Check(existing.ProfileDefaultsApplied' in migration and 'pass<2' in migration
assert 'Config.Json().Serialize(existing)' not in migration
assert 'ep.ProfileDefaultsApplied=true;' in p and p.index('SelfCheck.Run();')<p.index('InitConfig();',p.index('static void Install('))
assert 'Update-State ($script:lastCheckWasElevated -or $script:clamCheck -eq 13) \'install\'' in w
assert 'Update-State ($script:lastCheckWasElevated -or (Is-ClamOperation $op)) \'operation\'' in w
assert '$checkButton.Add_Click({if(-not $script:job){Update-State $true \'manual\'}})' in w
assert 'return 13;' in s and 'ClamAV configuration could not be read even by the elevated check' in w
assert 'DefinitionFreshness(version,DateTime.Now' in e and 'LogDefinitionReadiness(version,log)' in s
assert 'TotalHours>=72?"Stale":"Current"' in c and 'NumberStyles.None' in c and 'out stamp)||stamp>=localNow.AddDays(1)' in c
assert 'definition age below 72 hours' in selfcheck and 'definition age reaches 72 hours' in selfcheck
assert 'new byte[512]' in c and 'fields[0]!="ClamAV-VDB"' in c and 'loaded>=disk' in c
assert 'expectedDaily==0||loaded>=expectedDaily' in c and 'TimeSpan.FromSeconds(120)' in c
assert 'state.CoolingDown' in c and 'RunDueProvider(log)' in c
assert 'return current?0:ClamStale;' in s and 'return current?0:ClamStale;' in c
assert 'Loaded and on-disk daily versions agree but are stale' in c
for filename in ['src/SelfCheck.cs','src/ClamUpdateWorker.cs','setup/ClamSetup.cs','src/EndpointProtection.cs']:
    stack=[]
    for token,value in lex((r/filename).read_text(),CSharpLexer()):
        if token in String or token in Comment:continue
        for ch in value:
            if ch in '([{':stack.append(ch)
            elif ch in ')]}':assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch],(filename,ch)
    assert not stack,(filename,stack)
version=(r/'source-build-version.txt').read_text().strip()
assert version.startswith('V') and version[1:].isdigit() and int(version[1:])>=51
print('PASS: migration property snapshot/idempotence, installer check access flow, shared freshness checks, daily header diagnostics, reload verification, and C# delimiter balance (static). Native Windows self-check, FreshClam and UAC not executed.')
