"""Portable integration checks; real SID discovery and C# self-test require Windows."""
from pathlib import Path
import json, subprocess, re
r=Path(__file__).resolve().parents[1]
p=(r/'src/Program.cs').read_text(); w=(r/'setup/wizard.ps1').read_text(); e=(r/'src/EndpointProtection.cs').read_text(); j=(r/'src/app.js').read_text(); h=(r/'src/settings.html').read_text(); web=(r/'src/Web.cs').read_text(); selfcheck=(r/'src/SelfCheck.cs').read_text()
assert 'profile-v1|' in w and 'WindowsIdentity]::GetCurrent().User.Value' in w
assert w.index("$profileToken=")<w.index('Start-Process -FilePath $exe -ArgumentList $arguments -Verb RunAs')
assert 'ProfileList\\"+sid' in p and 'ProfileImagePath' in p and 'DriveType.Fixed' in p
assert 'if(ep.ProfileDefaultsApplied||string.IsNullOrEmpty(profile))return;' in p
assert 'ep.Paths=ep.Paths.Concat(new[]{profile}).ToArray()' in p
assert 'ep.Enabled=true;ep.RealTime=true;ep.Mode="monitor";ep.IntervalSeconds=86400;ep.MaxFileMiB=100;' in p
assert 'if(!fresh&&!ep.Enabled&&ep.Paths.Length>0)' in p
assert 'next.Endpoint.ProfileDefaultsApplied=settings.Endpoint.ProfileDefaultsApplied' in web
assert 'BackgroundExcludedPaths=Normalize(BackgroundExcludedPaths)' in e
assert 'if(full&&BackgroundExcluded(c,p))' in e
assert 'if(BackgroundExcluded(c,path))continue;' in e
assert '!BackgroundExcluded(c,(string)oldCoverage[1])' in e
assert '&&!c.CanaryPaths.Any(x=>Under(x,p))' in e
normal=e.split('internal static bool Excluded(',1)[1].split('internal static bool BackgroundExcluded',1)[0]
assert 'BackgroundExcludedPaths' not in normal
for key in ['EndpointPaths','EndpointBackgroundExcludedPaths','EndpointExcludedPaths']:
    assert h.count('id="'+key+'"')==1
assert 'CheckProfileDefaults(dir)' in selfcheck
# Exercise actual settings serialization and hydration using the real JS functions in isolation.
parts=[j[j.index('const endpointFlags='):j.index('function signatureScheduleFields()')],j[j.index('function readEndpoint()'):j.index('function fillIntegrity(')]]
js='''const assert=require('node:assert/strict');const fields={};const byId=id=>fields[id]??=( {checked:false,value:''} );const integrityLines=id=>byId(id).value.split(/\\r?\\n/).filter(Boolean);function signatureScheduleFields(){};\n'''+ '\n'.join(parts)+'''\nconst profile=String.raw`C:\\Users\\Example`, extra=String.raw`D:\\Projects`, cache=String.raw`C:\\Users\\Example\\cache`;
fillEndpoint({Endpoint:{Enabled:true,RealTime:true,Mode:'monitor',Paths:[profile,extra],ExcludedPaths:[],BackgroundExcludedPaths:[cache]}});
assert.deepEqual(readEndpoint().Paths,[profile,extra]);assert.deepEqual(readEndpoint().BackgroundExcludedPaths,[cache]);assert.deepEqual(readEndpoint().ExcludedPaths,[]);\n'''
subprocess.run(['node','-e',js],check=True)
assert json.loads((r/'src/default.json').read_text())['Endpoint']['ProfileDefaultsApplied'] is False
print('PASS: setup identity wiring, one-time additive profile migration, background-only scan guard, evidence preservation, actual JS settings round-trip. Native self-test not executed.')
