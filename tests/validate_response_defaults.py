"""Portable checks for response suggestions. Windows filesystem/ACL behavior is not exercised."""
from pathlib import Path
import json, subprocess
root=Path(__file__).resolve().parents[1]
src=root/'src'
app=(src/'app.js').read_text()
response=(src/'EndpointResponse.cs').read_text()
web=(src/'Web.cs').read_text()
settings=(src/'settings.html').read_text()
policy=json.loads((src/'default.json').read_text())['Endpoint']
assert policy['Mode']=='monitor' and policy['Enabled'] is False
assert policy['ResponsePaths']==policy['ContainmentExecutables']==[]
assert 'endpointResponseSuggestions=EndpointResponse.SuggestedTargets(settings.Endpoint)' in web
assert '"/ui/settings"' not in web.split('static readonly HashSet<string> ViewerReads=')[1].split(';',1)[0]
assert '/assets/app-signature-schedule-v17.js' in settings and '/assets/app-signature-schedule-v17.js' in web
suggest=response.split('internal static object SuggestedTargets(')[1].split('internal static EndpointWriter FindWriter(',1)[0]
for term in ['c.Paths','SafeScope(path)','EndpointProtection.Excluded(c,path)','EndpointProtection.SafePath(path)','SearchOption.TopDirectoryOnly','.Take(64)','executables.Count>=200','EndpointProtection.SafePath(file)','CanaryTemplates.FolderName']:
    assert term in suggest,term
assert 'c.ResponsePaths=' not in suggest and 'c.ContainmentExecutables=' not in suggest
assert 'confirmed' in response.lower()
for term in ['SuggestedEngine(c)','!string.IsNullOrWhiteSpace(c.TrustedEngineSha256)','SpecialFolder.ProgramFiles','Path.Combine(root,"ClamAV","clamd.exe")','VerifyHandle(file.SafeFileHandle,path)','64L*1024*1024','sha256=EndpointProtection.FileHash(file)']:
    assert term in suggest,term
assert 'c.TrustedEnginePath=' not in suggest and 'c.TrustedEngineSha256=' not in suggest
for ident in ['EndpointSuggestedResponse','EndpointSuggestedExecutable','EndpointAddSuggestedResponse','EndpointAddSuggestedExecutable','EndpointResponseSuggestionStatus','EndpointUseDetectedEngine','EndpointDetectedEngineStatus']:
    assert settings.count('id="'+ident+'"')==1
assert "'Apply settings',next.Endpoint.Mode!=='monitor'" in app or '"Apply settings",next.Endpoint.Mode!==\'monitor\'' in app
code=app[app.index('let endpointResponseSuggestions='):app.index('function readEndpoint(){')]
js=r'''
const assert=require('node:assert/strict'),vm=require('node:vm');
const ids={};
const byId=id=>ids[id]??=( {value:'',disabled:false,placeholder:'',textContent:'',replaceChildren(...options){this.options=options;this.value='';},dispatchEvent(){this.dispatched=true;}} );
const ctx={byId,integrityLines:id=>byId(id).value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),Option:function(label,value){this.label=label;this.value=value;},Event:function(){},confirmAction:async()=>false};
vm.createContext(ctx);vm.runInContext(CODE,ctx);
const f='EndpointResponsePaths', e='EndpointContainmentExecutables', p='EndpointPaths';
byId(p).value='C:\\unx';
ctx.loadResponseSuggestions({endpointResponseSuggestions:{paths:['C:\\unx','D:\\other'],executables:['C:\\unx\\app.exe','C:\\unx2\\other.exe','D:\\other\\tool.exe']}});
assert.equal(byId(f).value,'');assert.equal(byId(e).value,'');
assert.equal(byId('EndpointSuggestedResponse').value,'C:\\unx');
assert.equal(byId('EndpointAddSuggestedExecutable').disabled,true);
ctx.addResponseSuggestion('EndpointSuggestedResponse',f);
assert.equal(byId(f).value,'C:\\unx');assert.equal(byId(e).value,'');
assert.equal(byId('EndpointSuggestedExecutable').value,'C:\\unx\\app.exe');
ctx.addResponseSuggestion('EndpointSuggestedExecutable',e);
assert.equal(byId(e).value,'C:\\unx\\app.exe');
ctx.addResponseSuggestion('EndpointSuggestedExecutable',e);assert.equal(byId(e).value,'C:\\unx\\app.exe');
assert.equal(byId(e).dispatched,true);
byId(f).value='';ctx.updateResponseSuggestions();assert.equal(byId('EndpointAddSuggestedExecutable').disabled,true);
assert.equal(byId(e).value,'C:\\unx\\app.exe'); // never silently erase a saved/draft entry
byId(p).value='C:\\unx2';ctx.updateResponseSuggestions();assert.equal(byId('EndpointAddSuggestedResponse').disabled,true);
assert.equal(ctx.responseUnder('C:\\unx2\\app.exe','C:\\unx'),false);
assert.equal(ctx.responseUnder('c:\\UNX\\app.exe','C:\\unx\\'),true);
console.log('PASS: suggestions, scope boundaries, explicit additions, no implicit authorization, no duplicates, existing settings preserved');
(async()=>{
    const path='EndpointTrustedEnginePath', pin='EndpointTrustedEngineSha256', use='EndpointUseDetectedEngine';
    const engine={path:'C:\\Program Files\\ClamAV\\clamd.exe',sha256:'a'.repeat(64)};
    ctx.loadResponseSuggestions({endpointResponseSuggestions:{paths:[],executables:[],engine}});
    assert.equal(byId(use).disabled,false);assert.equal(byId(pin).value,'');
    await ctx.useDetectedEngine();assert.equal(byId(pin).value,'');
    ctx.confirmAction=async()=>true;
    await ctx.useDetectedEngine();assert.equal(byId(path).value,engine.path);assert.equal(byId(pin).value,engine.sha256);
    assert.equal(byId(use).disabled,true);assert.equal(byId(pin).dispatched,true);
    byId(pin).value='b'.repeat(64);await ctx.useDetectedEngine();assert.equal(byId(pin).value,'b'.repeat(64));
    byId(pin).value='';byId(path).value='C:\\Custom\\clamd.exe';ctx.updateEngineSuggestion();assert.equal(byId(use).disabled,true);
    console.log('PASS: observed engine hash requires explicit confirmation, never replaces an existing pin or nonstandard path');
})().catch(err=>{console.error(err);process.exitCode=1;});
'''.replace('CODE',json.dumps(code),1)
subprocess.run(['node','-e',js],check=True)
print('PASS: default monitor policy, admin settings route, bounded server-side discovery and existing confirmation wiring')

css=(src/'theme.css').read_text();nav=(src/'navigation.css').read_text()
assert 'font:700 29px/1' in nav and 'font:400 15px/20px' in nav
assert 'font:inherit;color:#dfedee' in nav
assert '.brand{font-size:18px;gap:4px}' in nav
assert 'flex-wrap:nowrap' in nav and 'ls-nav-compact' in nav
print('PASS: larger wordmark, regular navigation weight and responsive no-wrap layout rules')
