#!/usr/bin/env python3
"""Portable regression checks for the login challenge and MFA reminder. No Windows server required."""
from pathlib import Path
import subprocess, json, re
ROOT=Path(__file__).resolve().parents[1]; SRC=ROOT/'src'
app=(SRC/'app.js').read_text(); toast=(SRC/'toast.js').read_text(); web=(SRC/'Web.cs').read_text()
html=(SRC/'login.html').read_text(); css=(SRC/'theme.css').read_text()
assert re.search(r'<div id="mfaChallenge" hidden>',html)
assert re.search(r'<input name="otp"[^>]+disabled>',html)
assert web.count('mfaEnabled=session.MfaEnabled')==2
assert 'MfaEnabled=c.MfaEnabled' in (SRC/'Access.cs').read_text()
assert 'MfaEnabled=!string.IsNullOrEmpty(u.MfaProtected)' in (SRC/'UserAccounts.cs').read_text()
assert 'if(mfaRequired)' in web and 'return Reply.Json(new {mfaRequired=true});' in web
assert 'maybeRemindMfa(s);' in toast
assert 'setTimeout(()=>dismiss(key),7000)' in toast
assert 'if(document.body.dataset.page===\'login\')return;' in toast
# Test real login handler, with only browser and HTTP boundaries mocked.
login=app[app.index('async function start(){'):app.index("    const session=await request('/ui/session');csrf=session.admin?")]+ '\n}'
js=r'''
const assert=require('node:assert/strict'), vm=require('node:vm');
const source=LOGIN;
function fixture(){
 const ids={},events={},requests=[],responses=[],destinations=[];
 const make=(value='')=>({value,hidden:false,disabled:false,required:false,readOnly:false,focus(){this.focused=true},addEventListener(k,f){this[k]=f},setAttribute(){}});
 for(const id of ['loginForm','firstUse','signInButton','signInSpinner','signInLabel','notice','mfaChallenge','passwordRules'])ids[id]=make();
 const fields=Object.fromEntries(['user','password','otp','newPassword','confirmPassword'].map(k=>[k,make()]));
 fields.user.value='viewer';fields.password.value='password';
 ids.loginForm.elements=fields;ids.loginForm.reset=()=>Object.values(fields).forEach(f=>f.value='');
 const ctx={page:'login',byId:id=>ids[id],request:async(path,input)=>{requests.push({path,...input});const r=responses.shift();if(r instanceof Error)throw r;return r;},failure:()=>{},LinkScopeBusy:{begin:()=>()=>{}},window:{addEventListener(k,f){events[k]=f}},sessionStorage:{getItem:()=>null,removeItem(){}},location:{hash:'',assign:p=>destinations.push(p)}};
 vm.createContext(ctx);vm.runInContext(source,ctx);return {ids,fields,requests,responses,destinations,events,ctx,submit:()=>ids.loginForm.onsubmit({preventDefault(){}})};
}
(async()=>{
 const a=fixture();await a.ctx.start();assert.equal(a.ids.mfaChallenge.hidden,true);assert.equal(a.fields.otp.disabled,true);a.responses.push({ok:true});await a.submit();assert.equal('otp' in a.requests[0],false);assert.deepEqual(a.destinations,['/system']);
 const b=fixture();await b.ctx.start();b.responses.push({mfaRequired:true});await b.submit();assert.equal('otp' in b.requests[0],false);assert.equal(b.ids.mfaChallenge.hidden,false);assert.equal(b.fields.otp.required,true);assert.equal(b.fields.otp.readOnly,false);assert.equal(b.destinations.length,0);
 b.fields.otp.value='123456';b.responses.push(Error('Invalid code'));await b.submit();assert.equal(b.requests[1].otp,'123456');assert.equal(b.fields.otp.value,'');assert.equal(b.ids.mfaChallenge.hidden,false);
 b.fields.user.value='another';b.fields.user.input();assert.equal(b.ids.mfaChallenge.hidden,true);assert.equal(b.fields.otp.disabled,true);assert.equal(b.fields.otp.required,false);
 b.responses.push({ok:true});await b.submit();assert.equal('otp' in b.requests[2],false);
 const c=fixture();await c.ctx.start();c.responses.push({changeRequired:true});await c.submit();assert.equal(c.ids.firstUse.hidden,false);assert.equal(c.ids.mfaChallenge.hidden,true);c.fields.newPassword.value='Replacement1!';c.fields.confirmPassword.value='Replacement1!';c.responses.push({ok:true});await c.submit();assert.equal(c.requests[1].newPassword,'Replacement1!');assert.equal('otp' in c.requests[1],false);
 const d=fixture();await d.ctx.start();d.responses.push({mfaRequired:true});await d.submit();d.fields.otp.value='654321';d.responses.push({ok:true});await d.submit();assert.equal(d.requests[1].otp,'654321');assert.deepEqual(d.destinations,['/system']);
 console.log('PASS: actual login handler hides MFA by default, reveals it after server challenge, retries invalid codes, resets on credential changes, handles first-use and verified login');
})().catch(e=>{console.error(e);process.exitCode=1});
'''.replace('LOGIN',json.dumps(login),1)
subprocess.run(['node','-e',js],check=True)
reminder=toast[toast.index('    const mfaReminderPeriod='):toast.index('    function session(s){')]
js=r'''
const assert=require('node:assert/strict'),vm=require('node:vm');
const source=REMINDER, storage=new Map();let now=1000000;
const store={getItem:k=>storage.has(k)?storage.get(k):null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)};
function tab(){const shown=[],dismissed=[];const ctx={localStorage:store,document:{hidden:false},Date:{now:()=>now},stored:(s,k,f)=>{try{return JSON.parse(s.getItem(k))??f}catch{return f}},keep:(s,k,v)=>s.setItem(k,JSON.stringify(v)),dismiss:k=>dismissed.push(k),show:(...a)=>shown.push(a)};vm.createContext(ctx);vm.runInContext(source,ctx);return {shown,dismissed,ctx,check:s=>ctx.maybeRemindMfa(s)};}
const admin={authenticated:true,username:'admin',role:'Admin',mfaEnabled:false},viewer={authenticated:true,username:'viewer',role:'Viewer',mfaEnabled:false};
const a=tab();a.check(admin);assert.equal(a.shown.length,0);now+=299999;a.check(admin);assert.equal(a.shown.length,0);
const b=tab();b.check(admin);now++;b.check(admin);assert.equal(b.shown.length,1);assert.equal(b.shown[0][0],'mfa-reminder');assert.equal(b.shown[0][1],'warning');assert.equal(b.shown[0][4],null);assert.equal(b.shown[0][5].href,'/account');a.check(admin);assert.equal(a.shown.length,0);
b.check(admin);assert.equal(b.shown.length,1);now+=300000;b.ctx.document.hidden=true;b.check(admin);assert.equal(b.shown.length,1);b.ctx.document.hidden=false;b.check(admin);assert.equal(b.shown.length,2);
b.check({...admin,mfaEnabled:true});assert.equal(storage.has('linkscope.mfa-reminder.v1:admin'),false);now+=300000;b.check({...admin,mfaEnabled:true});assert.equal(b.shown.length,2);
b.check(viewer);assert.equal(b.shown.length,2);now+=300000;b.check(viewer);assert.equal(b.shown.length,3);
b.check({authenticated:false,username:'viewer',mfaEnabled:false});now+=300000;b.check({authenticated:false,username:'viewer',mfaEnabled:false});assert.equal(b.shown.length,3);b.check({authenticated:true,username:'viewer'});assert.equal(b.shown.length,3);
console.log('PASS: actual reminder code honors five minutes, survives navigation, shares account deadlines across tabs, covers both roles, skips hidden tabs and enrolled/unauthenticated users, links to MFA without a monitoring alert');
'''.replace('REMINDER',json.dumps(reminder),1)
subprocess.run(['node','-e',js],check=True)
for p in SRC.glob('*.html'):
    page=p.read_text();assert '/assets/theme-workspace-v11.css' in page,p
    assert '/assets/toast-stable-v6.js' in page,p
assert '--ls-workspace-max:1440px' in css and 'body:not([data-page=login])>main' in css
assert 'body header.ls-header .ls-account-menu :is(a,button){background:var(--control-bg)!important' in css
assert 'body[data-page=logs] #log-form{background:var(--paper,#fff)' in css
assert 'data-theme=dark]{--control-bg:#203541' in css
for f in ['app.js','toast.js','theme.js']:subprocess.run(['node','--check',str(SRC/f)],check=True)
print('PASS: shared versioned assets on all 12 pages; workspace and dark logout/log panel CSS assertions')
print('Pending: Windows compilation, browser rendering and real authentication end-to-end testing.')
