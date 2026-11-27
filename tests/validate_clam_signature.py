"""Portable cryptographic fixture tests + source checks. Not a Windows installer execution."""
from pathlib import Path
import subprocess, tempfile, re, xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
setup=(root/'setup/Setup.cs').read_text()
verify=(root/'setup/ClamSignature.cs').read_text()
pin=re.search(r'TalosFingerprint="([A-F0-9]{40})"',verify).group(1)
assert pin=='5BADCA2665EF59DCF8A23D8B707F0DB480836771'
block=setup[setup.index('static int InstallClamAv('):setup.index('static int Execute(')]
assert block.index('VerifyClamPackage(stage,package,log)')<block.index('ProductName(package)')<block.index('RunHidden(')
assert 'return ClamSignatureRejected;' in block and 'msiexec.exe' in block
assert 'Resource("cisco-talos.gpg")' in verify and 'VerifyClamTree' in verify
for option in ['--no-options','--no-auto-key-retrieve','--no-auto-key-import','--auto-key-locate clear','--status-fd 1','--verify']:
    assert option in verify
for status in ['BADSIG','ERRSIG','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','NO_PUBKEY','VALIDSIG','GOODSIG']:
    assert '"'+status+'"' in verify
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
assert ET.parse(root/'setup/LinkScope.Setup.csproj').find('.//m:EmbeddedResource[@Include="cisco-talos.gpg"]',ns) is not None
assert 'clamav-latest.msi.sig' in (root/'setup/BuildSetup.cmd').read_text()
assert '_SetupSig' in (root/'LinkScope.csproj').read_text()
assert 'clamav-latest.msi.sig' in (root/'setup/wizard.ps1').read_text()
# Fixture mirrors the documented GnuPG status contract; C# parser itself is not executed here.
def acceptable(output, rc, expected):
    records=[line[9:].split() for line in output.splitlines() if line.startswith('[GNUPG:] ')]
    rejects={'BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','NODATA','FAILURE','ERROR','BADARMOR','UNEXPECTED'}
    valid=[r for r in records if r and r[0]=='VALIDSIG']
    return rc==0 and not any(r and r[0] in rejects for r in records) and sum(r[0]=='GOODSIG' for r in records if r)==1 and len(valid)==1 and len(valid[0])>=10 and (valid[0][10] if len(valid[0])>=11 else valid[0][1])==expected and valid[0][8] in {'8','9','10'} and valid[0][9]=='00'
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp); home=d/'vendor'; home.mkdir(mode=0o700)
    def gpg(h,*args,check=True,isolated=True):
        opts=['--no-options','--homedir',str(h),'--batch','--no-tty','--no-auto-key-retrieve','--no-auto-key-import','--auto-key-locate','clear','--status-fd','1']
        if isolated: opts+=['--no-autostart']
        return subprocess.run(['gpg',*opts,*map(str,args)],capture_output=True,text=True,check=check,timeout=120)
    result=gpg(home,'--import',root/'setup/cisco-talos.gpg')
    assert 'IMPORT_OK 1 '+pin in result.stdout
    keylist=gpg(home,'--with-colons','--list-keys').stdout
    assert [line.split(':')[9] for line in keylist.splitlines() if line.startswith('fpr:')][0]==pin
    # Use a disposable key to prove correct vs mutated payload, wrong signer and malformed signature.
    signer=d/'signer'; signer.mkdir(mode=0o700)
    gpg(signer,'--pinentry-mode','loopback','--passphrase','','--quick-generate-key','Fixture test <fixture@example.invalid>','rsa2048','sign','1d',isolated=False)
    fpr=[line.split(':')[9] for line in gpg(signer,'--with-colons','--list-keys').stdout.splitlines() if line.startswith('fpr:')][0]
    payload=d/'sample.msi';payload.write_bytes(b'harmless fixture data\x00\xff')
    sig=d/'sample.msi.sig'
    gpg(signer,'--pinentry-mode','loopback','--passphrase','','--digest-algo','SHA256','--output',sig,'--detach-sign',payload,isolated=False)
    result=gpg(signer,'--verify',sig,payload)
    assert acceptable(result.stdout,result.returncode,fpr)
    assert not acceptable(result.stdout,result.returncode,pin)
    assert not acceptable(result.stdout+'\n[GNUPG:] EXPKEYSIG test\n',0,fpr)
    assert not acceptable(result.stdout+'\n[GNUPG:] REVKEYSIG test\n',0,fpr)
    assert not acceptable(result.stdout+'\n'+result.stdout,0,fpr)
    wrong=gpg(home,'--verify',sig,payload,check=False)
    assert not acceptable(wrong.stdout,wrong.returncode,pin)
    payload.write_bytes(payload.read_bytes()+b'changed')
    bad=gpg(signer,'--verify',sig,payload,check=False)
    assert bad.returncode!=0 and not acceptable(bad.stdout,bad.returncode,fpr)
    sig.write_bytes(b'not a signature')
    bad=gpg(signer,'--verify',sig,payload,check=False)
    assert bad.returncode!=0 and not acceptable(bad.stdout,bad.returncode,fpr)
    subprocess.run(['gpgconf','--homedir',str(signer),'--kill','all'],capture_output=True,check=False)
print('PASS: official key import/fingerprint, genuine synthetic detached signature, tampered payload, wrong signer, malformed signature, expiry/revocation status rejection, setup ordering and embedded resources. Windows runtime not tested.')
