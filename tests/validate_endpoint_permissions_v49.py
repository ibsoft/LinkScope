"""Static source validation only; native ACL and installer operations require Windows."""
from pathlib import Path
import xml.etree.ElementTree as ET
r=Path(__file__).resolve().parents[1]
s=(r/'setup/EndpointPermissions.cs').read_text(); setup=(r/'setup/Setup.cs').read_text(); wizard=(r/'setup/wizard.ps1').read_text(); response=(r/'src/EndpointResponse.cs').read_text(); web=(r/'src/Web.cs').read_text(); app=(r/'src/app.js').read_text(); html=(r/'src/endpoint.html').read_text()
assert 'RequireAdmin();var sid=EndpointServiceSid()' in s and 'NT AUTHORITY\\LocalService' in s and 'ServiceSidType' in s
assert 'new NTAccount("NT SERVICE","LinkScope")' in s and 'AceQualifier.AccessAllowed,1,sid' in s and 'acl.InsertAce' in s and 'RemoveAce' not in s
assert 'FileSystemAuditRule' in s and '(FileSystemRights)0x10046' in s and 'AuditFlags.Success' in s
assert 'FileSystemRights.Read|FileSystemRights.Delete' in s and 'FileSystemRights.DeleteSubdirectoriesAndFiles' in s
assert 'FullControl' not in s and 'TerminateProcess' not in s and 'SeDebugPrivilege' not in s
assert 'Values(ep,"ResponsePaths")' in s and 'Values(ep,"Paths")' in s and 'Values(ep,"ExcludedPaths")' in s and 'ProfileList' in s
assert 'DriveType.Fixed' in s and 'NTFS' in s and 'ReparsePoint' in s and 'PermissionFinalPath' in s and 'DirectoryIdentity' in s
assert 'PermissionOpen(current,0x80,3,' in s
apply=s.split('static string ApplyPermission(',1)[1].split('static string RollbackPermission(',1)[0]
assert apply.index('SavePermissionRecord(file,r)') < apply.index('WritePermission(kind,path,after)')
assert 'ReadPermission(kind,path)!=before' in apply and 'observed!=after' in apply
rollback=s.split('static string RollbackPermission(',1)[1].split('static string AuditPolicyReport(',1)[0]
assert 'pin.Identity!=r.DirectoryIdentity' in rollback and 'current!=r.After' in rollback and 'ReadPermission(r.Kind,r.Path)!=r.Before' in rollback
assert 'MessageBoxDefaultButton.Button2' in s and 'SecureDirectory(PermissionStore)' in s and 'FileShare.None' in s
assert '/get /subcategory:' in s and '/set /subcategory:' not in s
assert '--endpoint-permissions' in setup and '--endpoint-permissions' in wizard and '--endpoint-permissions' not in web
assert 'EndpointPermissions.cs' in (r/'setup/BuildSetup.cmd').read_text()
assert ET.parse(r/'setup/LinkScope.Setup.csproj').find('.//{http://schemas.microsoft.com/developer/msbuild/2003}Compile[@Include="EndpointPermissions.cs"]') is not None
assert 'File system audit evidence' in response and 'Security log readability' in response and 'Response path access' in response
assert 'Repair Windows permissions (local administrator)' in html and 'No permissions are changed from this web dashboard' in html
assert 'Response paths: ' in app and 'Review access' in app
version=(r/'source-build-version.txt').read_text().strip()
assert version.startswith('V') and version[1:].isdigit() and int(version[1:])>=49
print('PASS: administrator-only wizard, explicit service-SID read ACE, scoped audit/response rights, scope and directory guards, durable backup ordering, conflict-aware rollback, independent diagnostics and build graph (static).')
