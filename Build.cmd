@echo off
setlocal
pushd "%~dp0" || exit /b 1
if not exist "src\EndpointProtection.cs" (
  echo ERROR: Missing src\EndpointProtection.cs. Extract the complete LinkScope source archive.
  popd
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0tools\Assert-EndpointSources.ps1"
set "result=%errorlevel%"
if not "%result%"=="0" goto done
set "compiler=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%compiler%" (
  echo Install Windows .NET Framework 4.8 on a 64-bit Windows machine.
  popd
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0tools\Write-BuildVersion.ps1" -OutputPath "%~dp0obj\LinkScopeVersion.txt"
set "result=%errorlevel%"
if not "%result%"=="0" goto done
"%compiler%" /nologo /langversion:5 /target:exe /platform:x64 /optimize+ /out:LinkScope.exe /win32icon:linkscope.ico /reference:System.dll /reference:System.Xml.dll /reference:System.Numerics.dll /reference:System.Core.dll /reference:System.Web.dll /reference:System.Web.Extensions.dll /reference:System.Security.dll /reference:System.ServiceProcess.dll /resource:src\users.html,users.html /resource:src\account.html,account.html /resource:src\users.js,users.js /resource:src\users.css,users.css /resource:src\local-qr.js,local-qr.js /resource:src\audit.html,audit.html /resource:src\audit.js,audit.js /resource:src\pwa.js,pwa.js /resource:src\sw.js,sw.js /resource:src\manifest.webmanifest,manifest.webmanifest /resource:src\pwa-192.png,pwa-192.png /resource:src\pwa-512.png,pwa-512.png /resource:linkscope.ico,linkscope.ico /resource:obj\LinkScopeVersion.txt,build-version.txt /resource:src\theme.js,theme.js /resource:src\theme.css,theme.css /resource:src\navigation.css,navigation.css /resource:src\logs.html,logs.html /resource:src\logs.js,logs.js /resource:src\ai.html,ai.html /resource:src\loading.css,loading.css /resource:src\loading.js,loading.js /resource:src\ai.js,ai.js /resource:src\ai.css,ai.css /resource:src\alerts.html,alerts.html /resource:src\charts.js,charts.js /resource:src\paging.js,paging.js /resource:src\app.css,app.css /resource:src\app.js,app.js /resource:src\security.ps1,security.ps1 /resource:src\certificate.ps1,certificate.ps1 /resource:src\dashboard.css,dashboard.css /resource:src\dashboard.html,dashboard.html /resource:src\dashboard.js,dashboard.js /resource:src\default.json,default.json /resource:src\hardware-task.ps1,hardware-task.ps1 /resource:src\health.ps1,health.ps1 /resource:src\login.html,login.html /resource:src\pdf-lib.min.js,pdf-lib.min.js /resource:src\report.js,report.js /resource:src\settings.html,settings.html /resource:src\smart.ps1,smart.ps1 /resource:src\system.html,system.html /resource:src\endpoint.html,endpoint.html /resource:src\integrity.html,integrity.html /resource:src\toast.css,toast.css /resource:src\toast.js,toast.js src\*.cs
set "result=%errorlevel%"
if not "%result%"=="0" goto done
call "%~dp0setup\BuildSetup.cmd" "%~dp0LinkScope.exe" "%~dp0LinkScopeSetup.exe"
set "result=%errorlevel%"
:done
popd
exit /b %result%
