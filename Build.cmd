@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "compiler=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%compiler%" (
  echo Install Windows .NET Framework 4.8 on a 64-bit Windows machine.
  popd
  exit /b 1
)
"%compiler%" /nologo /target:exe /platform:x64 /optimize+ /out:LinkScope.exe /reference:System.dll /reference:System.Core.dll /reference:System.Web.dll /reference:System.Web.Extensions.dll /reference:System.Numerics.dll /reference:System.Security.dll /reference:System.ServiceProcess.dll /resource:src\alerts.html,alerts.html /resource:src\charts.js,charts.js /resource:src\logs.html,logs.html /resource:src\logs.js,logs.js /resource:src\ai.html,ai.html /resource:src\loading.js,loading.js /resource:src\loading.css,loading.css /resource:src\ai.js,ai.js /resource:src\ai.css,ai.css /resource:src\paging.js,paging.js /resource:src\app.css,app.css /resource:src\app.js,app.js /resource:src\security.ps1,security.ps1 /resource:src\certificate.ps1,certificate.ps1 /resource:src\dashboard.css,dashboard.css /resource:src\dashboard.html,dashboard.html /resource:src\dashboard.js,dashboard.js /resource:src\default.json,default.json /resource:src\hardware-task.ps1,hardware-task.ps1 /resource:src\health.ps1,health.ps1 /resource:src\login.html,login.html /resource:src\pdf-lib.min.js,pdf-lib.min.js /resource:src\report.js,report.js /resource:src\settings.html,settings.html /resource:src\smart.ps1,smart.ps1 /resource:src\system.html,system.html /resource:src\toast.css,toast.css /resource:src\toast.js,toast.js src\*.cs
set "result=%errorlevel%"
popd
exit /b %result%
