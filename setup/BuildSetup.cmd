@echo off
setlocal
if "%~1"=="" exit /b 2
if "%~2"=="" exit /b 2
set "payload=%~f1"
set "output=%~f2"
set "compiler=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%compiler%" (
  echo ERROR: Windows .NET Framework x64 compiler not found.
  exit /b 1
)
if not exist "%payload%" (
  echo ERROR: Compiled LinkScope.exe not found.
  exit /b 1
)
if exist "%output%" del /q "%output%"
if exist "%output%" exit /b 1
"%compiler%" /nologo /target:winexe /win32manifest:"%~dp0setup.manifest" /platform:x64 /optimize+ /out:"%output%" /win32icon:"%~dp0..\linkscope.ico" /reference:System.dll /reference:System.Core.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.ServiceProcess.dll /reference:System.Security.dll /reference:System.Web.Extensions.dll /resource:"%payload%",LinkScope.exe /resource:"%~dp0wizard.ps1",wizard.ps1 "%~dp0Setup.cs" "%~dp0EndpointPermissions.cs" "%~dp0ClamSetup.cs" "%~dp0ClamSignature.cs" "%~dp0..\src\CanaryTemplates.cs" "%~dp0..\src\ClamUpdateWorker.cs" /resource:"%~dp0cisco-talos.gpg",cisco-talos.gpg
if errorlevel 1 exit /b 1
if not exist "%output%" exit /b 1
rem Optional local prerequisite, copied beside Visual Studio build outputs.
rem Avoid copying a file onto itself for Build.cmd in the project root.
for %%I in ("%~dp0..\deploy") do set "sourceDeploy=%%~fI"
for %%I in ("%~dp2deploy") do set "targetDeploy=%%~fI"
if /i "%sourceDeploy%"=="%targetDeploy%" goto complete
if not exist "%targetDeploy%" mkdir "%targetDeploy%"
for %%F in (clamav-latest.msi clamav-latest.msi.sig) do (
  if exist "%sourceDeploy%\%%F" (
    copy /y "%sourceDeploy%\%%F" "%targetDeploy%\%%F" >nul
    if errorlevel 1 exit /b 1
  )
)
:complete
echo Setup generated: "%output%"
exit /b 0
