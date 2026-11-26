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
"%compiler%" /nologo /target:exe /platform:x64 /optimize+ /out:"%output%" /win32icon:"%~dp0..\linkscope.ico" /reference:System.dll /reference:System.Core.dll /reference:System.Windows.Forms.dll /resource:"%payload%",LinkScope.exe /resource:"%~dp0wizard.ps1",wizard.ps1 "%~dp0Setup.cs"
if errorlevel 1 exit /b 1
if not exist "%output%" exit /b 1
echo Setup generated: "%output%"
exit /b 0
