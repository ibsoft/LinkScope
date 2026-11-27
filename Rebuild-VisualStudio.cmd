@echo off
setlocal
set "configuration=%~1"
if not defined configuration set "configuration=Release"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0tools\Invoke-ProjectBuild.ps1" -Mode Rebuild -Configuration "%configuration%"
set "result=%errorlevel%"
if not "%result%"=="0" echo Rebuild failed. Review the diagnostic log in build-logs.
if "%result%"=="0" echo Rebuild succeeded.
exit /b %result%
