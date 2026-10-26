@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  python -B -m traffic_observer gui %*
) else (
  py -3 -B -m traffic_observer gui %*
)
if errorlevel 1 pause
endlocal
