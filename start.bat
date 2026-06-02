@echo off
cd /d C:\trust-sentinel

:loop
tasklist | findstr /i "trust-sentinel-daemon.exe" >nul
if %errorlevel% neq 0 (
    start "" /B "C:\trust-sentinel\target\release\trust-sentinel-daemon.exe"
    timeout /t 12 >nul
)

tasklist | findstr /i "trust-sentinel-tray.exe" >nul
if %errorlevel% neq 0 (
    timeout /t 3 >nul
    start "" /B "C:\trust-sentinel\target\release\trust-sentinel-tray.exe"
)

timeout /t 30 >nul
goto loop