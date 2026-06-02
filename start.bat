@echo off
cd /d C:\trust-sentinel
start "" "C:\trust-sentinel\target\release\trust-sentinel-daemon.exe"
timeout /t 8 >nul
start "" "C:\trust-sentinel\target\release\trust-sentinel-tray.exe"