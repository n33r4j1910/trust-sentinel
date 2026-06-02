@echo off
start "" "C:\trust-sentinel\target\release\trust-sentinel-daemon.exe"
timeout /t 3 >nul
start "" "C:\trust-sentinel\target\release\trust-sentinel-tray.exe"