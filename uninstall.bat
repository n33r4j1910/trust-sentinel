@echo off
echo Stopping Trust Sentinel...
taskkill /f /im trust-sentinel-daemon.exe >nul 2>&1
taskkill /f /im trust-sentinel-tray.exe >nul 2>&1
echo Removing startup shortcut...
del /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\TrustSentinel.lnk" >nul 2>&1
echo Removing firewall rules...
powershell -Command "Get-NetFirewallRule -DisplayName 'TS-*' | Remove-NetFirewallRule -Confirm:$false" >nul 2>&1
echo Removing data files...
rmdir /s /q "C:\ProgramData\Trust Sentinel" >nul 2>&1
echo. 
echo Trust Sentinel has been removed.
echo You can now delete C:\trust-sentinel folder manually.
pause