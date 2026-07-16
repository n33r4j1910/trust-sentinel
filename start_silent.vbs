Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "C:\trust-sentinel\target\release\trust-sentinel-daemon.exe", 0, False
WScript.Sleep 8000
WshShell.Run "C:\trust-sentinel\target\release\trust-sentinel-tray.exe", 0, False