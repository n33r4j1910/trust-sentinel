Set WshShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set colProcesses = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'trust-sentinel-daemon.exe'")
If colProcesses.Count = 0 Then
    WshShell.Run "C:\trust-sentinel\target\release\trust-sentinel-daemon.exe", 0, False
    WScript.Sleep 8000
End If
Set colProcesses2 = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'trust-sentinel-tray.exe'")
If colProcesses2.Count = 0 Then
    WshShell.Run "C:\trust-sentinel\target\release\trust-sentinel-tray.exe", 0, False
End If