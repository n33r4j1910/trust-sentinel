$ws = New-Object -ComObject WScript.Shell
$shortcutPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\TrustSentinel.lnk"
$sc = $ws.CreateShortcut($shortcutPath)
$sc.TargetPath = "wscript.exe"
$sc.Arguments = "C:\trust-sentinel\startup.vbs"
$sc.WorkingDirectory = "C:\trust-sentinel"
$sc.WindowStyle = 7
$sc.Save()
Write-Output "Shortcut created"