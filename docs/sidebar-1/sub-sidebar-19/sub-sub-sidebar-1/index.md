# 缓存投毒

## 1. 漏洞原理

### 1.1 基本概念

缓存投毒（Cache Poisoning）是一种利用Web缓存机制的攻击技术，攻击者通过操纵缓存服务器，使其存储恶意构造的HTTP响应，从而将恶意内容分发给其他用户。

### 1.2 攻击流程

1. 识别可缓存的页面和参数
2. 构造恶意请求，包含投毒载荷
3. 发送请求使缓存服务器存储恶意响应
4. 其他用户访问相同资源时收到被污染的响应
5. 恶意代码在用户浏览器中执行

### 1.3 核心要素

- **可缓存的内容**：静态资源、动态页面等
- **用户可控的输入点**：URL参数、HTTP头等
- **缓存键设计缺陷**：缓存服务器识别请求的方式存在漏洞

## 2. 漏洞分类

### 2.1 基于攻击向量分类

#### 2.1.1 HTTP头投毒

- **Host头投毒**
- **X-Forwarded-Host投毒**
- **User-Agent投毒**
- **Referer头投毒**

#### 2.1.2 URL参数投毒

- **查询字符串参数**
- **路径参数**
- **片段标识符**

#### 2.1.3 Cookie投毒

- 利用Cookie值影响响应内容

### 2.2 基于攻击目标分类

#### 2.2.1 XSS缓存投毒

```http
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: example.com
```

#### 2.2.2 开放重定向投毒

```http
GET /login?redirect=https://evil.com HTTP/1.1
Host: example.com
```

#### 2.2.3 资源注入投毒

- 注入恶意脚本、样式表等资源链接

#### 2.2.4 DoS缓存投毒

- 通过缓存大量无效响应耗尽资源

## 3. 关键技术点

### 3.1 缓存键识别

```http
# 正常缓存键组成

Cache-Key: GET|https|example.com|/page|param1=value1

# 存在缺陷的缓存键

Cache-Key: GET|https|example.com|/page # 忽略参数
```

### 3.2 未键控头（Unkeyed Headers）

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: evil.com # 未包含在缓存键中
```

### 3.3 动态内容缓存

- 包含用户输入的页面被错误缓存
- 个性化内容被全局缓存

## 4. 绕过技术

### 4.1 缓存键规范化绕过

#### 4.1.1 参数污染

```http
原始请求

GET /page?param=value HTTP/1.1

投毒请求

GET /page?param=value&malicious=payload HTTP/1.1
```

#### 4.1.2 参数顺序混淆

```http
GET /page?b=2&a=1 HTTP/1.1 # 与 ?a=1&b=2 可能产生不同缓存条目
```

### 4.2 HTTP方法混淆

```http
尝试不同HTTP方法

POST /page HTTP/1.1
Content-Type: application/x-www-form-urlencoded

param=malicious_value 
```

### 4.3 协议级绕过

#### 4.3.1 HTTP请求走私

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /poisoned HTTP/1.1
Host: example.com
```

#### 4.3.2 HTTP/2特性利用

- 标头压缩绕过
- 流多路复用混淆

### 4.4 缓存机制探测

#### 4.4.1 缓存状态检测

```http
观察Age、X-Cache、Cache-Control等头部

HTTP/1.1 200 OK
Age: 3600
X-Cache: HIT 
```

#### 4.4.2 时序分析

- 比较缓存命中与未命中的响应时间差异

## 5. 高级攻击技巧

### 5.1 链式攻击

#### 5.1.1 缓存投毒 + XSS

```http
GET /search?q=<svg onload=alert(1)> HTTP/1.1
Host: example.com
X-Forwarded-Host: example.com
```

#### 5.1.2 缓存投毒 + 开放重定向

```http
GET /login?next=https://evil.com HTTP/1.1
Host: example.com
```

### 5.2 DOM-based缓存投毒

- 利用客户端JavaScript处理未键控头
- 通过DOM操作影响页面内容

### 5.3 二级缓存投毒

- 污染CDN边缘节点
- 影响多级缓存架构

## 6. 防御措施

### 6.1 缓存服务器配置

#### 6.1.1 严格的缓存键设计

```nginx
Nginx示例 - 明确指定缓存键

proxy_cache_key "$scheme$request_method$host$request_uri";
```

#### 6.1.2 敏感头排除

```nginx
排除可能被操纵的头部

proxy_ignore_headers X-Forwarded-Host User-Agent; 
```

### 6.2 应用程序防护

#### 6.2.1 输入验证和净化

```javascript
// 验证Host头
function validateHost(host) {
 const allowedHosts = ['example.com', 'www.example.com'];
 return allowedHosts.includes(host);
}
```

#### 6.2.2 输出编码

```html
<div><%= encodeHTML(userInput) %></div>
```

<!-- 对动态内容进行编码 -->

### 6.3 缓存策略优化

#### 6.3.1 动态内容缓存控制

```http
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

#### 6.3.2 用户相关内容隔离

```http
基于Cookie的缓存变体

Vary: Cookie, User-Agent
```

### 6.4 架构级防护

#### 6.4.1 缓存层隔离

用户 -> CDN -> 反向代理 -> 应用服务器

#### 6.4.2 请求验证

- 在缓存层之前验证请求合法性
- 实施严格的HTTP头检查

### 6.5 监控和检测

#### 6.5.1 异常检测

```python
检测异常的缓存模式

def detect_cache_poisoning(log_entries):
 suspicious_patterns = [
 'unusual_headers',
 'malicious_payloads',
 'cache_hit_anomalies'
 ]
 # 实现检测逻辑
```

#### 6.5.2 定期安全审计

- 检查缓存配置
- 测试缓存键设计
- 验证缓存隔离策略

## 7. 测试方法论

### 7.1 reconnaissance阶段

1. 识别缓存基础设施（CDN、反向代理等）
2. 映射可缓存端点
3. 分析缓存头和行为

### 7.2 漏洞探测

1. 测试未键控头
2. 验证缓存键组成
3. 检查动态内容缓存

### 7.3 利用验证

1. 构造投毒载荷
2. 验证缓存污染效果
3. 确认影响范围

## 8. 工具推荐

### 8.1 专业工具

- **Param Miner** - Burp Suite扩展
- **Cache Poisoning Scanner** - 自动化扫描工具
- **HTTP Request Smuggler** - 请求走私检测

### 8.2 自定义脚本

```python
#!/usr/bin/env python3
import requests

def test_cache_poisoning(url, headers):
 # 实现缓存投毒测试逻辑
 pass
```

## 9. 总结

缓存投毒是一种严重的Web安全威胁，其危害程度取决于被污染内容的影响范围。成功的防御需要多层次的安全措施：

1. **严格配置** - 精心设计缓存键和缓存策略
2. **输入验证** - 对所有用户输入进行严格验证
3. **输出编码** - 防止注入攻击
4. **持续监控** - 实时检测异常模式
5. **定期测试** - 通过渗透测试发现潜在漏洞
