# 服务器配置错误

## 1. 服务器配置错误概述

### 1.1 基本概念

服务器配置错误是指由于不当的服务器配置导致的安全漏洞，攻击者可以利用这些配置缺陷来获取未授权访问、执行命令或破坏系统。

### 1.2 产生原因

- **使用默认配置**

- **缺乏安全加固**

- **权限设置不当**

- **不必要的服务开启**

- **错误的安全策略**

## 2. Web服务器配置错误

### 2.1 Nginx配置错误

#### 2.1.1 不安全配置示例

```nginx
# 危险配置：目录遍历
location /files/ {
    alias /var/www/;
    autoindex on;  # 开启目录列表
}

# 危险配置：任意文件读取
location ~ \.php$ {
    include /etc/nginx/fastcgi_params;
    fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    # 缺少对PHP文件的访问控制
}
```

#### 2.1.2 安全配置

```nginx
server {
    # 基础安全配置
    server_tokens off;  # 隐藏Nginx版本
    autoindex off;      # 关闭目录列表

    # 安全头配置
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # 限制HTTP方法
    if ($request_method !~ ^(GET|HEAD|POST)$ ) {
        return 444;
    }

    # 保护敏感文件
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~* \.(env|git|svn|htaccess|htpasswd)$ {
        deny all;
    }

    # PHP安全配置
    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;

        # 只允许访问存在的PHP文件
        location ~ /uploads/.*\.php$ {
            deny all;
        }
    }
}
```

### 2.2 Apache配置错误

#### 2.2.1 不安全配置示例

```apacheconf
# 危险配置：目录遍历
<Directory "/var/www/html">
    Options Indexes FollowSymLinks  # 启用目录列表
    AllowOverride None
    Require all granted
</Directory>

# 危险配置：服务器信息泄露
ServerTokens OS
ServerSignature On
```

#### 2.2.2 安全配置

```apacheconf
# 基础安全配置
ServerTokens Prod
ServerSignature Off
TraceEnable Off

# 安全模块启用
LoadModule security2_module modules/mod_security2.so
LoadModule headers_module modules/mod_headers.so

<Directory "/var/www/html">
    # 禁用危险选项
    Options -Indexes -FollowSymLinks -ExecCGI
    AllowOverride None

    # 安全头
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    # 限制HTTP方法
    <LimitExcept GET POST>
        Deny from all
    </LimitExcept>
</Directory>

# 保护敏感文件
<FilesMatch "\.(env|git|svn|htaccess|htpasswd|bak|save)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# 禁用服务器端包含
Options -Includes
```

## 3. 应用服务器配置错误

### 3.1 PHP配置错误

#### 3.1.1 不安全php.ini配置

```ini
; 危险配置
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
expose_php = On
allow_url_fopen = On
allow_url_include = On
enable_dl = On
```

#### 3.1.2 安全php.ini配置

```ini
; 生产环境安全配置
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
expose_php = Off

; 文件操作安全
allow_url_fopen = Off
allow_url_include = Off
enable_dl = Off

; 会话安全
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1

; 禁用危险函数
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; 文件上传安全
file_uploads = On
upload_max_filesize = 10M
max_file_uploads = 20
post_max_size = 10M

; 限制文件访问
open_basedir = "/var/www/html:/tmp"
```

### 3.2 Node.js配置错误

#### 3.2.1 不安全配置示例

```javascript
const express = require('express');
const app = express();

// 危险配置：静态文件目录遍历
app.use('/static', express.static('/'));

// 危险配置：不安全的CORS
app.use((req, res, next) => {
 res.header('Access-Control-Allow-Origin', '*');
 res.header('Access-Control-Allow-Headers', '*');
 res.header('Access-Control-Allow-Methods', '*');
 next();
});
```

#### 3.2.2 安全配置

```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

// 使用helmet安全中间件
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// 安全的静态文件服务
app.use('/static', express.static('public', {
    dotfiles: 'ignore',
    etag: true,
    index: false,
    maxAge: '1d',
    redirect: false,
    setHeaders: (res, path) => {
        res.set('x-timestamp', Date.now());
    }
}));

// 安全的CORS配置
app.use((req, res, next) => {
    const allowedOrigins = ['https://example.com', 'https://app.example.com'];
    const origin = req.headers.origin;

    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }

    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    next();
});

// 请求体大小限制
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
```

## 4. 数据库配置错误

### 4.1 MySQL配置错误

#### 4.1.1 不安全配置示例

```sql
-- 危险配置：弱密码策略
SET GLOBAL validate_password.policy = 0;

-- 危险配置：允许远程root访问
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'weakpassword';

-- 危险配置：不安全的权限
GRANT FILE ON *.* TO 'webuser'@'%';
```

#### 4.1.2 安全配置

```ini
# my.cnf 安全配置
[mysqld]
# 基础安全
bind-address = 127.0.0.1
skip-networking = 0

# 密码策略
validate_password.policy = STRONG
validate_password.length = 12
validate_password.mixed_case_count = 1
validate_password.number_count = 1
validate_password.special_char_count = 1

# 日志配置
log_error = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = 1

# 安全设置
local_infile = 0
symbolic_links = 0
secure_file_priv = /var/lib/mysql-files
```

#### 4.1.3 安全SQL配置

```sql
-- 创建专用用户
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'StrongPassword123!';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'webapp'@'localhost';

-- 删除测试数据库
DROP DATABASE test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- 删除匿名用户
DELETE FROM mysql.user WHERE User='';
FLUSH PRIVILEGES;
```

### 4.2 Redis配置错误

#### 4.2.1 不安全配置示例

```roboconf
# redis.conf 危险配置
bind 0.0.0.0
protected-mode no
requirepass ""
```

#### 4.2.2 安全配置

```roboconf
# redis.conf 安全配置
bind 127.0.0.1
protected-mode yes
port 6379

# 认证
requirepass "StrongRedisPassword123!"

# 安全设置
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command SHUTDOWN ""

# 限制
maxmemory 1gb
maxclients 10000
timeout 300

# 日志
loglevel notice
logfile /var/log/redis/redis-server.log
```

## 5. 操作系统配置错误

### 5.1 Linux系统加固

#### 5.1.1 不安全的系统配置

```bash
# 危险配置：宽松的文件权限
chmod 777 /var/www/html
chown nobody:nogroup /var/www/html

# 危险配置：SUID权限
find / -perm -4000 2>/dev/null  # 查找所有SUID文件
```

#### 5.1.2 系统安全配置

```bash
#!/bin/bash
# 系统安全加固脚本

# 1. 文件权限加固
chmod 750 /var/www/html
chown www-data:www-data /var/www/html
find /var/www/html -type f -exec chmod 644 {} \;
find /var/www/html -type d -exec chmod 755 {} \;

# 2. 删除不必要的SUID权限
chmod u-s /usr/bin/find
chmod u-s /usr/bin/nmap
chmod u-s /usr/bin/vim

# 3. 配置防火墙
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https

# 4. 配置SSH安全
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
systemctl restart ssh

# 5. 配置系统日志
echo "auth,authpriv.* /var/log/auth.log" >> /etc/rsyslog.d/50-default.conf
echo "*.info;mail.none;authpriv.none;cron.none /var/log/messages" >> /etc/rsyslog.d/50-default.conf
systemctl restart rsyslog
```

### 5.2 服务管理配置

#### 5.2.1 Systemd服务安全配置

```ini
# /etc/systemd/system/webapp.service
[Unit]
Description=Web Application
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/html
ExecStart=/usr/bin/node app.js
Restart=on-failure

# 安全设置
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWriteDirectories=/var/www/html
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
```

## 6. 容器配置错误

### 6.1 Docker配置错误

#### 6.1.1 不安全Dockerfile示例

```dockerfile
FROM node:14

# 危险配置：以root用户运行
USER root

# 危险配置：复制所有文件
COPY . .

# 危险配置：暴露所有端口
EXPOSE 3000

CMD ["node", "app.js"]
```

#### 6.1.2 安全Dockerfile配置

```dockerfile
FROM node:14-alpine

# 创建非root用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# 设置工作目录
WORKDIR /app

# 复制package文件
COPY --chown=nextjs:nodejs package*.json ./

# 安装依赖
RUN npm ci --only=production

# 复制应用文件
COPY --chown=nextjs:nodejs . .

# 切换到非root用户
USER nextjs

# 暴露端口
EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node healthcheck.js

# 启动命令
CMD ["node", "app.js"]
```

#### 6.1.3 Docker安全运行配置

```yaml
# docker-compose.yml 安全配置
version: '3.8'
services:
  webapp:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
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

  database:
    image: postgres:13
    environment:
      - POSTGRES_DB=app
      - POSTGRES_USER=appuser
      - POSTGRES_PASSWORD=StrongPassword123!
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    volumes:
      - db_data:/var/lib/postgresql/data
    networks:
      - backend

networks:
  frontend:
  backend:

volumes:
  db_data:
```

## 7. 云服务配置错误

### 7.1 AWS安全配置

#### 7.1.1 不安全S3配置

```json
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Effect": "Allow",
 "Principal": "*",
 "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::my-bucket/*"
 }
 ]
}
```

#### 7.1.2 安全S3配置

```json
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Effect": "Allow",
 "Principal": {
 "AWS": "arn:aws:iam::123456789012:user/username"
 },
 "Action": [
 "s3:GetObject",
 "s3:PutObject"
 ],
 "Resource": "arn:aws:s3:::my-bucket/*",
 "Condition": {
 "IpAddress": {
 "aws:SourceIp": "192.0.2.0/24"
 }
 }
 }
 ]
}
```

#### 7.1.3 AWS安全组配置

```json
{
 "GroupName": "web-server-sg",
 "Description": "Security group for web servers",
 "IpPermissions": [
 {
 "IpProtocol": "tcp",
 "FromPort": 80,
 "ToPort": 80,
 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
 },
 {
 "IpProtocol": "tcp",
 "FromPort": 443,
 "ToPort": 443,
 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
 },
 {
 "IpProtocol": "tcp",
 "FromPort": 22,
 "ToPort": 22,
 "IpRanges": [{"CidrIp": "203.0.113.0/24"}]
 }
 ]
}
```

## 8. 检测和审计工具

### 8.1 配置扫描工具

#### 8.1.1 Lynis - 系统安全审计

```bash
# 安装Lynis
apt install lynis

# 运行系统审计
lynis audit system

# 生成报告
lynis show report
```

#### 8.1.2 Docker Bench Security

```bash
# 运行Docker安全检测
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

#### 8.1.3 CIS-CAT - 合规性扫描

```bash
# CIS基准扫描
java -jar cis-cat.jar -a assess -p "Level 1" -b "Ubuntu Linux 20.04"
```

### 8.2 自定义配置检查脚本

```python
#!/usr/bin/env python3
import os
import subprocess
import configparser

class SecurityAudit:
    def check_file_permissions(self):
        """检查文件权限"""
        sensitive_files = [
            '/etc/passwd',
            '/etc/shadow', 
            '/etc/gshadow',
            '/etc/group',
            '/etc/sudoers'
        ]
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                if stat.st_mode & 0o777 != 0o644:
                    print(f"Warning: {file_path} has insecure permissions")
    
    def check_ssh_config(self):
        """检查SSH配置"""
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                config = f.read()
            
            checks = {
                'PermitRootLogin': 'no',
                'PasswordAuthentication': 'no',
                'Protocol': '2',
                'X11Forwarding': 'no'
            }
            
            for key, expected_value in checks.items():
                if f"{key} {expected_value}" not in config:
                    print(f"Warning: SSH config {key} is not set to {expected_value}")
                    
        except FileNotFoundError:
            print("SSH config file not found")
    
    def check_mysql_config(self):
        """检查MySQL配置"""
        try:
            config = configparser.ConfigParser()
            config.read('/etc/mysql/my.cnf')
            
            checks = {
                'bind-address': '127.0.0.1',
                'local-infile': '0',
                'skip-symbolic-links': '1'
            }
            
            for key, expected_value in checks.items():
                if not config.has_option('mysqld', key) or \
                   config.get('mysqld', key) != expected_value:
                    print(f"Warning: MySQL config {key} is not set to {expected_value}")
                    
        except Exception as e:
            print(f"Error checking MySQL config: {e}")
    
    def run_all_checks(self):
        """运行所有安全检查"""
        print("Starting security configuration audit...")
        self.check_file_permissions()
        self.check_ssh_config() 
        self.check_mysql_config()
        print("Security audit completed")

if __name__ == "__main__":
    audit = SecurityAudit()
    audit.run_all_checks()
```

## 9. 监控和告警

### 9.1 配置变更监控

#### 9.1.1 文件完整性监控

```bash
# 使用AIDE进行文件完整性检查
apt install aide
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 定期检查
aide --check
```

#### 9.1.2 系统审计配置

```bash
# 配置auditd
cat > /etc/audit/audit.rules << EOF
# 监控关键文件
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/group -p wa -k identity

# 监控系统调用
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# 监控网络配置
-w /etc/hosts -p wa -k network_mod
-w /etc/hostname -p wa -k network_mod
EOF

systemctl enable auditd
systemctl start auditd
```

## 10. 最佳实践总结

### 10.1 配置管理原则

1. **最小权限原则**：只授予必要的最小权限

2. **默认拒绝**：默认拒绝所有，按需开放

3. **纵深防御**：多层安全控制

4. **定期审计**：定期检查配置安全性

### 10.2 自动化安全配置

```yaml
# Ansible安全配置示例
- name: Harden SSH configuration
  lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "^{{ item.key }}"
    line: "{{ item.key }} {{ item.value }}"
    state: present
    backup: yes
  with_items:
    - { key: 'PermitRootLogin', value: 'no' }
    - { key: 'PasswordAuthentication', value: 'no' }
    - { key: 'Protocol', value: '2' }
    - { key: 'X11Forwarding', value: 'no' }
  notify: restart ssh

- name: Set secure file permissions
  file:
    path: "{{ item.path }}"
    owner: "{{ item.owner }}"
    group: "{{ item.group }}"
    mode: "{{ item.mode }}"
  with_items:
    - { path: '/etc/passwd', owner: 'root', group: 'root', mode: '0644' }
    - { path: '/etc/shadow', owner: 'root', group: 'shadow', mode: '0640' }
    - { path: '/var/www/html', owner: 'www-data', group: 'www-data', mode: '0750' }
```

### 10.3 持续安全监控

```bash
#!/bin/bash
# 持续安全监控脚本

# 检查失败的SSH登录
echo "Failed SSH attempts:"
grep "Failed password" /var/log/auth.log | tail -10

# 检查新增用户
echo "Recent user additions:"
lastlog -t 7

# 检查系统更新
echo "Available security updates:"
apt list --upgradable | grep -i security

# 检查开放端口
echo "Open network ports:"
netstat -tulpn | grep LISTEN
```
