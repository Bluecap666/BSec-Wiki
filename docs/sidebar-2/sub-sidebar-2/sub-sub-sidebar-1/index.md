# 企业系统利用工具

### 一、 办公自动化系统OA利用工具

下面这个表格汇总了几款覆盖多种主流OA、ERP等系统的工具：

| 工具名称 🛠️             | 主要针对系统 📊                                                                                                                                                     | 项目地址 🌐                                                                           | 核心特点 ✨                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **I-Wanna-Get-All** | 用友、泛微、致远、金蝶等多家主流OA及ERP[](http://cn-sec.com/archives/4351509.html#respond)[](http://cn-sec.com/archives/3249290.html)                               | [https://github.com/R4gd0ll/I-Wanna-Get-All](https://github.com/R4gd0ll/I-Wanna-Get-All) | 集成漏洞数量多，支持内存马注入、集成Sqlmap等[](http://cn-sec.com/archives/4351509.html#respond)      |
| **OA-EXPTOOL**      | 近20款不同厂商的OA系统[](https://www.wangan.com/p/11v71968e85d1cff)                                                                                                 | [https://github.com/LittleBear4/OA-EXPTOOL](https://github.com/LittleBear4/OA-EXPTOOL)   | 集合多种OA漏洞的Python工具[](https://www.wangan.com/p/11v71968e85d1cff)                              |
| **Exp-Tools**       | 用友、泛微、通达、致远等10个OA厂商[](https://www.cnblogs.com/nebulapioneer/p/18297367#commentform)[](https://blog.csdn.net/2401_87438300/article/details/142443160) | [https://github.com/cseroad/Exp-Tools](https://github.com/cseroad/Exp-Tools)             | 使用JavaFX开发，专注于漏洞复现与分析[](https://www.cnblogs.com/nebulapioneer/p/18297367#commentform) |
| **TongdaOATool**    | 通达OA[](http://cn-sec.com/archives/2383553.html#respond)                                                                                                           | [https://github.com/xiaokp7/TongdaOATool](https://github.com/xiaokp7/TongdaOATool)       | 专精于通达OA，更新维护勤[](http://cn-sec.com/archives/2383553.html#respond)                          |
| **DecryptTools**    | 覆盖万户、用友、金蝶等20余种主流OA及ERP系统的密码解密[](https://cmd.clicksun.cn/mis/bbs/showbbs.asp?id=34249)                                                       | [https://github.com/wafinfo/DecryptTools](https://github.com/wafinfo/DecryptTools)       | 专注于系统加密数据的解密                                                                             |

### 二、 综合性与平台级利用框架

这类框架通常包含大量模块，覆盖多个系统。

| 工具名称                       | 针对系统/类型                                 | 项目地址                                                                                      | 核心特点                                                           |
| ------------------------------ | --------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **Metasploit Framework** | **几乎所有** （OA, ERP, CMS, 中间件等） | [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) | 渗透测试行业标准，集成了海量漏洞的利用、载荷投递和后渗透模块。     |
| **Nuclei**               | **几乎所有** （Web应用、中间件、设备）  | [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)         | 基于YAML模板的快速、可定制化漏洞扫描与利用工具，社区模板更新极快。 |
| **Pocsuite3**            | **几乎所有**                            | [https://github.com/knownsec/pocsuite3](https://github.com/knownsec/pocsuite3)                   | 由知道创宇开发的开源远程漏洞测试框架，插件化，易于扩展。           |

### 三、 内容管理系统（CMS）利用工具

CMS因其插件和主题生态而漏洞频发。

| 工具名称             | 针对系统                        | 项目地址                                                                  | 核心特点                                                                   |
| -------------------- | ------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **CMSmap**     | WordPress, Joomla!, Drupal      | [https://github.com/Dionach/CMSmap](https://github.com/Dionach/CMSmap)       | 一款自动化的CMS漏洞扫描器，集成了常见的漏洞利用。                          |
| **WPScan**     | WordPress                       | [https://github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) | WordPress安全评估的**事实标准** ，可枚举用户、主题、插件并检查漏洞。 |
| **JoomScan**   | Joomla!                         | [https://github.com/OWASP/joomscan](https://github.com/OWASP/joomscan)       | OWASP旗下的Joomla!漏洞扫描工具。                                           |
| **Droopescan** | Silverstripe, WordPress, Drupal | [https://github.com/droope/droopescan](https://github.com/droope/droopescan) | 用于扫描多种CMS的插件式工具。                                              |

### 四、 ERP与CRM系统利用工具

除了OA，ERP和CRM也是攻击重点。

| 工具名称                             | 针对系统     | 项目地址                                                                                                                                                                                                                          | 核心特点                                              |
| ------------------------------------ | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| **ERP-Vulnerability-Exploits** | 用友、金蝶等 | [https://github.com/Mr-xn/ERP-Exploits](https://github.com/Mr-xn/ERP-Exploits)                                                                                                                                                       | 收集了多种ERP系统（主要是用友、金蝶）的漏洞利用代码。 |
| **SuiteCRM-Exploit**           | SuiteCRM     | [https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/webapp/suitecrm_log_file_rce.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/webapp/suitecrm_log_file_rce.rb) | 以Metasploit模块为例，展示对SuiteCRM特定漏洞的利用。  |
