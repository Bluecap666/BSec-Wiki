# BSec WiKi 📘

---

<div align="center">

![BSec-Wiki Banner](https://img.shields.io/badge/Kali_Linux-Security_Framework-red?style=for-the-badge&logo=kali-linux)
![VuePress](https://img.shields.io/badge/VuePress-Doc_Framework-green?style=for-the-badge&logo=vue.js)

</div>

---

<div align="center">

#### 🚀 Author: Bluecap 👨‍💻 | ⚡ Created: 2025-04-26 📅

</div>

---

### 📖 项目简介

[CH] 总结渗透测试基础知识，包括漏洞原理、工具使用、攻击手法、绕过、免杀等等！ 🔍<br>
[EN] Online knowledge is too scattered and disorganized, we reorganize the basic knowledge, record the key points, vulnerability principles, tool usage, attack techniques, bypass, unkillable, etc. 🌐

---

### 🛠️ 环境搭建

1. 项目使用 <kbd>Hello VuePress</kbd> 💻
2. `npm install -g vuepress`  #需 Node.js ✅
3. `npx vuepress dev docs` 或 `vuepress dev docs` #本地预览 🧪
4. `vuepress build docs` #打包生成 HTML 📦

### 📋 配置导航栏和侧边栏

请查看 `docs/.vuepress/config.js` 文件进行配置。 ⚙️

---

### 🗂️ 项目结构

```
BSec-WiKi/
├── docs/
│   ├── README.md
│   ├── sidebar-1/
│   ├── sidebar-2/
│   └── .vuepress/
│       ├── public/
│       └── styles/
└── package.json
```

---

### 🌐 项目部署到服务器

1. 确保服务器已安装 Node.js 和 npm。 🔧
2. 将项目上传到服务器。 📤
3. 在项目根目录下运行以下命令进行构建： 🔨
4. 构建完成后，生成的静态文件会位于 `docs/.vuepress/dist` 目录下。 📁
5. 配置 Web 服务器（如 Nginx 或 Apache）将根目录指向 `docs/.vuepress/dist`。 🌍
6. 启动 Web 服务器，访问配置的域名或 IP 地址即可查看部署后的项目。 🌐

---

### 🔄 同步到 GitHub

1. 在 GitHub 上创建一个新的仓库。 📁
2. 在本地项目根目录下初始化 Git 仓库：`git init` 🆕
3. 将本地项目关联到 GitHub 仓库：`git remote add origin https://github.com/your-username/your-repo-name.git` 🔗
4. 将项目文件添加到 Git 仓库并提交：`git add .` 和 `git commit -m "Initial commit"` 💾
5. 将本地代码推送到 GitHub 仓库：`git push -u origin master` 📤
6. 后续更新项目后，执行以下命令同步到 GitHub：
   ```
   git add .
   git commit -m "Update project"
   git push origin master
   ``` 🔄
7. 出现 SSL certificate problem: unable to get local issuer certificate 问题执行如下：
   ```bash
   git config --global http.sslBackend "schannel"  # Windows系统 🏁
   ```

---

### 🎯 项目特色

- 📚 结构化的安全知识整理
- 🔍 漏洞原理深度解析
- 🛠️ 工具使用技巧分享
- 🚫 绕过与免杀技术总结
- 📝 渗透测试实战经验

---

### 🤝 贡献指南

欢迎各位安全研究者和开发者贡献内容，共同完善此知识库！ 💪

#### Git 提交信息中的 Emoji 使用指南

在提交代码时使用 emoji 可以让提交历史更容易理解和分类。以下是一些常用的 Git emoji：

| Emoji | 代码 | 描述 |
|-------|------|-----|
| ✨ | `:sparkles:` | 引入新功能 |
| 🐛 | `:bug:` | 修复错误 |
| 🚑 | `:ambulance:` | 紧急修复 |
| 🔒 | `:lock:` | 修复安全问题 |
| 📝 | `:memo:` | 添加或更新文档 |
| 💡 | `:bulb:` | 添加或更新注释 |
| 🔧 | `:wrench:` | 添加或更新配置文件 |
| 🔥 | `:fire:` | 删除代码或文件 |
| 💚 | `:green_heart:` | 修复 CI 构建问题 |
| ✅ | `:white_check_mark:` | 添加测试 |
| 🔐 | `:lock_with_ink_pen:` | 添加安全策略 |
| 🚀 | `:rocket:` | 部署功能 |
| 🎨 | `:art:` | 改进UI/UX设计 |
| 🚜 | `:tractor:` | 大规模重构 |
| 📦 | `:package:` | 更新打包文件 |
| 👕 | `:shirt:` | 移除 Lint 错误 |

示例提交信息：
```
git commit -m "✨ 添加漏洞扫描模块"
git commit -m "🐛 修复登录验证漏洞"
git commit -m "📝 更新项目文档"
git commit -m "🔒 增强密码加密算法"
```

---

<div align="center">

#### ©️ 2025 BSec-Wiki | Made with ❤️ for Cybersecurity Community

</div>