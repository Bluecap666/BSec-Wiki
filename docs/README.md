# BSec WIKI
***
Author:Bluecap    
Created:2025-04-26
***
[CH]网上知识过于杂乱分散，重新总结基础知识，记录重点，漏洞原理、工具使用、攻击手法、绕过、免杀等等，没有口水话，只有经典！
后续完善后会开放公网使用，同时也欢迎大家多多分享!<br>
[EN]Online knowledge is too scattered and disorganized, we reorganize the basic knowledge, record the key points, vulnerability principles, tool usage, attack techniques, bypass, unkillable, etc. There is no sourdough speech, only classic!Later we will make it public for everyone to use. We also welcome everyone to share with us.

*** 
### 环境搭建
1. 项目使用Hello VuePress 
2. npm install -g vuepress  #需 Node.js 
3. vuepress dev docs #本地预览 
4. vuepress build docs #打包生成html 

### 配置导航栏和侧边栏
请查看`docs/.vuepress/config.js`文件进行配置。

### 项目部署到服务器
1. 确保服务器已安装Node.js和npm。
2. 将项目上传到服务器。
3. 在项目根目录下运行以下命令进行构建：
4. 构建完成后，生成的静态文件会位于docs/.vuepress/dist目录下。
5. 配置Web服务器（如Nginx或Apache）将根目录指向docs/.vuepress/dist。
6. 启动Web服务器，访问配置的域名或IP地址即可查看部署后的项目。

### 同步到GitHub
1. 在GitHub上创建一个新的仓库。
2. 在本地项目根目录下初始化Git仓库：  
git init
3. 将本地项目关联到GitHub仓库：  
 git remote add origin https://github.com/your-username/your-repo-name.git
4. 将项目文件添加到Git仓库并提交：  
git add .  
git commit -m "Initial commit"
5. 将本地代码推送到GitHub仓库：  
git push -u origin master
6. 后续更新项目后，执行以下命令同步到GitHub：  
git add .  
git commit -m "Update project"  
git push origin master
7. 出现SSL certificate problem: unable to get local issuer certificate问题执行如下：    
git config --global http.sslBackend "schannel"  # Windows系统