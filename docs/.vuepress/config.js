module.exports = {
  title: 'BSec WIKI', // 添加网页标题
  head: [
    ['meta', { name: 'author', content: 'Bluecap' }] // 将 head 配置移到根级别
  ],
  themeConfig: {
    logo: 'https://via.placeholder.com/150x50.png?text=BSec+Logo', // Logo 配置
    footer: '© 2023 Bluecap. All rights reserved.', // 页脚配置
    nav: [
      { text: 'MySite', link: 'http://www.boloveyou.fun/' },
      { text: 'Github', link: 'https://github.com/Bluecap666/BSec-Wiki' }
    ],
    sidebar: [
      {
        title: '漏洞原理(WEB)',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'SQL注入',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-1/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'SSRF服务端请求伪造',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-2/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-2/sub-sub-sidebar-2/' 
            ]
          },
          {
            title: 'XSS跨站脚本',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-3/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-3/sub-sub-sidebar-2/' 
            ]
          },
          {
            title: 'CSRF跨站请求伪造',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-4/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-4/sub-sub-sidebar-2/' 
            ]
          },
          {
            title: '文件上传',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-5/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-5/sub-sub-sidebar-2/' 
            ]
          },
          {
            title: '文件读取',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-6/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-6/sub-sub-sidebar-2/' 
            ]
          },
          {
            title: '命令执行',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-7/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-7/sub-sub-sidebar-2/' 
            ]
          },
          {
            title: 'XXE xml外部实体注入',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-8/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-8/sub-sub-sidebar-2/' 
            ]
          },
          {
            title: '反序列化',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-9/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-9/sub-sub-sidebar-2/' 
            ]
          },
          {
            title: '逻辑漏洞',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-10/sub-sub-sidebar-1/',
              'sidebar-1/sub-sidebar-10/sub-sub-sidebar-2/' 
            ]
          },
        ]
      },
      {
        title: '漏洞利用(WEB)',
        collapsable: true, // 允许折叠
        children: [
          {
            title: '漏洞手册',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-1/',
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-2/',
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-3/'
            ]
          },
          {
            title: '利用工具',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-2/sub-sub-sidebar-1/',
              'sidebar-2/sub-sidebar-2/sub-sub-sidebar-2/' 
            ]
          }
          
        ]
      },
      {
        title: '内网漏洞原理',
        collapsable: true, // 允许折叠
        children: [
          {
            title: '工作组',
            collapsable: true,
            children: [
              'sidebar-3/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-3/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '域环境',
            collapsable: true,
            children: [
              'sidebar-3/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-3/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: '其他漏洞',
        collapsable: true, // 允许折叠
        children: [
          {
            title: '钓鱼',
            collapsable: true,
            children: [
              'sidebar-4/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-4/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'DDOS',
            collapsable: true,
            children: [
              'sidebar-4/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-4/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'APT',
            collapsable: true,
            children: [
              'sidebar-4/sub-sidebar-3/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-4/sub-sidebar-3/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: '移动端漏洞',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'Android',
            collapsable: true,
            children: [
              'sidebar-5/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-5/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'IOS',
            collapsable: true,
            children: [
              'sidebar-5/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-5/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: '物理漏洞',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'WIFI',
            collapsable: true,
            children: [
              'sidebar-6/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-6/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      }
    ]
  }
};