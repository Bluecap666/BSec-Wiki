module.exports = {
  title: 'BSec WiKi', // 添加网页标题
  head: [
    ['meta', { name: 'author', content: 'Bluecap' }] // 将 head 配置移到根级别
  ],
  themeConfig: {
    logo: 'dist/assets/img/bsec.png', // Logo 配置
    footer: '© 2023 Bluecap. All rights reserved.', // 页脚配置
    nav: [
      { text: 'MySite', link: 'http://www.boloveyou.fun/' },
      { text: 'Github', link: 'https://github.com/Bluecap666/BSec-Wiki' }
    ],
    sidebar: [
      {
        title: 'WEB安全',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'SQL注入',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-1/sub-sub-sidebar-1/' // 确保路径正确
            ]
          },
          {
            title: 'SSRF服务端请求伪造',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-2/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '跨站脚本',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-3/sub-sub-sidebar-1/'
            ]
          },
          {
            title: 'CSRF跨站请求伪造',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-4/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '文件上传',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-5/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '文件读取',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-6/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '命令执行',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-7/sub-sub-sidebar-1/'
            ]
          },
          {
            title: 'XXE xml外部实体注入',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-8/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '反序列化',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-9/sub-sub-sidebar-1/' 
            ]
          },
          {
            title: '逻辑漏洞',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-10/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '服务器配置错误',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-11/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '权限提升',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-12/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '信息泄露',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-13/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '不安全的通信',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-14/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '拒绝服务',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-15/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '中间件漏洞',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-16/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '第三方组件漏洞',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-17/sub-sub-sidebar-1/'
            ]
          }, 
          {
            title: 'API安全漏洞',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-18/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '缓存投毒',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-19/sub-sub-sidebar-1/'
            ]
          },
          {
            title: 'HTTP请求走私',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-20/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '会话管理漏洞',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-21/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '点击劫持漏洞',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-22/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '不安全的重定向和转发',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-23/sub-sub-sidebar-1/'
            ]
          },
          {
            title: '使用已知漏洞的组件',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-24/sub-sub-sidebar-1/'
            ]
          }

        ]
      },
      {
        title: 'WEB攻击',
        collapsable: true, // 允许折叠
        children: [
          {
            title: '检测工具',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-1/',
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-2/',
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-3/',
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-4/',
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-5/'
            ]
          },
          {
            title: '利用工具',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-2/sub-sub-sidebar-1/',
              'sidebar-2/sub-sidebar-2/sub-sub-sidebar-2/',
              'sidebar-2/sub-sidebar-2/sub-sub-sidebar-3/',
              'sidebar-2/sub-sidebar-2/sub-sub-sidebar-4/'
            ]
          },
          {
            title: '综合漏洞检测利用工具',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-3/sub-sub-sidebar-1/',
              'sidebar-2/sub-sidebar-3/sub-sub-sidebar-2/',
              'sidebar-2/sub-sidebar-3/sub-sub-sidebar-3/'
            ]
          },
          {
            title: '代理工具',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-4/sub-sub-sidebar-1/'
              // 'sidebar-2/sub-sidebar-4/sub-sub-sidebar-2/',
              // 'sidebar-2/sub-sidebar-4/sub-sub-sidebar-3/'
            ]
          },
          {
            title: '漏洞库',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-5/sub-sub-sidebar-1/'
              // 'sidebar-2/sub-sidebar-5/sub-sub-sidebar-2/',
              // 'sidebar-2/sub-sidebar-5/sub-sub-sidebar-3/'
              ]
          }
        ]
      },
      {
        title: '内网安全',
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
          },
          {
            title: '工作组利用工具',
            collapsable: true,
            children: [
              'sidebar-3/sub-sidebar-3/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-3/sub-sidebar-3/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '域环境利用工具',
            collapsable: true,
            children: [
              'sidebar-3/sub-sidebar-4/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-3/sub-sidebar-4/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '内网代理工具',
            collapsable: true,
            children: [
              'sidebar-3/sub-sidebar-5/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-3/sub-sidebar-5/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '漏洞库',
            collapsable: true,
            children: [
              'sidebar-3/sub-sidebar-6/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-3/sub-sidebar-6/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: '安全进阶',
        collapsable: true, // 允许折叠
        children: [
          {
            title: '代码审计',
            collapsable: true,
            children: [
              'sidebar-4/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-4/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '免杀',
            collapsable: true,
            children: [
              'sidebar-4/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-4/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '持久化',
            collapsable: true,
            children: [
              'sidebar-4/sub-sidebar-3/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-4/sub-sidebar-3/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'C2',
            collapsable: true,
            children: [
              'sidebar-4/sub-sidebar-4/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-4/sub-sidebar-4/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
          
        ]
      },
      {
        title: '安全攻防',
        collapsable: true, // 允许折叠
        children: [
          {
            title: '钓鱼',
            collapsable: true,
            children: [
              'sidebar-5/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-5/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'DDOS',
            collapsable: true,
            children: [
              'sidebar-5/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-5/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'APT',
            collapsable: true,
            children: [
              'sidebar-5/sub-sidebar-3/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-5/sub-sidebar-3/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '挖矿',
            collapsable: true,
            children: [
              'sidebar-5/sub-sidebar-3/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-5/sub-sidebar-3/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '僵木蠕',
            collapsable: true,
            children: [
              'sidebar-5/sub-sidebar-3/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-5/sub-sidebar-3/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '黑灰产',
            collapsable: true,
            children: [
              'sidebar-5/sub-sidebar-3/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-5/sub-sidebar-3/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: '移动安全',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'Android',
            collapsable: true,
            children: [
              'sidebar-6/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-6/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'IOS',
            collapsable: true,
            children: [
              'sidebar-6/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-6/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: '无线安全',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'WIFI',
            collapsable: true,
            children: [
              'sidebar-7/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-7/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '蓝牙',
            collapsable: true,
            children: [
              'sidebar-7/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-7/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: 'CTF',
        collapsable: true, // 允许折叠
        children: [
          {
            title: '杂项',
            collapsable: true,
            children: [
              'sidebar-8/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-8/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'web',
            collapsable: true,
            children: [
              'sidebar-8/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-8/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'MISC',
            collapsable: true,
            children: [
              'sidebar-8/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-8/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'PWN',
            collapsable: true,
            children: [
              'sidebar-8/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-8/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: '安全加固',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'windows安全加固',
            collapsable: true,
            children: [
              'sidebar-9/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-9/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'Linux安全加固',
            collapsable: true,
            children: [
              'sidebar-9/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-9/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'Android安全加固',
            collapsable: true,
            children: [
              'sidebar-9/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-9/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'IOS安全加固',
            collapsable: true,
            children: [
              'sidebar-9/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-9/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: '应急响应',
        collapsable: true, // 允许折叠
        children: [
          {
            title: '应急响应技术',
            collapsable: true,
            children: [
              'sidebar-10/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-10/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: '应急响应场景',
            collapsable: true,
            children: [
              'sidebar-10/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-10/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]

          }
        ]
      }
    ]
  }
};