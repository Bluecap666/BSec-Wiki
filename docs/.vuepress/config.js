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
        title: 'Sidebar 1',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'Sub Sidebar 1-1',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-1/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'Sub Sidebar 1-2',
            collapsable: true,
            children: [
              'sidebar-1/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-1/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      },
      {
        title: 'Sidebar 2',
        collapsable: true, // 允许折叠
        children: [
          {
            title: 'Sub Sidebar 2-1',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-2/sub-sidebar-1/sub-sub-sidebar-2/' // 确保路径正确
            ]
          },
          {
            title: 'Sub Sidebar 2-2',
            collapsable: true,
            children: [
              'sidebar-2/sub-sidebar-2/sub-sub-sidebar-1/', // 确保路径正确
              'sidebar-2/sub-sidebar-2/sub-sub-sidebar-2/' // 确保路径正确
            ]
          }
        ]
      }
    ]
  }
};