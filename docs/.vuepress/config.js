module.exports = {
  themeConfig: {
    // 删除导航栏配置
    sidebar: [
      {
        title: 'Sidebar 1',
        collapsable: true, // 允许折叠
        children: [
          'sidebar-1/', // 确保路径正确
          'sidebar-1/sub-sidebar-1/', // 确保路径正确
          'sidebar-1/sub-sidebar-2/' // 确保路径正确
        ]
      },
      {
        title: 'Sidebar 2',
        collapsable: true, // 允许折叠
        children: [
          'sidebar-2/', // 确保路径正确
          'sidebar-2/sub-sidebar-1/', // 确保路径正确
          'sidebar-2/sub-sidebar-2/' // 确保路径正确
        ]
      }
    ]
  }
};