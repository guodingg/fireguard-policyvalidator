import { useState } from 'react'
import { Layout, Menu, Avatar, Dropdown, Space, Breadcrumb } from 'antd'
import {
  DashboardOutlined,
  SearchOutlined,
  CloudServerOutlined,
  SafetyOutlined,
  FileTextOutlined,
  BugOutlined,
  HistoryOutlined,
  SettingOutlined,
  TeamOutlined,
  UserOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  RobotOutlined,
  FolderOutlined
} from '@ant-design/icons'
import { useNavigate, useLocation } from 'react-router-dom'
import useAuthStore from '../store/authStore'

const { Header, Sider, Content, Footer } = Layout

const menuItems = [
  { key: '/dashboard', icon: <DashboardOutlined />, label: '首页' },
  { key: '/scan/tasks', icon: <SearchOutlined />, label: '扫描任务' },
  { key: '/assets', icon: <CloudServerOutlined />, label: '资产管理' },
  { key: '/vulns', icon: <SafetyOutlined />, label: '漏洞管理' },
  { key: '/pocs', icon: <BugOutlined />, label: 'POC管理' },
  { key: '/reports', icon: <FileTextOutlined />, label: '报告管理' },
  { key: '/ai-assistant', icon: <RobotOutlined />, label: 'AI助手' },
  { key: '/dicts', icon: <FolderOutlined />, label: '字典管理' },
  { key: '/logs', icon: <HistoryOutlined />, label: '日志审计' },
  { key: '/settings', icon: <SettingOutlined />, label: '系统设置' },
  { key: '/users', icon: <TeamOutlined />, label: '用户管理' }
]

const MainLayout = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const { user, logout } = useAuthStore()

  const handleMenuClick = ({ key }) => {
    navigate(key)
  }

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const userMenuItems = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: '个人中心'
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: '退出登录',
      danger: true
    }
  ]

  const getBreadcrumbItems = () => {
    const paths = location.pathname.split('/').filter(Boolean)
    const items = [{ title: '首页' }]
    
    if (paths.length > 0) {
      const pathLabels = {
        dashboard: '数据大屏',
        scan: '扫描任务',
        tasks: '任务管理',
        assets: '资产管理',
        vulns: '漏洞管理',
        pocs: 'POC管理',
        reports: '报告管理',
        ai_assistant: 'AI助手',
        dicts: '字典管理',
        logs: '日志审计',
        settings: '系统设置',
        users: '用户管理'
      }
      
      paths.forEach((path, index) => {
        const label = pathLabels[path] || path
        const pathKey = '/' + paths.slice(0, index + 1).join('/')
        items.push({ title: label })
      })
    }
    
    return items
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        trigger={null}
        collapsible
        collapsed={collapsed}
        width={220}
        style={{
          background: '#fff',
          borderRight: '1px solid #E8E8E8',
          position: 'fixed',
          left: 0,
          top: 0,
          bottom: 0,
          zIndex: 100
        }}
      >
        {/* Logo */}
        <div className="logo-area" style={{ justifyContent: collapsed ? 'center' : 'flex-start', padding: collapsed ? '16px 8px' : '16px' }}>
          <div className="logo-icon">蚂蚁</div>
          {!collapsed && (
            <div className="logo-text">
              <span className="logo-title">蚂蚁安全风险评估系统</span>
              <span className="logo-subtitle">ANTsafe System</span>
            </div>
          )}
        </div>

        {/* 菜单 */}
        <Menu
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={handleMenuClick}
          style={{
            borderRight: 'none',
            marginTop: 8
          }}
        />
      </Sider>

      <Layout style={{ marginLeft: collapsed ? 80 : 220, transition: 'margin-left 0.2s' }}>
        {/* Header */}
        <Header
          style={{
            background: '#fff',
            padding: '0 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: '1px solid #E8E8E8',
            position: 'sticky',
            top: 0,
            zIndex: 99
          }}
        >
          <Space size={16}>
            {collapsed ? (
              <MenuUnfoldOutlined onClick={() => setCollapsed(!collapsed)} style={{ fontSize: 18, cursor: 'pointer' }} />
            ) : (
              <MenuFoldOutlined onClick={() => setCollapsed(!collapsed)} style={{ fontSize: 18, cursor: 'pointer' }} />
            )}
            <Breadcrumb items={getBreadcrumbItems()} />
          </Space>

          <Space size={16}>
            <Dropdown
              menu={{
                items: userMenuItems,
                onClick: ({ key }) => {
                  if (key === 'logout') handleLogout()
                }
              }}
              placement="bottomRight"
            >
              <Space style={{ cursor: 'pointer' }}>
                <Avatar style={{ backgroundColor: '#1677FF' }} icon={<UserOutlined />} />
                <span style={{ fontWeight: 500 }}>{user?.username || 'Admin'}</span>
              </Space>
            </Dropdown>
          </Space>
        </Header>

        {/* Content */}
        <Content style={{ padding: 24, minHeight: 'calc(100vh - 64px - 48px)', background: '#F5F7FA' }}>
          {children}
        </Content>

        {/* Footer */}
        <Footer style={{ textAlign: 'center', padding: '16px', background: 'transparent', borderTop: '1px solid #E8E8E8' }}>
          <span>© 2024 </span>
          <a href="https://www.mayisafe.cn" target="_blank" rel="noopener noreferrer" style={{ color: '#1677FF', textDecoration: 'none' }}>
            蚂蚁安全
          </a>
          <span> www.mayisafe.cn 版权所有</span>
        </Footer>
      </Layout>
    </Layout>
  )
}

export default MainLayout
