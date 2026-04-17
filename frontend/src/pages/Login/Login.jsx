import { useState } from 'react'
import { Form, Input, Button, message, Checkbox } from 'antd'
import { UserOutlined, LockOutlined, SafetyOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import api from '../../services/api'
import './Login.css'

const Login = () => {
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const onFinish = async (values) => {
    setLoading(true)
    try {
      await api.login(values.username, values.password)
      message.success('登录成功')
      navigate('/')
    } catch (error) {
      message.error(error.message || '登录失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-background">
        <div className="login-content">
          <div className="login-header">
            <div className="login-logo">
              <SafetyOutlined style={{ fontSize: 48, color: '#1677FF' }} />
            </div>
            <h1 className="login-title">蚂蚁安全风险评估系统</h1>
            <p className="login-subtitle">ANTsafe Security Assessment System</p>
          </div>

          <Form
            name="login"
            className="login-form"
            onFinish={onFinish}
            initialValues={{ remember: true }}
            size="large"
          >
            <Form.Item
              name="username"
              rules={[{ required: true, message: '请输入用户名' }]}
            >
              <Input
                prefix={<UserOutlined style={{ color: '#8C8C8C' }} />}
                placeholder="用户名: admin"
              />
            </Form.Item>

            <Form.Item
              name="password"
              rules={[{ required: true, message: '请输入密码' }]}
            >
              <Input.Password
                prefix={<LockOutlined style={{ color: '#8C8C8C' }} />}
                placeholder="密码: admin123"
              />
            </Form.Item>

            <Form.Item name="remember" valuePropName="checked">
              <div className="login-options">
                <Checkbox>记住密码</Checkbox>
                <a href="#">忘记密码?</a>
              </div>
            </Form.Item>

            <Form.Item>
              <Button type="primary" htmlType="submit" block loading={loading} className="login-button">
                登 录
              </Button>
            </Form.Item>
          </Form>

          <div className="login-footer">
            <p>© 2024 蚂蚁安全 www.mayisafe.cn</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Login
