import { useState } from 'react'
import { Card, Steps, Form, Input, Select, Button, Space, message, Row, Col, Alert, Switch, Typography, Tag, Spin, Table } from 'antd'
import { useNavigate } from 'react-router-dom'
import { CheckCircleOutlined, CloseCircleOutlined, GlobalOutlined, SearchOutlined, CloudServerOutlined, WifiOutlined } from '@ant-design/icons'
import api from '../../services/api'

const { Text, Paragraph } = Typography
const { TextArea } = Input

const TaskCreate = () => {
  const navigate = useNavigate()
  const [currentStep, setCurrentStep] = useState(0)
  const [form] = Form.useForm()
  const [diagnosticLoading, setDiagnosticLoading] = useState(false)
  const [diagnosticResults, setDiagnosticResults] = useState(null)
  const [submitLoading, setSubmitLoading] = useState(false)
  const [diagnosticTargets, setDiagnosticTargets] = useState('')
  const [formData, setFormData] = useState({})
  const [portMode, setPortMode] = useState('common')

  const diagnoseNetwork = async () => {
    if (!diagnosticTargets.trim()) {
      message.warning('请输入诊断目标')
      return
    }
    setDiagnosticLoading(true)
    setDiagnosticResults(null)
    try {
      const result = await api.request('/diagnostic/', {
        method: 'POST',
        body: JSON.stringify({ targets: diagnosticTargets.split('\n').filter(t => t.trim()) })
      })
      setDiagnosticResults(result.code === 0 ? result.data : null)
      if (result.code !== 0) {
        message.error('诊断失败: ' + (result.msg || '未知错误'))
      }
    } catch (error) {
      console.error('Diagnostic error:', error)
      message.error('网络诊断请求失败')
      setDiagnosticResults(null)
    } finally {
      setDiagnosticLoading(false)
    }
  }

  const handleSubmit = async (values) => {
    setSubmitLoading(true)
    try {
      const options = {
        port_mode: values.port_mode || 'common',
      }
      if (values.port_mode === 'custom' && values.custom_ports) {
        options.ports = values.custom_ports
      }
      if (values.ai_assist) {
        options.ai_assist = true
      }

      const taskData = {
        ...formData,
        name: formData.name,
        target: formData.target,
        scan_type: values.scan_type,
        options,
        ai_assist: values.ai_assist || false
      }
      await api.createTask(taskData)
      message.success('任务创建成功')
      navigate('/scan/tasks')
    } catch (error) {
      message.error('创建任务失败: ' + (error?.message || '未知错误'))
    } finally {
      setSubmitLoading(false)
    }
  }

  const diagnosticColumns = [
    { title: '目标', dataIndex: 'target', key: 'target', render: (t) => <Text code>{t}</Text> },
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => s === 'success' ? <Tag color="success" icon={<CheckCircleOutlined />}>正常</Tag> : <Tag color="error" icon={<CloseCircleOutlined />}>失败</Tag> },
    { title: '延迟', dataIndex: 'latency', key: 'latency', render: (l) => l ? <Text>{l}ms</Text> : '-' },
    { title: 'DNS', dataIndex: 'dns', key: 'dns', render: (d) => d ? <Tag color="green">通过</Tag> : <Tag color="red">失败</Tag> },
    { title: 'TCP', dataIndex: 'tcp', key: 'tcp', render: (d) => d ? <Tag color="green">通过</Tag> : <Tag color="red">失败</Tag> },
    { title: 'HTTP', dataIndex: 'http', key: 'http', render: (d) => d ? <Tag color="green">通过</Tag> : <Tag color="red">失败</Tag> },
    { title: '说明', dataIndex: 'message', key: 'message' },
  ]

  const steps = [
    { title: '基本信息', icon: <CloudServerOutlined /> },
    { title: '网络诊断', icon: <GlobalOutlined /> },
    { title: '扫描配置', icon: <SearchOutlined /> },
  ]

  const nextStep = async () => {
    try {
      if (currentStep === 0) {
        const values = await form.validateFields(['name', 'target'])
        const targets = values.target.split('\n').filter(t => t.trim()).join('\n')
        setFormData(prev => ({ ...prev, ...values }))
        setDiagnosticTargets(targets)
        setCurrentStep(1)
      } else {
        setCurrentStep(c => Math.min(c + 1, 2))
      }
    } catch (err) {
      // Validation failed
    }
  }

  const prevStep = () => setCurrentStep(c => Math.max(c - 1, 0))

  const renderStepContent = () => {
    switch (currentStep) {
      case 0:
        return (
          <Form form={form} layout="vertical">
            <Form.Item label="任务名称" name="name" rules={[{ required: true, message: '请输入任务名称' }]}>
              <Input placeholder="请输入任务名称" />
            </Form.Item>
            <Form.Item label="扫描目标" name="target" rules={[{ required: true, message: '请输入扫描目标' }]}>
              <TextArea rows={4} placeholder="支持单IP、IP段、CIDR、域名，每行一个" />
            </Form.Item>
            <Form.Item>
              <Button type="primary" onClick={nextStep}>下一步：网络诊断</Button>
            </Form.Item>
          </Form>
        )
      case 1:
        return (
          <Space direction="vertical" style={{ width: '100%' }} size="large">
            <Alert message="网络诊断（可选）" description="在扫描前检测网络连通性，确保目标可达。如跳过，扫描任务仍会正常执行。" type="info" showIcon />
            <Card>
              <Paragraph>诊断目标（已从扫描目标自动填充）</Paragraph>
              <TextArea rows={4} placeholder="每行一个目标" value={diagnosticTargets} onChange={(e) => setDiagnosticTargets(e.target.value)} />
              <Button type="primary" icon={<WifiOutlined />} onClick={diagnoseNetwork} loading={diagnosticLoading} style={{ marginTop: 16 }}>开始诊断</Button>
            </Card>
            {diagnosticLoading && <Card><Space><Spin /> 正在诊断...</Space></Card>}
            {diagnosticResults && (
              <Card title="诊断结果">
                <Row gutter={16} style={{ marginBottom: 16 }}>
                  <Col span={6}><Card size="small"><Text>总目标：{diagnosticResults.summary.total}</Text></Card></Col>
                  <Col span={6}><Card size="small"><Text style={{ color: '#52c41a' }}>成功：{diagnosticResults.summary.success}</Text></Card></Col>
                  <Col span={6}><Card size="small"><Text style={{ color: '#cf1322' }}>失败：{diagnosticResults.summary.failed}</Text></Card></Col>
                  <Col span={6}><Card size="small"><Text>平均延迟：{diagnosticResults.summary.avg_latency}ms</Text></Card></Col>
                </Row>
                <Table dataSource={diagnosticResults.results} columns={diagnosticColumns} rowKey="target" pagination={false} size="small" />
              </Card>
            )}
            <Space>
              <Button onClick={prevStep}>上一步</Button>
              <Button onClick={() => setCurrentStep(2)}>跳过诊断</Button>
              <Button type="primary" onClick={() => setCurrentStep(2)} disabled={!diagnosticResults}>下一步：扫描配置</Button>
            </Space>
          </Space>
        )
      case 2:
        return (
          <Form form={form} layout="vertical" onFinish={handleSubmit}>
            <Alert message={`扫描目标：${formData.target?.split('\n').filter(t=>t.trim()).length || 0} 个`} type="success" showIcon style={{ marginBottom: 16 }} />
            <Form.Item label="扫描类型" name="scan_type" rules={[{ required: true, message: '请选择扫描类型' }]}>
              <Select placeholder="请选择扫描类型">
                <Select.Option value="asset">资产发现</Select.Option>
                <Select.Option value="vuln">漏洞扫描</Select.Option>
                <Select.Option value="full">全面扫描</Select.Option>
                <Select.Option value="custom">自定义</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label="端口范围" name="port_mode" extra="选择扫描的端口范围：Top100（常用100端口）、全端口（1-65535）或常用端口">
              <Select placeholder="请选择端口范围" defaultValue="common" onChange={(v) => setPortMode(v)}>
                <Select.Option value="top100">Top100（快速发现常用端口）</Select.Option>
                <Select.Option value="full">全端口（1-65535，耗时较长）</Select.Option>
                <Select.Option value="common">常用端口（推荐）</Select.Option>
                <Select.Option value="custom">自定义端口</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label="自定义端口" name="custom_ports" extra="当端口范围选择「自定义」时填写，如：80,443,8080 或 1-1000">
              <Input placeholder="如：80,443,8080-8090" disabled={portMode !== 'custom'} />
            </Form.Item>
            <Form.Item label="AI辅助扫描" name="ai_assist" valuePropName="checked" extra="启用后，AI将实时分析扫描结果">
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item>
              <Space>
                <Button onClick={prevStep}>上一步</Button>
                <Button type="primary" htmlType="submit" loading={submitLoading}>创建任务</Button>
              </Space>
            </Form.Item>
          </Form>
        )
      default:
        return null
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">创建扫描任务</h1>
      </div>
      <Card className="content-card" bordered={false}>
        <Steps current={currentStep} items={steps} style={{ marginBottom: 24 }} />
        {renderStepContent()}
      </Card>
    </div>
  )
}

export default TaskCreate
