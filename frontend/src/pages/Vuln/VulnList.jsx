import { useState, useEffect } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, message, Popconfirm } from 'antd'
import { SearchOutlined, SafetyOutlined, ReloadOutlined, CheckCircleOutlined, ToolOutlined } from '@ant-design/icons'
import api from '../../services/api'

const VulnList = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [filters, setFilters] = useState({ severity: null, status: null })
  const [pagination, setPagination] = useState({ current: 1, pageSize: 10, total: 0 })

  useEffect(() => {
    loadVulns()
  }, [pagination.current, filters])

  const loadVulns = async () => {
    setLoading(true)
    try {
      const params = {
        skip: (pagination.current - 1) * pagination.pageSize,
        limit: pagination.pageSize
      }
      if (filters.severity) params.severity = filters.severity
      if (filters.status) params.status = filters.status

      const result = await api.getVulns(params)
      setData(Array.isArray(result) ? result : [])
    } catch (error) {
      message.error('加载漏洞列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async (id) => {
    try {
      await api.verifyVuln(id)
      message.success('漏洞已验证')
      loadVulns()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const handleFix = async (id) => {
    try {
      await api.fixVuln(id)
      message.success('已标记为已修复')
      loadVulns()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const handleFalsePositive = async (id) => {
    try {
      await api.markFalsePositive(id)
      message.success('已标记为误报')
      loadVulns()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const severityColor = { critical: 'red', high: 'orange', medium: 'gold', low: 'green', info: 'blue' }
  const statusColor = { verified: 'success', unverified: 'warning', fixed: 'processing', false_positive: 'default' }
  const statusText = { verified: '已验证', unverified: '待验证', fixed: '已修复', false_positive: '误报' }

  const columns = [
    { title: '漏洞名称', dataIndex: 'name', key: 'name', render: (t) => <span style={{ fontWeight: 500 }}>{t}</span> },
    { title: 'CVE编号', dataIndex: 'cve', key: 'cve', render: (t) => t || '-' },
    { 
      title: '严重性', 
      dataIndex: 'severity', 
      key: 'severity', 
      render: (s) => <Tag color={severityColor[s]}>{s?.toUpperCase()}</Tag> 
    },
    { title: '目标', dataIndex: 'target', key: 'target', ellipsis: true },
    { title: '影响产品', dataIndex: 'product', key: 'product', render: (t) => t || '-' },
    { 
      title: '状态', 
      dataIndex: 'status', 
      key: 'status', 
      render: (s) => <Tag color={statusColor[s]}>{statusText[s] || s}</Tag> 
    },
    { title: '发现时间', dataIndex: 'created_at', key: 'created_at', render: (t) => t ? new Date(t).toLocaleDateString() : '-' },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space>
          {record.status !== 'verified' && (
            <Button type="text" size="small" icon={<CheckCircleOutlined />} onClick={() => handleVerify(record.id)}>验证</Button>
          )}
          {record.status !== 'fixed' && (
            <Button type="text" size="small" icon={<ToolOutlined />} onClick={() => handleFix(record.id)}>修复</Button>
          )}
          <Popconfirm title="标记为误报?" onConfirm={() => handleFalsePositive(record.id)}>
            <Button type="text" size="small">误报</Button>
          </Popconfirm>
        </Space>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><SafetyOutlined style={{ marginRight: 8 }} />漏洞管理</h1>
        <Button icon={<ReloadOutlined />} onClick={loadVulns}>刷新</Button>
      </div>

      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索漏洞名称/CVE" prefix={<SearchOutlined />} style={{ width: 200 }} allowClear />
          <Select 
            placeholder="严重性" 
            style={{ width: 100 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, severity: v }))}
          >
            <Select.Option value="critical">严重</Select.Option>
            <Select.Option value="high">高危</Select.Option>
            <Select.Option value="medium">中危</Select.Option>
            <Select.Option value="low">低危</Select.Option>
          </Select>
          <Select 
            placeholder="状态" 
            style={{ width: 100 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, status: v }))}
          >
            <Select.Option value="verified">已验证</Select.Option>
            <Select.Option value="unverified">待验证</Select.Option>
            <Select.Option value="fixed">已修复</Select.Option>
          </Select>
        </Space>

        <Table 
          columns={columns} 
          dataSource={data} 
          rowKey="id" 
          loading={loading}
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: pagination.total,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条`
          }}
          onChange={(p) => setPagination(p)}
        />
      </Card>
    </div>
  )
}

export default VulnList
