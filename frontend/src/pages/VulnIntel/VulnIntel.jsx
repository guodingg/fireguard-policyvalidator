import { useState, useEffect } from 'react'
import { Card, Table, Tag, Select, Space, Button, Row, Col, Statistic, Typography, Tooltip, Badge } from 'antd'
import { AlertOutlined, SyncOutlined, BugOutlined, GlobalOutlined, SafetyOutlined } from '@ant-design/icons'
import api from '../../services/api'

const { Title, Text } = Typography

const VulnIntel = () => {
  const [vulns, setVulns] = useState([])
  const [sources, setSources] = useState([])
  const [loading, setLoading] = useState(false)
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, poc: 0, rce: 0 })
  
  // 筛选条件
  const [severity, setSeverity] = useState('high')
  const [source, setSource] = useState(null)
  
  const fetchVulns = async () => {
    setLoading(true)
    try {
      const params = { limit: 100 }
      if (severity) params.severity = severity
      if (source) params.source = source
      
      const res = await api.getVulnIntel(params)
      setVulns(res.items || [])
      setSources(res.sources || [])
      
      // 计算统计（使用API返回的总数）
      const items = res.items || []
      const allStats = res.stats || {}
      setStats({
        total: res.total || items.length,
        critical: allStats.by_severity?.critical || items.filter(i => i.severity === 'critical').length,
        high: allStats.by_severity?.high || items.filter(i => i.severity === 'high').length,
        poc: items.filter(i => i.is_poc_public).length,
        rce: items.filter(i => i.is_rce).length
      })
    } catch (err) {
      console.error('获取漏洞情报失败:', err)
    }
    setLoading(false)
  }
  
  useEffect(() => {
    fetchVulns()
  }, [severity, source])
  
  const severityColor = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'green'
  }
  
  const severityLabel = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危'
  }
  
  const sourceLabel = {
    nvd: 'NVD漏洞库',
    oscs: 'OSCS情报',
    cisa: 'CISA KEV',
    avd: '阿里云'
  }
  
  const columns = [
    {
      title: '严重性',
      dataIndex: 'severity',
      width: 100,
      render: (sev) => (
        <Tag color={severityColor[sev] || 'default'}>
          {severityLabel[sev] || sev}
        </Tag>
      )
    },
    {
      title: 'CVE编号',
      dataIndex: 'cve_id',
      width: 160,
      render: (cve_id) => (
        <Text strong style={{ fontFamily: 'monospace' }}>
          {cve_id && cve_id !== '-' ? cve_id : '-'}
        </Text>
      )
    },
    {
      title: '漏洞名称',
      dataIndex: 'vulnerability_name',
      ellipsis: true,
      render: (name, row) => (
        <Space direction="vertical" size={0}>
          <Text style={{ maxWidth: 400 }} ellipsis={{ tooltip: name }}>
            {name}
          </Text>
          <Space size={4} style={{ marginTop: 4 }}>
            {row.is_rce && <Tag color="red" icon={<BugOutlined />}>RCE</Tag>}
            {row.is_poc_public && <Tag color="blue">POC公开</Tag>}
            {row.is_known_exploited && <Tag color="purple">已被利用</Tag>}
          </Space>
        </Space>
      )
    },
    {
      title: '影响产品',
      dataIndex: 'product',
      width: 120,
      ellipsis: true
    },
    {
      title: '来源',
      dataIndex: 'source',
      width: 120,
      render: (src) => {
        const srcMap = {
          'cisa_kev': 'CISA KEV',
          'github_advisory': 'GitHub Advisory',
          'nvd_rss': 'NVD',
          'chaitin': '长亭漏洞库',
          'oscs': 'OSCS',
          'avd': '阿里云AVD'
        }
        return srcMap[src] || src
      }
    },
    {
      title: '发布日期',
      dataIndex: 'published_date',
      width: 120,
      render: (date) => date || '-'
    },
    {
      title: '参考链接',
      dataIndex: 'references',
      width: 100,
      render: (_, row) => (
        <Tooltip title="查看漏洞详情">
          <Button 
            type="link" 
            size="small"
            icon={<GlobalOutlined />}
            href={row.references?.[0]}
            target="_blank"
          />
        </Tooltip>
      )
    }
  ]
  
  return (
    <div style={{ padding: 24 }}>
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        {/* 标题 */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Space>
            <AlertOutlined style={{ fontSize: 24, color: '#1890ff' }} />
            <Title level={4} style={{ margin: 0 }}>漏洞情报中心</Title>
          </Space>
          <Button 
            icon={<SyncOutlined spin={loading} />} 
            onClick={fetchVulns}
            loading={loading}
          >
            刷新
          </Button>
        </div>
        
        {/* 统计卡片 */}
        <Row gutter={16}>
          <Col span={4}>
            <Card size="small">
              <Statistic 
                title="漏洞总数" 
                value={stats.total} 
                valueStyle={{ color: '#1890ff' }}
                prefix={<SafetyOutlined />}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic 
                title="严重漏洞" 
                value={stats.critical} 
                valueStyle={{ color: '#cf1322' }}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic 
                title="高危漏洞" 
                value={stats.high} 
                valueStyle={{ color: '#fa8c16' }}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic 
                title="RCE漏洞" 
                value={stats.rce} 
                valueStyle={{ color: '#cf1322' }}
                prefix={<BugOutlined />}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic 
                title="POC公开" 
                value={stats.poc} 
                valueStyle={{ color: '#1890ff' }}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic 
                title="情报来源" 
                value={sources.length} 
              />
            </Card>
          </Col>
        </Row>
        
        {/* 筛选 */}
        <Card size="small">
          <Space size="large">
            <Space>
              <Text>最低严重性：</Text>
              <Select 
                value={severity} 
                onChange={setSeverity}
                style={{ width: 100 }}
              >
                <Select.Option value="critical">严重</Select.Option>
                <Select.Option value="high">高危</Select.Option>
                <Select.Option value="medium">中危</Select.Option>
                <Select.Option value="low">低危</Select.Option>
              </Select>
            </Space>
            <Space>
              <Text>来源：</Text>
              <Select 
                value={source} 
                onChange={setSource}
                allowClear
                placeholder="全部来源"
                style={{ width: 120 }}
              >
                {sources.map(s => (
                  <Select.Option key={s} value={s}>{sourceLabel[s] || s}</Select.Option>
                ))}
              </Select>
            </Space>
          </Space>
        </Card>
        
        {/* 漏洞列表 */}
        <Card>
          <Table
            columns={columns}
            dataSource={vulns}
            rowKey={(row) => row.cve || row.hash_id}
            loading={loading}
            pagination={{ 
              pageSize: 20,
              showSizeChanger: true,
              showTotal: (total) => `共 ${total} 条漏洞情报`
            }}
            size="middle"
          />
        </Card>
        
        {/* 来源说明 */}
        <Card size="small" title="情报来源说明">
          <Row gutter={16}>
            <Col span={6}>
              <Text strong>NVD漏洞库</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>美国国家漏洞数据库</Text>
            </Col>
            <Col span={6}>
              <Text strong>OSCS开源安全情报</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>开源安全情报平台</Text>
            </Col>
            <Col span={6}>
              <Text strong>CISA KEV</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>已知被利用漏洞目录</Text>
            </Col>
            <Col span={6}>
              <Text strong>阿里云漏洞库</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>阿里云高危漏洞</Text>
            </Col>
          </Row>
        </Card>
      </Space>
    </div>
  )
}

export default VulnIntel
