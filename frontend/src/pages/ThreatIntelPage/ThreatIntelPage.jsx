import { useState, useEffect } from 'react'
import { Card, Row, Col, Form, Input, Select, Button, Table, Tag, Space, Statistic, message, Spin, Typography, Tabs, Popconfirm, Empty, Badge } from 'antd'
import { SearchOutlined, SafetyOutlined, GlobalOutlined, BugOutlined, ReloadOutlined, HistoryOutlined, DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import api from '../../services/api'

const { Text } = Typography
const { Option } = Select

const QUERY_HISTORY_KEY = 'secscan_intel_query_history'
const MAX_HISTORY = 10

const ThreatIntelPage = () => {
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('query')
  const [queryType, setQueryType] = useState('ip')
  const [queryValue, setQueryValue] = useState('')
  const [intelSource, setIntelSource] = useState('crt')
  const [result, setResult] = useState({ total: 0, high_risk: 0, quota_remain: 0, assets: [], iocs: [] })
  const [sourceStatus, setSourceStatus] = useState({})
  const [queryHistory, setQueryHistory] = useState([])

  useEffect(() => {
    try {
      const saved = localStorage.getItem(QUERY_HISTORY_KEY)
      if (saved) setQueryHistory(JSON.parse(saved))
    } catch {}
  }, [])

  const saveToHistory = (record) => {
    const item = {
      id: Date.now(),
      time: new Date().toLocaleString('zh-CN'),
      queryType: record.queryType,
      queryValue: record.queryValue,
      intelSource: record.intelSource,
      sourceName: sources.find(s => s.id === record.intelSource)?.name || record.intelSource,
      result: record.result || { total: 0, high_risk: 0, quota_remain: 0, assets: [], iocs: [] },
    }
    const updated = [item, ...queryHistory.filter(h => !(h.queryType === item.queryType && h.queryValue === item.queryValue))].slice(0, MAX_HISTORY)
    setQueryHistory(updated)
    localStorage.setItem(QUERY_HISTORY_KEY, JSON.stringify(updated))
  }

  const deleteHistory = (id) => {
    const updated = queryHistory.filter(h => h.id !== id)
    setQueryHistory(updated)
    localStorage.setItem(QUERY_HISTORY_KEY, JSON.stringify(updated))
  }

  const clearHistory = () => {
    setQueryHistory([])
    localStorage.removeItem(QUERY_HISTORY_KEY)
  }

  const loadFromHistory = (record) => {
    if (!record) return
    setQueryType(record.queryType || 'ip')
    setQueryValue(record.queryValue || '')
    setIntelSource(record.intelSource || 'crt')
    setResult(record.result || { total: 0, high_risk: 0, quota_remain: 0, assets: [], iocs: [] })
    setActiveTab('query')
    message.success('已加载查询记录')
  }

  const sources = [
    { id: 'crt', name: 'CRT.sh 证书查询', type: 'subdomain', needKey: false },
    { id: 'fofa', name: 'FOFA 网络空间测绘', type: 'asset', needKey: true },
    { id: 'shodan', name: 'Shodan', type: 'asset', needKey: true },
    { id: 'zoomeye', name: 'ZoomEye 网络空间测绘', type: 'asset', needKey: true },
    { id: 'hunter', name: 'Hunter 鹰图探测', type: 'asset', needKey: true },
    { id: 'otx', name: 'AlienVault OTX', type: 'threat_intel', needKey: false },
  ]

  useEffect(() => {
    const fetchSourceStatus = async () => {
      try {
        const status = await api.getApiKeyStatus()
        setSourceStatus(status || {})
      } catch (e) {
        console.error('获取数据源状态失败:', e)
      }
    }
    fetchSourceStatus()
  }, [])

  const handleQuery = async () => {
    if (!queryValue.trim()) {
      message.warning('请输入查询内容')
      return
    }

    setLoading(true)
    try {
      const data = await api.request('/threat-intel/query', {
        method: 'POST',
        body: JSON.stringify({
          type: queryType,
          value: queryValue,
          source: intelSource,
          limit: 100,
        }),
      })

      if (data.code === 0) {
        setResult(data)
        saveToHistory({ queryType, queryValue, intelSource, result: data })
        message.success(`查询成功，发现 ${data.total} 条结果`)
      } else {
        message.error(data.message || '查询失败')
        setResult({
          code: data.code,
          total: 0,
          high_risk: 0,
          quota_remain: 0,
          assets: [],
          iocs: [],
          error: data.message
        })
      }
    } catch (error) {
      message.error('网络请求失败，请检查网络连接')
      setResult({
        code: -1,
        total: 0,
        high_risk: 0,
        quota_remain: 0,
        assets: [],
        iocs: [],
        error: error.message
      })
    } finally {
      setLoading(false)
    }
  }

  const assetColumns = [
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (t) => <Text style={{ fontFamily: 'monospace' }}>{t}</Text> },
    { title: '端口', dataIndex: 'port', key: 'port' },
    { title: '主机名', dataIndex: 'hostname', key: 'hostname' },
    { title: '域名', dataIndex: 'domain', key: 'domain' },
    { title: '服务', dataIndex: 'server', key: 'server' },
    { title: '地区', dataIndex: 'country', key: 'country' },
  ]

  const historyColumns = [
    { title: '查询时间', dataIndex: 'time', key: 'time', width: 160 },
    { title: '查询类型', dataIndex: 'queryType', key: 'queryType', render: (t) => {
      const map = { ip: 'IP查询', domain: '域名查询', keyword: '关键字', hash: '哈希值' }
      return <Tag>{map[t] || t}</Tag>
    }},
    { title: '查询内容', dataIndex: 'queryValue', key: 'queryValue', ellipsis: true, render: (t) => <Text code style={{ fontSize: 12 }}>{t}</Text> },
    { title: '情报源', dataIndex: 'sourceName', key: 'sourceName', render: (t) => <Tag color="blue">{t}</Tag> },
    { title: '查询结果', dataIndex: 'result', key: 'result', render: (r) => r?.total > 0 ? <Tag color="green">{r.total} 条</Tag> : <Tag>0 条</Tag> },
    { title: '高危资产', dataIndex: 'result', key: 'high_risk', render: (r) => r?.high_risk > 0 ? <Tag color="red">{r.high_risk}</Tag> : <Tag>0</Tag> },
    { title: '操作', key: 'action', width: 120, render: (_, r) => (
      <Space>
        <Button size="small" type="link" icon={<PlusOutlined />} onClick={() => loadFromHistory(r)}>加载</Button>
        <Popconfirm title="删除此记录？" onConfirm={() => deleteHistory(r.id)}><Button size="small" type="link" danger icon={<DeleteOutlined />}>删除</Button></Popconfirm>
      </Space>
    )},
  ]

  const tabItems = [
    {
      key: 'query',
      label: <span><SearchOutlined /> 查询结果</span>,
      children: (
        <Spin spinning={loading}>
          <Row gutter={16} style={{ marginBottom: 16 }}>
            <Col span={6}><Card><Statistic title="查询结果" value={result.total} prefix={<SearchOutlined />} /></Card></Col>
            <Col span={6}><Card><Statistic title="高危资产" value={result.high_risk} prefix={<SafetyOutlined />} valueStyle={{ color: '#ff4d4f' }} /></Card></Col>
            <Col span={6}><Card><Statistic title="IOC情报" value={result.iocs?.length || 0} prefix={<BugOutlined />} /></Card></Col>
            <Col span={6}><Card><Statistic title="剩余额度" value={result.quota_remain} suffix="次" valueStyle={{ color: '#52c41a' }} /></Card></Col>
          </Row>
          {result.assets && result.assets.length > 0 && (
            <Card title="资产发现" style={{ marginBottom: 16 }}>
              <Table columns={assetColumns} dataSource={result.assets} rowKey="ip" pagination={{ pageSize: 10 }} size="small" />
            </Card>
          )}
          {result.iocs && result.iocs.length > 0 && (
            <Card title="威胁指标 (IOC)">
              <Table
                dataSource={result.iocs}
                rowKey="value"
                pagination={{ pageSize: 10 }}
                size="small"
                columns={[
                  { title: '类型', dataIndex: 'type', key: 'type', render: (type) => <Tag color="blue">{type}</Tag> },
                  { title: '值', dataIndex: 'value', key: 'value' },
                  { title: '来源', dataIndex: 'source', key: 'source' },
                  { title: '置信度', dataIndex: 'confidence', key: 'confidence' },
                  { title: '标签', dataIndex: 'tags', key: 'tags', render: (tags) => tags?.map((t) => <Tag key={t}>{t}</Tag>) },
                ]}
              />
            </Card>
          )}
        </Spin>
      )
    },
    {
      key: 'history',
      label: <span><HistoryOutlined /> 查询记录 <Badge count={queryHistory.length} style={{ backgroundColor: '#fa8c16' }} /></span>,
      children: (
        <Card bordered={false}>
          <Space style={{ marginBottom: 12 }}>
            <Text type="secondary">最近 {queryHistory.length} 次查询记录，最多保存 {MAX_HISTORY} 次</Text>
            {queryHistory.length > 0 && (
              <Popconfirm title="清空所有查询记录？" onConfirm={clearHistory}>
                <Button size="small" danger icon={<DeleteOutlined />}>清空</Button>
              </Popconfirm>
            )}
          </Space>
          {queryHistory.length === 0 ? (
            <Empty description="暂无查询记录" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <Table dataSource={queryHistory} columns={historyColumns} rowKey="id" size="small" pagination={{ pageSize: 10, size: 'small' }} />
          )}
        </Card>
      )
    }
  ]

  return (
    <div style={{ padding: 24 }}>
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Space>
            <GlobalOutlined style={{ fontSize: 24, color: '#1890ff' }} />
            <h2 style={{ margin: 0 }}>资产测绘</h2>
          </Space>
        </div>

        <Card>
          <Row gutter={16}>
            <Col span={4}>
              <Form.Item label="查询类型">
                <Select value={queryType} onChange={setQueryType}>
                  <Option value="ip">IP查询</Option>
                  <Option value="domain">域名查询</Option>
                  <Option value="keyword">关键字</Option>
                  <Option value="hash">哈希值</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={10}>
              <Form.Item label="查询内容">
                <Input
                  placeholder={
                    intelSource === 'fofa' ? '请输入 FOFA 查询语法,例如: country="CN" && port="443"' :
                    queryType === 'ip' ? '例如: 8.8.8.8' :
                    queryType === 'domain' ? '例如: example.com' :
                    queryType === 'keyword' ? '例如: ThinkPHP rce' :
                    '例如: d41d8cd98f00b204e9800998ecf8427e'
                  }
                  value={queryValue}
                  onChange={(e) => setQueryValue(e.target.value)}
                  onPressEnter={handleQuery}
                />
              </Form.Item>
            </Col>
            <Col span={4}>
              <Form.Item label="情报源">
                <Select value={intelSource} onChange={setIntelSource}>
                  {sources.map((s) => <Option key={s.id} value={s.id}>{s.name}</Option>)}
                </Select>
              </Form.Item>
            </Col>
            <Col span={4}>
              <Form.Item label=" ">
                <Button type="primary" icon={<SearchOutlined />} onClick={handleQuery} loading={loading} block>查询</Button>
              </Form.Item>
            </Col>
          </Row>
        </Card>

        <Row gutter={16}>
          {sources.map((source) => {
            const isConfigured = !source.needKey || (sourceStatus[`${source.id}_api_key`]?.configured || sourceStatus[`${source.id}_email`]?.configured)
            return (
              <Col span={6} key={source.id}>
                <Card size="small">
                  <Space>
                    <Tag color={isConfigured ? 'green' : 'red'}>{isConfigured ? '已配置' : '未配置'}</Tag>
                    <span>{source.name}</span>
                  </Space>
                </Card>
              </Col>
            )
          })}
        </Row>

        <Tabs activeKey={activeTab} onChange={setActiveTab} items={tabItems} />
      </Space>
    </div>
  )
}

export default ThreatIntelPage
