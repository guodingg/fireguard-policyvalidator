import { Card, Result, Button } from 'antd'
import { useNavigate } from 'react-router-dom'

const TaskCreate = () => {
  const navigate = useNavigate()

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">创建扫描任务</h1>
      </div>
      <Card className="content-card" bordered={false}>
        <Result
          title="功能开发中"
          subTitle="扫描任务创建功能即将上线，敬请期待。"
          extra={<Button type="primary" onClick={() => navigate('/scan/tasks')}>返回列表</Button>}
        />
      </Card>
    </div>
  )
}

export default TaskCreate
