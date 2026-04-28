# 蚂蚁安全风险评估系统 (ANTsafe / FireGuard)

一款具备 AI 能力的综合性网络安全评估平台，融合资产发现、漏洞扫描、威胁情报分析与自动化渗透测试。

**GitHub 仓库：** https://github.com/guodingg/ANTsafe-FireGuard/

---

## 系统功能

| 模块 | 说明 |
|------|------|
| 首页/数据大屏 | 系统态势总览，快速扫描入口 |
| 扫描任务 | 创建、管理扫描任务，支持多种扫描类型 |
| 资产管理 | 主机、端口、服务、产品识别 |
| 漏洞管理 | 漏洞列表、验证、DNSlog 盲打查询 |
| 资产过滤 | 域名白名单、泛解析去重、内网地址过滤 |
| POC管理 | 内置 9万+ POC，支持自定义导入和 AI 生成 |
| 报告管理 | 报告生成与导出 |
| 日志审计 | 完整的操作审计 |
| AI助手 | Kimi/MiniMax 大模型辅助漏洞分析和扫描策略 |
| 系统设置 | AI配置、规则更新、安全设置 |

---

## 技术栈

**前端：** React 18 + Vite 5 + Ant Design 5 + ECharts + Zustand  
**后端：** Python 3.11 + FastAPI + SQLite + Redis  
**漏洞引擎：** Nuclei + Xray

---

## 演示截图

### 首页
!([首页演示截图](https://github.com/guodingg/ANTsafe-FireGuard/blob/main/iShot_2026-04-28_10.37.15.png))

---

## 快速部署（Docker 一键启动）

### 方式一：Docker Compose 启动（推荐）


```bash
# 1. 克隆仓库
git clone https://github.com/guodingg/fireguard-policyvalidator.git
cd fireguard-policyvalidator

# 2. 构建前端（在 frontend 目录执行）
cd frontend
npm install
npm run build
cd ..

# 3. 启动所有服务
docker-compose up -d
```

启动后访问：**http://your-ip:80**

默认管理员账号：`admin` / `admin123`

---

### 方式二：手动构建前端后启动

```bash
# 前端构建
cd frontend
npm install
npm run build

# 返回项目根目录，启动后端
cd ..
docker build -t secscan-backend .

# 启动前端（使用 nginx 直接托管构建产物）
docker run -d \
  --name secscan-frontend \
  -p 80:80 \
  -v $(pwd)/frontend/dist:/usr/share/nginx/html \
  nginx:alpine
```

---

## 详细部署教程

### 环境要求

| 项目 | 最低要求 |
|------|----------|
| CPU | 2 核 |
| 内存 | 4 GB |
| 磁盘 | 10 GB |
| Docker | 20.10+ |
| Docker Compose | 2.0+ |

### 第一步：服务器环境准备

```bash
# 安装 Docker（若未安装）
curl -fsSL https://get.docker.com | sh

# 安装 Docker Compose
curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# 启动 Docker
systemctl start docker
systemctl enable docker
```

### 第二步：下载项目

```bash
git clone https://github.com/guodingg/fireguard-policyvalidator.git
cd fireguard-policyvalidator
```

### 第三步：配置（可选）

环境变量文件 `.env`（可选，不填则使用默认值）：

```bash
# 复制示例配置
cp .env.example .env  # 如有此文件

# 编辑配置
nano .env

# 主要配置项：
AI_API_KEY=your-kimi-or-minimax-api-key   # AI 功能需要
SECRET_KEY=your-secret-key-change-me       # JWT 密钥，请修改
DATABASE_URL=sqlite+aiosqlite:///app/data/secscan.db
```

### 第四步：构建并启动

```bash
# 构建并启动所有容器
docker-compose up -d --build

# 查看容器状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

### 第五步：访问系统

| 服务 | 地址 |
|------|------|
| 前端（Web界面） | http://服务器IP:80 |
| 后端API | http://服务器IP:8000 |
| API文档 | http://服务器IP:8000/docs |

### 停止服务

```bash
docker-compose down
```

### 重启服务

```bash
docker-compose restart
```

---

## 前端开发模式（无需 Docker）

```bash
cd frontend
npm install
npm run dev
# 访问 http://localhost:5173
```

> 开发模式下前端直接连接 http://localhost:8000 的后端 API。

---

## 后端开发模式（本地运行）

```bash
cd backend

# 安装依赖
pip install -r requirements.txt

# 初始化数据库（首次运行自动创建）
python scripts/init_db.py

# 启动后端服务
uvicorn secscan.main:app --host 0.0.0.0 --port 8000 --reload
```

> 后端需要先启动才有数据。

---

## 数据目录说明

```
backend/data/
├── secscan.db          # 主数据库（内置9万+POC、5千+Payload、1700+漏洞情报）
├── nuclei-templates/    # Nuclei 漏洞模板（可选，需单独下载）
└── xray-pocs/          # Xray POC 模板（可选，需单独下载）
```

---

## 内置数据

| 数据类型 | 数量 | 说明 |
|----------|------|------|
| POC | 94,832 | 漏洞验证代码 |
| Payload | 5,093 | 测试载荷 |
| 漏洞情报 | 1,792 | 已知漏洞信息 |
| 系统用户 | 1 | 管理员账户 |

**默认管理员登录：**  
- 用户名：`admin`  
- 密码：`admin123`  
> ⚠️ 生产环境请立即修改默认密码！

---

## AI 功能配置

系统支持 Kimi 和 MiniMax 大模型，需要配置 API Key：

1. 登录系统 → 系统设置 → AI 配置
2. 选择 AI 提供商（Kimi / MiniMax）
3. 填入 API Key
4. 保存并测试连接

---

## 目录结构

```
fireguard-policyvalidator/
├── frontend/                  # 前端源码（React + Vite）
│   ├── src/
│   │   ├── pages/            # 各功能页面
│   │   ├── services/         # API 调用
│   │   ├── store/             # 状态管理
│   │   └── layouts/           # 布局组件
│   ├── dist/                  # 前端构建产物（nginx 托管）
│   └── package.json
├── backend/                   # 后端源码（FastAPI）
│   ├── secscan/
│   │   ├── api/v1/           # API 路由
│   │   ├── ai/               # AI 模块
│   │   └── main.py           # 应用入口
│   ├── data/
│   │   └── secscan.db        # 内置数据库
│   ├── scripts/              # 工具脚本
│   └── requirements.txt
├── docker-compose.yml         # Docker Compose 配置
├── Dockerfile                # 后端镜像构建文件
├── nginx.conf                # Nginx 配置
├── README.md
└── SPEC.md
```

---

## 常见问题

### Q: 启动后前端无法访问？
```bash
# 检查 nginx 容器是否正常
docker logs secscan-frontend

# 检查端口是否被占用
netstat -tlnp | grep :80
```

### Q: 后端 API 无法访问？
```bash
# 检查后端容器是否正常
docker logs secscan-backend

# 查看后端日志
docker-compose logs backend
```

### Q: 如何修改数据库？
```bash
# 进入后端容器
docker exec -it secscan-backend /bin/bash

# 使用 sqlite3
sqlite3 /app/data/secscan.db
```

### Q: 如何更新 Nuclei 模板？
```bash
# 进入后端容器
docker exec -it secscan-backend /bin/bash

# 更新 nuclei-templates
cd /app/data/nuclei-templates && git pull
```

### Q: 前端修改后如何重新构建？
```bash
cd frontend
npm install
npm run build
# 重新启动前端容器
docker-compose restart frontend
```

---

## 版权信息

© 蚂蚁安全 www.mayisafe.cn 版权所有
