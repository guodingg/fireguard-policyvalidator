FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制后端代码
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# 创建数据目录
RUN mkdir -p /app/data

# 暴露端口
EXPOSE 8000

# 初始化数据库
RUN python scripts/init_db.py

# 启动命令
CMD ["uvicorn", "secscan.main:app", "--host", "0.0.0.0", "--port", "8000"]
