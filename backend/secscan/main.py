"""
SecScan AI - 蚂蚁安全风险评估系统
FastAPI应用入口
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time

from secscan.config import settings
from secscan.database import init_db
from secscan.api.v1 import (
    auth_router, users_router, scan_router,
    assets_router, vulns_router, pocs_router,
    reports_router, logs_router, ai_router,
    dashboard_router
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期"""
    # 启动时
    print(f"\n{'='*50}")
    print(f"  {settings.APP_NAME}")
    print(f"  {settings.APP_NAME_EN} v{settings.VERSION}")
    print(f"  {settings.COPYRIGHT}")
    print(f"{'='*50}\n")
    
    # 初始化数据库
    await init_db()
    
    yield
    
    # 关闭时
    print("\n正在关闭服务...")

# 创建应用
app = FastAPI(
    title=settings.APP_NAME,
    description="蚂蚁安全风险评估系统 API",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 请求日志中间件
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = int((time.time() - start_time) * 1000)
    
    # 跳过健康检查的日志
    if request.url.path != "/health":
        print(f"{request.method} {request.url.path} - {response.status_code} ({duration}ms)")
    
    return response

# 注册路由
app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(scan_router, prefix="/api/v1")
app.include_router(assets_router, prefix="/api/v1")
app.include_router(vulns_router, prefix="/api/v1")
app.include_router(pocs_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(ai_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")

@app.get("/")
async def root():
    """根路径"""
    return {
        "name": settings.APP_NAME,
        "version": settings.VERSION,
        "docs": "/docs"
    }

@app.get("/health")
async def health():
    """健康检查"""
    return {"status": "healthy"}

# 全局异常处理
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "detail": "服务器内部错误",
            "message": str(exc) if settings.DEBUG else "请联系管理员"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "secscan.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
