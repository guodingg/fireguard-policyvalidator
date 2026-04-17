"""
扫描任务模型
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, JSON, DateTime, ForeignKey, Enum
from secscan.database import Base
import enum

class TaskType(str, enum.Enum):
    ASSET = "asset"           # 资产发现
    VULN = "vuln"            # 漏洞扫描
    FULL = "full"            # 全面扫描
    CUSTOM = "custom"         # 自定义

class TaskStatus(str, enum.Enum):
    PENDING = "pending"       # 等待中
    RUNNING = "running"       # 运行中
    PAUSED = "paused"         # 已暂停
    COMPLETED = "completed"  # 已完成
    FAILED = "failed"         # 失败

class ScanTask(Base):
    """扫描任务表"""
    __tablename__ = "scan_tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(256), nullable=False)
    target = Column(Text, nullable=False)  # 支持多目标: IP/CIDR/域名
    scan_type = Column(Enum(TaskType), nullable=False)
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    options = Column(JSON, default={})  # 扫描选项
    
    # 进度
    progress = Column(Integer, default=0)
    total_hosts = Column(Integer, default=0)
    scanned_hosts = Column(Integer, default=0)
    found_vulns = Column(Integer, default=0)
    
    # 时间
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 错误信息
    error_message = Column(Text)
    
    def __repr__(self):
        return f"<ScanTask {self.name}>"
