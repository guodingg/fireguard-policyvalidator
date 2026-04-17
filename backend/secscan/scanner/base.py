"""
扫描器基类
"""

from abc import ABC, abstractmethod
from typing import AsyncGenerator, Dict, Any, List
from dataclasses import dataclass
import asyncio

@dataclass
class ScanProgress:
    """扫描进度"""
    task_id: int
    current: int
    total: int
    current_target: str
    message: str
    vulns_found: int = 0

@dataclass
class HostResult:
    """主机扫描结果"""
    ip: str
    port: int
    protocol: str
    service: str
    product: str = ""
    version: str = ""
    banner: str = ""
    status: str = "open"
    vulns: List[Dict] = None
    
    def __post_init__(self):
        if self.vulns is None:
            self.vulns = []

class ScannerBase(ABC):
    """扫描器基类"""
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        self.task_id = task_id
        self.options = options or {}
        self.progress_callback = None
    
    def set_progress_callback(self, callback):
        """设置进度回调"""
        self.progress_callback = callback
    
    async def report_progress(self, current: int, total: int, target: str, message: str, vulns: int = 0):
        """报告进度"""
        if self.progress_callback:
            progress = ScanProgress(
                task_id=self.task_id,
                current=current,
                total=total,
                current_target=target,
                message=message,
                vulns_found=vulns
            )
            await self.progress_callback(progress)
    
    @abstractmethod
    async def scan(self, targets: List[str]) -> AsyncGenerator[HostResult, None]:
        """
        执行扫描
        yield每个主机的结果
        """
        pass
    
    @abstractmethod
    async def validate_target(self, target: str) -> bool:
        """验证目标格式"""
        pass
    
    async def close(self):
        """清理资源"""
        pass
