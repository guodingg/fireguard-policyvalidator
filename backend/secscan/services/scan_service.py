"""
扫描服务
"""

import asyncio
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime

from secscan.database import async_session_maker
from secscan.models.scan import ScanTask, TaskType, TaskStatus
from secscan.models.asset import Asset, AssetStatus
from secscan.models.vuln import Vulnerability, Severity, VulnStatus
from secscan.scanner.port_scanner import PortScanner
from secscan.scanner.web_scanner import WebScanner
from secscan.scanner.base import ScanProgress, HostResult

class ScanService:
    """扫描服务"""
    
    _running_tasks: Dict[int, asyncio.Task] = {}
    
    @classmethod
    async def start_scan(
        cls,
        task_id: int,
        progress_callback: Optional[Callable] = None
    ):
        """启动扫描任务"""
        if task_id in cls._running_tasks:
            raise ValueError(f"任务 {task_id} 已在运行中")
        
        task = asyncio.create_task(cls._run_scan(task_id, progress_callback))
        cls._running_tasks[task_id] = task
        
        try:
            await task
        finally:
            cls._running_tasks.pop(task_id, None)
    
    @classmethod
    async def stop_scan(cls, task_id: int):
        """停止扫描任务"""
        if task_id in cls._running_tasks:
            cls._running_tasks[task_id].cancel()
            raise ValueError(f"任务 {task_id} 已停止")
    
    @classmethod
    async def _run_scan(
        cls,
        task_id: int,
        progress_callback: Optional[Callable] = None
    ):
        """执行扫描"""
        async with async_session_maker() as db:
            # 获取任务
            from sqlalchemy import select
            result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
            task = result.scalar_one_or_none()
            
            if not task:
                raise ValueError(f"任务 {task_id} 不存在")
            
            # 更新状态
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()
            await db.commit()
            
            # 解析目标
            targets = [t.strip() for t in task.target.split("\n") if t.strip()]
            task.total_hosts = len(targets)
            await db.commit()
            
            # 选择扫描器
            if task.scan_type == TaskType.ASSET:
                scanner = PortScanner(task_id, task.options)
            elif task.scan_type == TaskType.VULN:
                scanner = WebScanner(task_id, task.options)
            else:  # FULL
                scanner = PortScanner(task_id, task.options)
            
            scanner.set_progress_callback(progress_callback or cls._default_progress)
            
            # 执行扫描
            async for host_result in scanner.scan(targets):
                # 保存资产
                asset = Asset(
                    task_id=task_id,
                    ip=host_result.ip,
                    port=host_result.port,
                    protocol=host_result.protocol,
                    service=host_result.service,
                    product=host_result.product,
                    version=host_result.version,
                    banner=host_result.banner,
                    status=AssetStatus.ALIVE
                )
                db.add(asset)
                await db.flush()
                
                # 保存漏洞
                for vuln_data in host_result.vulns:
                    vuln = Vulnerability(
                        task_id=task_id,
                        asset_id=asset.id,
                        name=vuln_data.get("name", "未知漏洞"),
                        severity=Severity.MEDIUM,
                        description=vuln_data.get("payload", ""),
                        status=VulnStatus.UNVERIFIED
                    )
                    db.add(vuln)
                    task.found_vulns += 1
                
                task.scanned_hosts += 1
                await db.commit()
            
            # 完成任务
            task.status = TaskStatus.COMPLETED
            task.finished_at = datetime.utcnow()
            task.progress = 100
            await db.commit()
    
    @classmethod
    async def _default_progress(cls, progress: ScanProgress):
        """默认进度回调"""
        print(f"[{progress.task_id}] {progress.current}/{progress.total} - {progress.message}")
    
    @classmethod
    def get_task_stats(cls, task_id: int) -> Dict[str, Any]:
        """获取任务统计"""
        # 同步方法，返回基础统计
        return {
            "task_id": task_id,
            "is_running": task_id in cls._running_tasks
        }
