"""
扫描任务执行器
"""

import asyncio
from typing import Dict, Any, Optional, Callable
from datetime import datetime

from secscan.database import async_session_maker
from secscan.models.scan import ScanTask, TaskType, TaskStatus
from secscan.models.asset import Asset, AssetStatus
from secscan.models.vuln import Vulnerability, Severity, VulnStatus
from secscan.scanner.port_scanner import PortScanner
from secscan.scanner.web_scanner import WebScanner
from secscan.scanner.base import ScanProgress, HostResult

class ScanExecutor:
    """扫描任务执行器"""
    
    _running_tasks: Dict[int, asyncio.Task] = {}
    
    @classmethod
    async def execute(
        cls,
        task_id: int,
        progress_callback: Optional[Callable] = None
    ):
        """执行扫描任务"""
        if task_id in cls._running_tasks:
            raise ValueError(f"任务 {task_id} 已在运行中")
        
        task = asyncio.create_task(
            cls._run_scan(task_id, progress_callback)
        )
        cls._running_tasks[task_id] = task
        
        try:
            await task
        finally:
            cls._running_tasks.pop(task_id, None)
    
    @classmethod
    async def stop(cls, task_id: int):
        """停止扫描任务"""
        if task_id in cls._running_tasks:
            cls._running_tasks[task_id].cancel()
            cls._running_tasks.pop(task_id, None)
            return True
        return False
    
    @classmethod
    async def is_running(cls, task_id: int) -> bool:
        """检查任务是否在运行"""
        return task_id in cls._running_tasks
    
    @classmethod
    async def _run_scan(
        cls,
        task_id: int,
        progress_callback: Optional[Callable] = None
    ):
        """执行扫描"""
        async with async_session_maker() as db:
            from sqlalchemy import select
            
            # 获取任务
            result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
            task = result.scalar_one_or_none()
            
            if not task:
                print(f"[任务{task_id}] 任务不存在")
                return
            
            # 更新状态为运行中
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()
            await db.commit()
            
            # 解析目标
            targets = [t.strip() for t in task.target.split("\n") if t.strip()]
            task.total_hosts = len(targets)
            task.progress = 0
            await db.commit()
            
            print(f"[任务{task_id}] 开始扫描，目标: {len(targets)}个")
            
            try:
                # 选择扫描器
                if task.scan_type == TaskType.ASSET:
                    scanner = PortScanner(task_id, task.options or {})
                elif task.scan_type == TaskType.VULN:
                    scanner = WebScanner(task_id, task.options or {})
                else:  # FULL - 同时扫描端口和Web漏洞
                    scanner = PortScanner(task_id, task.options or {})
                
                # 设置进度回调
                if progress_callback:
                    scanner.set_progress_callback(progress_callback)
                
                # 执行扫描
                scanned = 0
                for host_result in scanner.scan(targets):
                    scanned += 1
                    
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
                        severity = cls._map_severity(vuln_data.get("severity", "medium"))
                        vuln = Vulnerability(
                            task_id=task_id,
                            asset_id=asset.id,
                            name=vuln_data.get("name", "未知漏洞"),
                            severity=severity,
                            description=vuln_data.get("description", ""),
                            payload=vuln_data.get("payload", ""),
                            status=VulnStatus.UNVERIFIED
                        )
                        db.add(vuln)
                        task.found_vulns += 1
                    
                    task.scanned_hosts = scanned
                    task.progress = int(scanned / len(targets) * 100)
                    await db.commit()
                
                # 完成任务
                task.status = TaskStatus.COMPLETED
                task.finished_at = datetime.utcnow()
                task.progress = 100
                await db.commit()
                
                print(f"[任务{task_id}] 扫描完成，发现{task.found_vulns}个漏洞")
                
            except asyncio.CancelledError:
                # 任务被取消
                task.status = TaskStatus.PAUSED
                task.finished_at = datetime.utcnow()
                await db.commit()
                print(f"[任务{task_id}] 扫描已暂停")
                
            except Exception as e:
                # 扫描出错
                task.status = TaskStatus.FAILED
                task.finished_at = datetime.utcnow()
                task.error_message = str(e)
                await db.commit()
                print(f"[任务{task_id}] 扫描失败: {e}")
            
            finally:
                await scanner.close()
    
    @classmethod
    def _map_severity(cls, severity: str) -> Severity:
        """映射严重性等级"""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO
        }
        return mapping.get(severity.lower(), Severity.MEDIUM)
