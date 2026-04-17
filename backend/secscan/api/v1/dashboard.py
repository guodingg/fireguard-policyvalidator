"""
仪表盘API
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.scan import ScanTask, TaskStatus
from secscan.models.asset import Asset, AssetStatus
from secscan.models.vuln import Vulnerability, Severity
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/dashboard", tags=["仪表盘"])

@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取仪表盘统计"""
    
    # 任务统计
    total_tasks_result = await db.execute(select(func.count(ScanTask.id)))
    total_tasks = total_tasks_result.scalar()
    
    running_tasks_result = await db.execute(
        select(func.count(ScanTask.id)).where(ScanTask.status == TaskStatus.RUNNING)
    )
    running_tasks = running_tasks_result.scalar()
    
    completed_tasks_result = await db.execute(
        select(func.count(ScanTask.id)).where(ScanTask.status == TaskStatus.COMPLETED)
    )
    completed_tasks = completed_tasks_result.scalar()
    
    # 资产统计
    total_assets_result = await db.execute(select(func.count(Asset.id)))
    total_assets = total_assets_result.scalar()
    
    alive_assets_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.status == AssetStatus.ALIVE)
    )
    alive_assets = alive_assets_result.scalar()
    
    # 漏洞统计
    total_vulns_result = await db.execute(select(func.count(Vulnerability.id)))
    total_vulns = total_vulns_result.scalar()
    
    critical_vulns_result = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == Severity.CRITICAL)
    )
    critical_vulns = critical_vulns_result.scalar()
    
    high_vulns_result = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == Severity.HIGH)
    )
    high_vulns = high_vulns_result.scalar()
    
    # 最近7天的任务趋势
    week_ago = datetime.utcnow() - timedelta(days=7)
    trend_result = await db.execute(
        select(
            func.date(ScanTask.created_at).label('date'),
            func.count(ScanTask.id).label('count')
        )
        .where(ScanTask.created_at >= week_ago)
        .group_by(func.date(ScanTask.created_at))
        .order_by(func.date(ScanTask.created_at))
    )
    task_trend = [{"date": str(r[0]), "count": r[1]} for r in trend_result.all()]
    
    # 漏洞严重性分布
    severity_dist_result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
    )
    severity_dist = [{"severity": r[0].value if hasattr(r[0], 'value') else r[0], "count": r[1]} for r in severity_dist_result.all()]
    
    # 最近任务
    recent_tasks_result = await db.execute(
        select(ScanTask)
        .order_by(ScanTask.created_at.desc())
        .limit(5)
    )
    recent_tasks = []
    for task in recent_tasks_result.scalars().all():
        recent_tasks.append({
            "id": task.id,
            "name": task.name,
            "status": task.status.value if hasattr(task.status, 'value') else task.status,
            "progress": task.progress,
            "created_at": task.created_at.isoformat() if task.created_at else None
        })
    
    return {
        "tasks": {
            "total": total_tasks,
            "running": running_tasks,
            "completed": completed_tasks
        },
        "assets": {
            "total": total_assets,
            "alive": alive_assets
        },
        "vulnerabilities": {
            "total": total_vulns,
            "critical": critical_vulns,
            "high": high_vulns
        },
        "task_trend": task_trend,
        "severity_distribution": severity_dist,
        "recent_tasks": recent_tasks
    }

@router.get("/trend")
async def get_scan_trend(
    days: int = 7,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取扫描趋势"""
    start_date = datetime.utcnow() - timedelta(days=days)
    
    result = await db.execute(
        select(
            func.date(ScanTask.created_at).label('date'),
            func.count(ScanTask.id).label('tasks'),
            func.sum(ScanTask.found_vulns).label('vulns')
        )
        .where(ScanTask.created_at >= start_date)
        .group_by(func.date(ScanTask.created_at))
        .order_by(func.date(ScanTask.created_at))
    )
    
    return [
        {"date": str(r[0]), "tasks": r[1] or 0, "vulns": r[2] or 0}
        for r in result.all()
    ]
