"""
扫描任务API
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List
from datetime import datetime

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.scan import ScanTask, TaskType, TaskStatus
from secscan.schemas.scan import ScanTaskCreate, ScanTaskUpdate, ScanTaskInDB
from secscan.services.scan_executor import ScanExecutor
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/scan/tasks", tags=["扫描任务"])

async def scan_progress_callback(progress):
    """扫描进度回调"""
    print(f"[进度] {progress.current}/{progress.total} - {progress.message}")

@router.get("/", response_model=List[ScanTaskInDB])
async def list_tasks(
    skip: int = 0,
    limit: int = 100,
    status_filter: TaskStatus = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """任务列表"""
    query = select(ScanTask).order_by(ScanTask.created_at.desc())
    
    if status_filter:
        query = query.where(ScanTask.status == status_filter)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    tasks = result.scalars().all()
    
    return tasks

@router.post("/", response_model=ScanTaskInDB, status_code=status.HTTP_201_CREATED)
async def create_task(
    task_data: ScanTaskCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """创建扫描任务"""
    task = ScanTask(
        user_id=current_user.id,
        name=task_data.name,
        target=task_data.target,
        scan_type=task_data.scan_type,
        options=task_data.options,
        status=TaskStatus.PENDING
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    
    return task

@router.get("/{task_id}", response_model=ScanTaskInDB)
async def get_task(
    task_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取任务详情"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    return task

@router.put("/{task_id}", response_model=ScanTaskInDB)
async def update_task(
    task_id: int,
    task_data: ScanTaskUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """更新任务"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    # 检查权限
    if task.user_id != current_user.id and current_user.role.value not in ["admin", "operator"]:
        raise HTTPException(status_code=403, detail="权限不足")
    
    update_data = task_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(task, field, value)
    
    await db.commit()
    await db.refresh(task)
    
    return task

@router.post("/{task_id}/start")
async def start_task(
    task_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """开始扫描"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.status not in [TaskStatus.PENDING, TaskStatus.PAUSED]:
        raise HTTPException(status_code=400, detail=f"任务状态不允许启动 (当前: {task.status.value})")
    
    # 在后台启动扫描
    background_tasks.add_task(ScanExecutor.execute, task_id, scan_progress_callback)
    
    return {"message": "任务已启动", "task_id": task_id, "status": "running"}

@router.post("/{task_id}/pause")
async def pause_task(
    task_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """暂停扫描"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.status != TaskStatus.RUNNING:
        raise HTTPException(status_code=400, detail="任务不在运行中")
    
    # 停止执行器中的任务
    await ScanExecutor.stop(task_id)
    
    task.status = TaskStatus.PAUSED
    await db.commit()
    
    return {"message": "任务已暂停"}

@router.post("/{task_id}/stop")
async def stop_task(
    task_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """停止扫描"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    # 停止执行器中的任务
    await ScanExecutor.stop(task_id)
    
    task.status = TaskStatus.FAILED
    task.finished_at = datetime.utcnow()
    await db.commit()
    
    return {"message": "任务已停止"}

@router.delete("/{task_id}")
async def delete_task(
    task_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """删除任务"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.user_id != current_user.id and current_user.role.value not in ["admin"]:
        raise HTTPException(status_code=403, detail="权限不足")
    
    # 先停止运行中的任务
    if await ScanExecutor.is_running(task_id):
        await ScanExecutor.stop(task_id)
    
    await db.delete(task)
    await db.commit()
    
    return {"message": "任务已删除"}

@router.get("/{task_id}/progress")
async def get_task_progress(
    task_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取任务进度"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    is_running = await ScanExecutor.is_running(task_id)
    
    return {
        "task_id": task_id,
        "progress": task.progress,
        "status": task.status.value,
        "scanned_hosts": task.scanned_hosts,
        "total_hosts": task.total_hosts,
        "found_vulns": task.found_vulns,
        "is_running": is_running
    }
