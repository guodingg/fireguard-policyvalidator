"""
漏洞API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.vuln import Vulnerability, VulnStatus, VulnVerification
from secscan.models.asset import Asset
from secscan.models.scan import ScanTask
from secscan.api.v1.auth import get_current_user
from secscan.scanner.vuln_verifier import verify_vulnerability

router = APIRouter(prefix="/vulns", tags=["漏洞管理"])

@router.get("/")
async def list_vulns(
    skip: int = 0,
    limit: int = 100,
    task_id: int = None,
    severity: str = None,
    status: VulnStatus = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """漏洞列表"""
    from sqlalchemy import func, select
    from secscan.models.asset import Asset
    
    # 构建基础查询
    base_query = select(Vulnerability)
    count_query = select(func.count(Vulnerability.id))
    
    if task_id:
        base_query = base_query.where(Vulnerability.task_id == task_id)
        count_query = count_query.where(Vulnerability.task_id == task_id)
    if severity:
        base_query = base_query.where(Vulnerability.severity == severity)
        count_query = count_query.where(Vulnerability.severity == severity)
    if status:
        base_query = base_query.where(Vulnerability.status == status)
        count_query = count_query.where(Vulnerability.status == status)
    
    # 获取总数
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0
    
    # 获取分页数据
    query = base_query.order_by(Vulnerability.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    vulns = result.scalars().all()
    
    # 获取所有漏洞的最新验证记录
    vuln_ids = [v.id for v in vulns]
    latest_verifs = {}
    if vuln_ids:
        verif_result = await db.execute(
            select(VulnVerification.vuln_id, VulnVerification.status)
            .where(VulnVerification.vuln_id.in_(vuln_ids))
            .order_by(VulnVerification.verified_at.desc())
        )
        for row in verif_result.all():
            if row[0] not in latest_verifs:
                latest_verifs[row[0]] = row[1]
    
    # 构建带target信息的响应
    items = []
    for vuln in vulns:
        vuln_dict = {
            "id": vuln.id,
            "name": vuln.name,
            "cve": vuln.cve,
            "severity": vuln.severity,
            "status": vuln.status,
            "task_id": vuln.task_id,
            "asset_id": vuln.asset_id,
            "path": vuln.path,
            "payload": vuln.payload,
            "description": vuln.description,
            "verified": vuln.verified,
            "category": vuln.category,
            "created_at": vuln.created_at.isoformat() if vuln.created_at else None,
            "verification_result": latest_verifs.get(vuln.id)
        }
        # 获取资产信息构建target
        if vuln.asset_id:
            asset_result = await db.execute(select(Asset).where(Asset.id == vuln.asset_id))
            asset = asset_result.scalar_one_or_none()
            if asset:
                protocol = asset.protocol or "http"
                port = asset.port or 80
                host = asset.ip or asset.hostname or ""
                # 简化端口显示
                if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
                    port_str = ""
                else:
                    port_str = f":{port}"
                vuln_dict["target"] = f"{protocol}://{host}{port_str}{vuln.path}"
            else:
                vuln_dict["target"] = vuln.path
        else:
            vuln_dict["target"] = vuln.path
        items.append(vuln_dict)
    
    return {"total": total, "items": items}

@router.get("/{vuln_id}")
async def get_vuln(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取漏洞详情"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    return vuln

@router.put("/{vuln_id}/verify")
async def verify_vuln(
    vuln_id: int,
    auto: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """验证漏洞
    
    Args:
        vuln_id: 漏洞ID
        auto: 是否自动验证（发送测试数据包）
    """
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    # 自动验证模式
    if auto:
        # 获取扫描任务的目标地址
        task_result = await db.execute(select(ScanTask).where(ScanTask.id == vuln.task_id))
        task = task_result.scalar_one_or_none()
        
        vuln_data = {
            "target": task.target if task else vuln.path or "http://unknown",
            "path": vuln.path or "",
            "name": vuln.name or "",
            "category": vuln.category or "",
            "cve": vuln.cve or "",
            "payload": vuln.payload
        }
        verify_result = await verify_vulnerability(vuln_data)
        
        if not verify_result:
            verify_result = {"vulnerable": None, "reason": "验证服务返回空结果", "error": "empty result"}
        
        # 如果验证成功，更新漏洞状态
        if verify_result.get("vulnerable"):
            vuln.verified = True
            vuln.status = VulnStatus.VERIFIED
            await db.commit()
        
        return {
            "vulnerable": verify_result.get("vulnerable"),
            "reason": verify_result.get("reason", ""),
            "indicator": verify_result.get("indicator", ""),
            "payload": verify_result.get("payload", ""),
            "url": verify_result.get("url", task.target if task else vuln.path or ""),
            "method": verify_result.get("method", "GET"),
            "status_code": verify_result.get("status_code", 0),
            "response_time": verify_result.get("response_time", 0),
            "evidence": verify_result.get("evidence", ""),
            "error": verify_result.get("error", "")
        }
    
    # 手动验证模式
    vuln.verified = True
    vuln.status = VulnStatus.VERIFIED
    await db.commit()
    
    return {"message": "漏洞已验证", "status": "manual"}

@router.put("/{vuln_id}/fix")
async def fix_vuln(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """标记漏洞已修复"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    vuln.status = VulnStatus.FIXED
    vuln.verified = False
    await db.commit()
    
    return {"message": "漏洞已修复"}

@router.put("/{vuln_id}/false-positive")
async def mark_false_positive(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """标记为误报"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    vuln.is_false_positive = True
    vuln.status = VulnStatus.FALSE_POSITIVE
    await db.commit()
    
    return {"message": "已标记为误报"}
