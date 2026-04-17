"""
AI API
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

from secscan.models.user import User
from secscan.api.v1.auth import get_current_user
from secscan.ai.manager import AIManager

router = APIRouter(prefix="/ai", tags=["AI分析"])

class VulnAnalyzeRequest(BaseModel):
    name: str
    cve: Optional[str] = None
    target: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None

class POCGenerateRequest(BaseModel):
    vuln_description: str
    target: str

class ReportSummaryRequest(BaseModel):
    total_targets: int = 0
    alive_hosts: int = 0
    total_vulns: int = 0
    critical_vulns: int = 0
    vulnerabilities: List[Dict[str, Any]] = []

@router.post("/analyze/vulnerability")
async def analyze_vulnerability(
    data: VulnAnalyzeRequest,
    current_user: User = Depends(get_current_user)
):
    """分析漏洞"""
    try:
        result = await AIManager.analyze_vulnerability(data.model_dump())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/generate/poc")
async def generate_poc(
    data: POCGenerateRequest,
    current_user: User = Depends(get_current_user)
):
    """生成POC"""
    try:
        result = await AIManager.generate_poc(data.vuln_description, data.target)
        return {"poc": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/summarize/report")
async def summarize_report(
    data: ReportSummaryRequest,
    current_user: User = Depends(get_current_user)
):
    """生成报告摘要"""
    try:
        result = await AIManager.summarize_report(data.model_dump())
        return {"summary": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/explain/cve/{cve_id}")
async def explain_cve(
    cve_id: str,
    current_user: User = Depends(get_current_user)
):
    """CVE漏洞解释"""
    try:
        result = await AIManager.explain_cve(cve_id)
        return {"explanation": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/batch/analyze")
async def batch_analyze(
    vulns: List[Dict[str, Any]],
    current_user: User = Depends(get_current_user)
):
    """批量分析漏洞"""
    try:
        results = await AIManager.batch_analyze_vulns(vulns)
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
