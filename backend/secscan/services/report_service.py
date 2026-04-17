"""
报告生成服务
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from secscan.database import async_session_maker
from secscan.models.scan import ScanTask, TaskStatus
from secscan.models.asset import Asset
from secscan.models.vuln import Vulnerability
from secscan.models.report import Report, ReportType
from secscan.config import settings

class ReportService:
    """报告生成服务"""
    
    @classmethod
    async def generate_markdown_report(
        cls,
        task_id: int,
        user_id: int
    ) -> Report:
        """生成Markdown报告"""
        async with async_session_maker() as db:
            from sqlalchemy import select
            
            # 获取任务
            result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
            task = result.scalar_one_or_none()
            
            if not task:
                raise ValueError(f"任务 {task_id} 不存在")
            
            # 获取资产
            assets_result = await db.execute(
                select(Asset).where(Asset.task_id == task_id)
            )
            assets = assets_result.scalars().all()
            
            # 获取漏洞
            vulns_result = await db.execute(
                select(Vulnerability).where(Vulnerability.task_id == task_id)
            )
            vulns = vulns_result.scalars().all()
            
            # 生成报告内容
            content = cls._generate_markdown_content(task, assets, vulns)
            
            # 保存报告
            report = Report(
                task_id=task_id,
                user_id=user_id,
                name=f"{task.name} - 安全评估报告",
                type=ReportType.MARKDOWN,
                content=content,
                file_size=len(content.encode('utf-8'))
            )
            db.add(report)
            await db.commit()
            await db.refresh(report)
            
            return report
    
    @classmethod
    def _generate_markdown_content(
        cls,
        task: ScanTask,
        assets: list,
        vulns: list
    ) -> str:
        """生成Markdown内容"""
        # 统计
        alive_assets = [a for a in assets if a.status == "alive"]
        critical_vulns = [v for v in vulns if v.severity == "critical"]
        high_vulns = [v for v in vulns if v.severity == "high"]
        
        lines = [
            f"# {task.name} - 安全评估报告",
            "",
            f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**扫描目标**: {task.target}",
            f"**扫描类型**: {task.scan_type.value}",
            "",
            "## 执行摘要",
            "",
            f"- **扫描时间**: {task.started_at.strftime('%Y-%m-%d %H:%M:%S') if task.started_at else 'N/A'} - {task.finished_at.strftime('%Y-%m-%d %H:%M:%S') if task.finished_at else 'N/A'}",
            f"- **发现资产**: {len(alive_assets)} 个存活 / {len(assets)} 个总资产",
            f"- **发现漏洞**: {len(vulns)} 个",
            f"  - 严重: {len(critical_vulns)} 个",
            f"  - 高危: {len(high_vulns)} 个",
            "",
            "## 风险评估",
            "",
            cls._generate_risk_assessment(len(critical_vulns), len(high_vulns), len(assets)),
            "",
            "## 漏洞详情",
            ""
        ]
        
        # 按严重性分组
        severity_order = ["critical", "high", "medium", "low", "info"]
        vulns_by_severity = {s: [] for s in severity_order}
        
        for vuln in vulns:
            sev = vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity
            if sev in vulns_by_severity:
                vulns_by_severity[sev].append(vuln)
        
        for sev in severity_order:
            if vulns_by_severity[sev]:
                lines.append(f"### {sev.upper()} - {len(vulns_by_severity[sev])} 个")
                lines.append("")
                for vuln in vulns_by_severity[sev]:
                    lines.append(f"#### {vuln.name}")
                    lines.append(f"- **CVE**: {vuln.cve or 'N/A'}")
                    lines.append(f"- **目标**: {vuln.asset_id}")  # TODO: 关联资产信息
                    lines.append(f"- **描述**: {vuln.description or '无'}")
                    lines.append(f"- **修复建议**: {vuln.remediation or '请参考CVE官方公告'}")
                    lines.append("")
        
        lines.extend([
            "## 资产清单",
            "",
            f"| IP地址 | 端口 | 服务 | 产品 | 版本 | 状态 |",
            f"|--------|------|------|------|------|------|"
        ])
        
        for asset in assets:
            lines.append(f"| {asset.ip} | {asset.port} | {asset.service} | {asset.product} | {asset.version} | {asset.status} |")
        
        lines.extend([
            "",
            "---",
            f"",
            f"© {settings.COPYRIGHT}"
        ])
        
        return "\n".join(lines)
    
    @classmethod
    def _generate_risk_assessment(cls, critical: int, high: int, total_assets: int) -> str:
        """生成风险评估描述"""
        if critical > 0:
            level = "🔴 **极高风险**"
            desc = "发现严重漏洞，建议立即修复"
        elif high > 5:
            level = "🟠 **高风险**"
            desc = "发现多个高危漏洞，建议尽快修复"
        elif high > 0:
            level = "🟡 **中风险**"
            desc = "发现高危漏洞，建议安排修复"
        elif total_assets > 10:
            level = "🟢 **低风险**"
            desc = "暂未发现高危漏洞"
        else:
            level = "✅ **安全**"
            desc = "未发现明显安全问题"
        
        return f"{level}\n\n{desc}"
