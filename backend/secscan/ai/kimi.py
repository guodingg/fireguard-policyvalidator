"""
Kimi AI Provider (Moonshot)
"""

import json
import httpx
from typing import Dict, Any
from secscan.ai.base import AIBase
from secscan.config import settings

class KimiProvider(AIBase):
    """Kimi AI (Moonshot) 提供商"""
    
    BASE_URL = "https://api.moonshot.cn/v1"
    
    def __init__(self, api_key: str = None, model: str = "moonshot-v1-8k", timeout: int = 30):
        super().__init__(api_key or settings.AI_API_KEY, model, timeout)
    
    async def _call_api(self, messages: list) -> str:
        """调用Kimi API"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.3
                }
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
    
    async def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析漏洞"""
        prompt = f"""你是一个漏洞分析专家。请分析以下漏洞信息并返回JSON格式的分析结果。

漏洞名称: {vuln_data.get('name', '未知')}
CVE编号: {vuln_data.get('cve', 'N/A')}
目标: {vuln_data.get('target', '未知')}
描述: {vuln_data.get('description', '无')}

请返回JSON格式的分析，包含以下字段：
- severity: 严重程度 (critical/high/medium/low/info)
- cvss: CVSS评分 (0-10)
- cwe: CWE编号
- description: 详细描述
- remediation: 修复建议
- risk_factor: 风险因素分析

只返回JSON，不要有其他文字。"""
        
        messages = [{"role": "user", "content": self.sanitize_content(prompt)}]
        
        try:
            result = await self._call_api(messages)
            return json.loads(result)
        except Exception as e:
            return {
                "severity": vuln_data.get('severity', 'medium'),
                "cvss": 5.0,
                "cwe": "N/A",
                "description": str(e),
                "remediation": "请人工分析",
                "risk_factor": "AI分析失败"
            }
    
    async def generate_poc(self, vuln_description: str, target: str) -> str:
        """生成POC"""
        prompt = f"""你是一个安全专家。请根据以下漏洞描述生成一个检测POC。

漏洞描述: {vuln_description}
目标: {target}

请生成一个Python脚本形式的POC，用于检测该漏洞。
要求：
1. 使用requests库
2. 包含漏洞验证逻辑
3. 打印检测结果
4. 不要包含任何攻击性代码

只返回代码，不要有其他解释。"""
        
        messages = [{"role": "user", "content": self.sanitize_content(prompt)}]
        
        try:
            return await self._call_api(messages)
        except Exception as e:
            return f"# POC生成失败: {str(e)}"
    
    async def summarize_report(self, scan_results: Dict[str, Any]) -> str:
        """生成报告摘要"""
        prompt = f"""你是一个安全报告撰写专家。请根据以下扫描结果生成一份简洁的安全报告摘要。

扫描结果概览:
- 总目标数: {scan_results.get('total_targets', 0)}
- 存活主机: {scan_results.get('alive_hosts', 0)}
- 发现漏洞: {scan_results.get('total_vulns', 0)}
- 高危漏洞: {scan_results.get('critical_vulns', 0)}

漏洞列表:
{json.dumps(scan_results.get('vulnerabilities', [])[:10], ensure_ascii=False, indent=2)}

请生成一份中文的安全摘要，包括：
1. 总体风险评估
2. 主要发现
3. 建议优先级

用自然语言描述，不要JSON格式。"""
        
        messages = [{"role": "user", "content": prompt}]
        
        try:
            return await self._call_api(messages)
        except Exception as e:
            return f"报告生成失败: {str(e)}"
    
    async def explain_vulnerability(self, cve_id: str) -> str:
        """解释CVE"""
        prompt = f"""请解释以下CVE漏洞的详细信息：

CVE编号: {cve_id}

请提供：
1. 漏洞简介
2. 影响范围
3. 利用条件
4. 修复建议

用中文回答。"""
        
        messages = [{"role": "user", "content": prompt}]
        
        try:
            return await self._call_api(messages)
        except Exception as e:
            return f"CVE查询失败: {str(e)}"
