"""
MiniMax AI Provider
"""

import json
import httpx
from typing import Dict, Any
from secscan.ai.base import AIBase

class MiniMaxProvider(AIBase):
    """MiniMax AI 提供商"""
    
    BASE_URL = "https://api.minimax.chat/v1"
    
    def __init__(self, api_key: str, group_id: str, model: str = "abab6.5s-chat", timeout: int = 30):
        super().__init__(api_key, model, timeout)
        self.group_id = group_id
    
    async def _call_api(self, messages: list) -> str:
        """调用MiniMax API"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.BASE_URL}/text/chatcompletion_v2",
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
        prompt = f"""分析以下漏洞：

名称: {vuln_data.get('name', '未知')}
CVE: {vuln_data.get('cve', 'N/A')}
目标: {vuln_data.get('target', '未知')}

返回JSON：{{"severity": "high/low/medium/critical", "cvss": 8.0, "cwe": "CWE-XX", "remediation": "修复建议"}}"""
        
        messages = [{"role": "user", "content": self.sanitize_content(prompt)}]
        
        try:
            result = await self._call_api(messages)
            return json.loads(result)
        except:
            return {"severity": "medium", "cvss": 5.0, "cwe": "N/A", "remediation": "请人工分析"}
    
    async def generate_poc(self, vuln_description: str, target: str) -> str:
        """生成POC"""
        prompt = f"根据漏洞描述生成检测POC：{vuln_description}，目标：{target}"
        messages = [{"role": "user", "content": self.sanitize_content(prompt)}]
        
        try:
            return await self._call_api(messages)
        except:
            return "# POC生成失败"
    
    async def summarize_report(self, scan_results: Dict[str, Any]) -> str:
        """生成报告"""
        prompt = f"生成安全扫描报告摘要：{json.dumps(scan_results, ensure_ascii=False)}"
        messages = [{"role": "user", "content": prompt}]
        
        try:
            return await self._call_api(messages)
        except:
            return "报告生成失败"
    
    async def explain_vulnerability(self, cve_id: str) -> str:
        """解释CVE"""
        prompt = f"解释CVE漏洞 {cve_id}，用中文回答"
        messages = [{"role": "user", "content": prompt}]
        
        try:
            return await self._call_api(messages)
        except:
            return f"CVE查询失败: {cve_id}"
