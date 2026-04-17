"""
AI模块基类
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class AIBase(ABC):
    """AIProvider基类"""
    
    def __init__(self, api_key: str, model: str = None, timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
    
    @abstractmethod
    async def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析漏洞
        返回: {
            "severity": "high",
            "description": "...",
            "remediation": "...",
            "cvss": 8.5,
            "cwe": "CWE-89"
        }
        """
        pass
    
    @abstractmethod
    async def generate_poc(self, vuln_description: str, target: str) -> str:
        """
        生成POC代码
        """
        pass
    
    @abstractmethod
    async def summarize_report(self, scan_results: Dict[str, Any]) -> str:
        """
        生成报告摘要
        """
        pass
    
    @abstractmethod
    async def explain_vulnerability(self, cve_id: str) -> str:
        """
        解释漏洞（CVE详情）
        """
        pass
    
    def sanitize_content(self, content: str) -> str:
        """
        内容脱敏 - 移除敏感信息
        """
        import re
        
        # 移除IP地址（但保留目标信息）
        content = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]', content)
        
        # 移除域名（保留目标）
        # content = re.sub(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b', '[DOMAIN]', content)
        
        # 移除用户名
        content = re.sub(r'(?i)(user|username|userid)\s*[:=]\s*\S+', r'\1: [REDACTED]', content)
        
        # 移除密码
        content = re.sub(r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+', r'\1: [REDACTED]', content)
        
        # 移除API Key
        content = re.sub(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[a-zA-Z0-9\-_]{16,}', r'\1: [REDACTED]', content)
        
        # 移除邮箱
        content = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', content)
        
        # 移除手机号
        content = re.sub(r'\b1[3-9]\d{9}\b', '[PHONE]', content)
        
        return content
