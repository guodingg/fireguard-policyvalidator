"""
AI服务管理器
"""

from typing import Dict, Any, Optional
from secscan.config import settings
from secscan.ai.base import AIBase
from secscan.ai.kimi import KimiProvider
from secscan.ai.minimax import MiniMaxProvider

class AIManager:
    """AI服务统一管理器"""
    
    _providers: Dict[str, AIBase] = {}
    
    @classmethod
    def get_provider(cls, provider: str = None) -> AIBase:
        """获取AI提供商实例"""
        provider = provider or settings.AI_PROVIDER
        
        if provider in cls._providers:
            return cls._providers[provider]
        
        if provider == "kimi":
            cls._providers[provider] = KimiProvider()
        elif provider == "minimax":
            cls._providers[provider] = MiniMaxProvider(api_key=settings.AI_API_KEY, group_id="")
        elif provider == "deepseek":
            # DeepSeek provider
            cls._providers[provider] = KimiProvider(api_key=settings.AI_API_KEY, model="deepseek-chat")
        else:
            raise ValueError(f"不支持的AI提供商: {provider}")
        
        return cls._providers[provider]
    
    @classmethod
    async def analyze_vulnerability(cls, vuln_data: Dict[str, Any], provider: str = None) -> Dict[str, Any]:
        """分析漏洞"""
        p = cls.get_provider(provider)
        return await p.analyze_vulnerability(vuln_data)
    
    @classmethod
    async def generate_poc(cls, vuln_description: str, target: str, provider: str = None) -> str:
        """生成POC"""
        p = cls.get_provider(provider)
        return await p.generate_poc(vuln_description, target)
    
    @classmethod
    async def summarize_report(cls, scan_results: Dict[str, Any], provider: str = None) -> str:
        """生成报告摘要"""
        p = cls.get_provider(provider)
        return await p.summarize_report(scan_results)
    
    @classmethod
    async def explain_cve(cls, cve_id: str, provider: str = None) -> str:
        """解释CVE"""
        p = cls.get_provider(provider)
        return await p.explain_vulnerability(cve_id)
    
    @classmethod
    async def batch_analyze_vulns(cls, vulns: list, provider: str = None) -> list:
        """批量分析漏洞"""
        results = []
        for vuln in vulns:
            try:
                result = await cls.analyze_vulnerability(vuln, provider)
                results.append({**vuln, "ai_analysis": result, "ai_analyzed": True})
            except Exception as e:
                results.append({**vuln, "ai_analysis": {"error": str(e)}, "ai_analyzed": False})
        return results
