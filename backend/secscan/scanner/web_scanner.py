"""
Web漏洞扫描器
"""

import asyncio
import httpx
from typing import AsyncGenerator, List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from secscan.scanner.base import ScannerBase, HostResult

class WebScanner(ScannerBase):
    """Web漏洞扫描器"""
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        super().__init__(task_id, options)
        self.timeout = options.get("timeout", 10)
        self.maxConcurrency = options.get("maxConcurrency", 10)
        self.followRedirects = options.get("followRedirects", True)
        
        # 常见漏洞检测规则
        self.vuln_checks = [
            {
                "name": "SQL注入",
                "patterns": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "admin'--",
                    "1' AND 1=2--"
                ],
                "indicators": ["sql", "syntax", "error", "mysql", "postgresql", "sqlite"]
            },
            {
                "name": "XSS跨站脚本",
                "patterns": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>"
                ],
                "indicators": ["<script>", "onerror=", "onload="]
            },
            {
                "name": "路径遍历",
                "patterns": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32",
                    "%2e%2e%2f%2e%2e%2f"
                ],
                "indicators": ["root:", "[drivers]", "boot loader"]
            }
        ]
    
    async def validate_target(self, target: str) -> bool:
        """验证目标"""
        try:
            result = urlparse(target)
            return all([result.scheme in ["http", "https"], result.netloc])
        except:
            return False
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """提取表单"""
        forms = []
        # 简单的表单提取（实际应该用BeautifulSoup）
        import re
        form_pattern = r'<form[^>]*>(.*?)</form>'
        action_pattern = r'action=["\']([^"\']*)["\']'
        method_pattern = r'method=["\']([^"\']*)["\']'
        input_pattern = r'<input[^>]*>'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            action = re.search(action_pattern, form_html)
            method = re.search(method_pattern, form_html)
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            forms.append({
                "action": urljoin(base_url, action.group(1) if action else ""),
                "method": method.group(1).lower() if method else "get",
                "inputs": inputs
            })
        
        return forms
    
    async def _check_vuln(self, url: str, vuln_check: Dict) -> Optional[Dict]:
        """检测漏洞"""
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.followRedirects
        ) as client:
            for payload in vuln_check["patterns"]:
                try:
                    # GET检测
                    test_url = f"{url}{'&' if '?' in url else '?'}test={payload}"
                    response = await client.get(test_url)
                    content = response.text.lower()
                    
                    # 检查响应
                    for indicator in vuln_check["indicators"]:
                        if indicator.lower() in content:
                            return {
                                "name": vuln_check["name"],
                                "payload": payload,
                                "url": test_url,
                                "evidence": indicator
                            }
                    
                    # POST检测（如果有表单）
                    forms = self._extract_forms(response.text, url)
                    for form in forms[:3]:  # 限制表单数量
                        data = {f"test{i}": payload for i in range(len(form["inputs"]))}
                        if form["method"] == "post":
                            resp = await client.post(form["action"], data=data)
                            if any(ind.lower() in resp.text.lower() for ind in vuln_check["indicators"]):
                                return {
                                    "name": vuln_check["name"],
                                    "payload": payload,
                                    "url": form["action"],
                                    "evidence": "form POST"
                                }
                
                except Exception:
                    continue
        
        return None
    
    async def scan(self, targets: List[str]) -> AsyncGenerator[HostResult, None]:
        """执行扫描"""
        total = len(targets)
        
        for i, target in enumerate(targets):
            target = target.strip()
            if not target:
                continue
            
            await self.report_progress(
                current=i + 1,
                total=total,
                target=target,
                message=f"扫描Web漏洞: {target}"
            )
            
            # 基本信息收集
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=self.followRedirects
                ) as client:
                    response = await client.get(target)
                    
                    # 解析URL
                    parsed = urlparse(target)
                    
                    # 创建结果
                    result = HostResult(
                        ip=parsed.netloc,
                        port=443 if parsed.scheme == "https" else 80,
                        protocol=parsed.scheme,
                        service="http",
                        banner=f"{response.status_code} - {len(response.text)} bytes"
                    )
                    
                    # 执行漏洞检测
                    vulns = []
                    for vuln_check in self.vuln_checks:
                        vuln = await self._check_vuln(target, vuln_check)
                        if vuln:
                            vulns.append(vuln)
                    
                    result.vulns = vulns
                    
                    if vulns:
                        await self.report_progress(
                            current=i + 1,
                            total=total,
                            target=target,
                            message=f"发现 {len(vulns)} 个漏洞",
                            vulns=len(vulns)
                        )
                    
                    yield result
                    
            except Exception as e:
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"扫描失败: {str(e)}"
                )
        
        await self.close()
    
    async def close(self):
        """清理"""
        pass
