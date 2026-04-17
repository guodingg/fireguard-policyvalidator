"""
Web漏洞扫描器
"""

import asyncio
import httpx
import re
from typing import AsyncGenerator, List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from secscan.scanner.base import ScannerBase, HostResult

class WebScanner(ScannerBase):
    """Web漏洞扫描器"""
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        super().__init__(task_id, options)
        self.timeout = options.get("timeout", 10)
        self.maxConcurrency = options.get("maxConcurrency", 5)
        self.followRedirects = options.get("follow_redirects", True)
        self.user_agent = options.get("user_agent", "ANTsafe Scanner/1.0")
        
        # 启用的漏洞检测
        self.enable_sqli = options.get("enable_sqli", True)
        self.enable_xss = options.get("enable_xss", True)
        self.enable_lfi = options.get("enable_lfi", True)
        self.enable_ssti = options.get("enable_ssti", True)
        
        # 漏洞检测规则
        self.vuln_checks = self._init_vuln_checks()
    
    def _init_vuln_checks(self) -> List[Dict]:
        """初始化漏洞检测规则"""
        checks = []
        
        # SQL注入
        if self.enable_sqli:
            checks.extend([
                {
                    "name": "SQL注入",
                    "severity": "high",
                    "patterns": [
                        "' OR '1'='1",
                        "' OR 1=1--",
                        "admin'--",
                        "1' AND 1=2--",
                        "' UNION SELECT NULL--"
                    ],
                    "error_indicators": ["sql", "syntax", "error", "mysql", "postgresql", "sqlite", "oracle", "microsoft sql"]
                }
            ])
        
        # XSS
        if self.enable_xss:
            checks.extend([
                {
                    "name": "XSS跨站脚本",
                    "severity": "medium",
                    "patterns": [
                        "<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>",
                        "<svg/onload=alert(1)>",
                        "javascript:alert(1)"
                    ],
                    "error_indicators": ["<script>", "onerror=", "onload=", "alert(1)"]
                }
            ])
        
        # 路径遍历
        if self.enable_lfi:
            checks.extend([
                {
                    "name": "路径遍历",
                    "severity": "high",
                    "patterns": [
                        "../../../etc/passwd",
                        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                        "%2e%2e%2f%2e%2e%2f",
                        "....//....//....//etc/passwd"
                    ],
                    "error_indicators": ["root:", "[drivers]", "boot loader", "winnt"]
                }
            ])
        
        # SSTI模板注入
        if self.enable_ssti:
            checks.extend([
                {
                    "name": "SSTI模板注入",
                    "severity": "critical",
                    "patterns": [
                        "{{7*7}}",
                        "${7*7}",
                        "<%= 7*7 %>",
                        "{7*7}"
                    ],
                    "error_indicators": ["49", "7*7"]
                }
            ])
        
        return checks
    
    async def validate_target(self, target: str) -> bool:
        """验证目标"""
        try:
            result = urlparse(target)
            return all([result.scheme in ["http", "https"], result.netloc])
        except:
            return False
    
    def _normalize_url(self, target: str) -> str:
        """标准化URL"""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """提取表单"""
        forms = []
        
        # 简单的表单提取
        form_pattern = r'<form[^>]*>(.*?)</form>'
        action_pattern = r'action=["\']([^"\']*)["\']'
        method_pattern = r'method=["\']([^"\']*)["\']'
        input_pattern = r'<input[^>]*>'
        name_pattern = r'name=["\']([^"\']*)["\']'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            action = re.search(action_pattern, form_html)
            method = re.search(method_pattern, form_html)
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            form_action = ""
            if action:
                action_value = action.group(1)
                form_action = urljoin(base_url, action_value if action_value else base_url)
            
            forms.append({
                "action": form_action or base_url,
                "method": method.group(1).lower() if method else "get",
                "inputs": inputs
            })
        
        return forms
    
    async def _check_vuln(self, url: str, vuln_check: Dict) -> Optional[Dict]:
        """检测漏洞"""
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.followRedirects,
            headers={"User-Agent": self.user_agent}
        ) as client:
            for payload in vuln_check["patterns"]:
                try:
                    # GET检测
                    separator = "&" if "?" in url else "?"
                    test_url = f"{url}{separator}test={payload}&q={payload}"
                    
                    response = await client.get(test_url, follow_redirects=True)
                    content = response.text.lower()
                    
                    # 检查响应中的错误指示器
                    for indicator in vuln_check["error_indicators"]:
                        if indicator.lower() in content:
                            return {
                                "name": vuln_check["name"],
                                "severity": vuln_check["severity"],
                                "payload": payload,
                                "url": test_url,
                                "evidence": f"发现敏感信息: {indicator}"
                            }
                    
                    # 检查是否直接回显
                    if payload in response.text:
                        return {
                            "name": vuln_check["name"],
                            "severity": vuln_check["severity"],
                            "payload": payload,
                            "url": test_url,
                            "evidence": "Payload直接回显"
                        }
                    
                    # POST检测（如果有表单）
                    forms = self._extract_forms(response.text, url)
                    for form in forms[:3]:
                        data = {}
                        for inp in form["inputs"]:
                            name_match = re.search(name_pattern, inp, re.IGNORECASE)
                            if name_match:
                                data[name_match.group(1)] = payload
                        
                        if form["method"] == "post" and data:
                            try:
                                resp = await client.post(form["action"], data=data)
                                if any(ind.lower() in resp.text.lower() for ind in vuln_check["error_indicators"]):
                                    return {
                                        "name": vuln_check["name"],
                                        "severity": vuln_check["severity"],
                                        "payload": payload,
                                        "url": form["action"],
                                        "evidence": "Form POST检测到漏洞"
                                    }
                            except:
                                pass
                
                except Exception:
                    continue
        
        return None
    
    async def scan(self, targets: List[str]) -> AsyncGenerator[HostResult, None]:
        """执行扫描"""
        total = len(targets)
        
        for i, target in enumerate(targets):
            target = self._normalize_url(target)
            
            if not await self.validate_target(target):
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"无效的URL: {target}",
                    vulns=0
                )
                continue
            
            await self.report_progress(
                current=i + 1,
                total=total,
                target=target,
                message=f"正在扫描: {target}",
                vulns=0
            )
            
            # 基本信息收集
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=self.followRedirects,
                    headers={"User-Agent": self.user_agent}
                ) as client:
                    response = await client.get(target, follow_redirects=True)
                    
                    # 解析URL
                    parsed = urlparse(target)
                    
                    # 识别Web指纹
                    server = response.headers.get("server", "")
                    powered = response.headers.get("x-powered-by", "")
                    
                    # 提取标题
                    title_match = re.search(r'<title>([^<]+)</title>', response.text, re.IGNORECASE)
                    web_title = title_match.group(1) if title_match else ""
                    
                    # 创建结果
                    result = HostResult(
                        ip=parsed.netloc,
                        port=443 if parsed.scheme == "https" else 80,
                        protocol=parsed.scheme,
                        service="http",
                        product=server or powered,
                        banner=f"{response.status_code} - {web_title or 'N/A'}"
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
                    else:
                        await self.report_progress(
                            current=i + 1,
                            total=total,
                            target=target,
                            message=f"扫描完成，未发现漏洞",
                            vulns=0
                        )
                    
                    yield result
                    
            except httpx.TimeoutException:
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"连接超时",
                    vulns=0
                )
            except Exception as e:
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"扫描失败: {str(e)}",
                    vulns=0
                )
        
        await self.close()
    
    async def close(self):
        """清理"""
        pass
