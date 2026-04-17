"""
端口扫描器
"""

import asyncio
import socket
import concurrent.futures
from typing import AsyncGenerator, List, Dict, Any, Optional
import ipaddress

from secscan.scanner.base import ScannerBase, HostResult

# 常用端口列表
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb"
}

class PortScanner(ScannerBase):
    """TCP端口扫描器"""
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        super().__init__(task_id, options)
        self.timeout = options.get("timeout", 3)
        self.maxConcurrency = options.get("maxConcurrency", 100)
        self.ports_to_scan = options.get("ports", list(COMMON_PORTS.keys()))
    
    async def validate_target(self, target: str) -> bool:
        """验证目标"""
        try:
            # 支持IP、CIDR、域名
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
            else:
                socket.gethostbyname(target)
            return True
        except:
            return False
    
    def _expand_targets(self, targets: List[str]) -> List[str]:
        """展开目标列表"""
        expanded = []
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            try:
                if "/" in target:
                    # CIDR
                    network = ipaddress.ip_network(target, strict=False)
                    # 限制范围
                    if network.num_addresses > 256:
                        # 太大了，只取前256个
                        expanded.extend([str(ip) for ip in list(network.hosts())[:256]])
                    else:
                        expanded.extend([str(ip) for ip in network.hosts()])
                else:
                    expanded.append(target)
            except:
                expanded.append(target)
        
        return expanded
    
    async def _scan_port(self, ip: str, port: int) -> Optional[HostResult]:
        """扫描单个端口"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # 获取banner
            banner = ""
            try:
                reader.writer.write(b"\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=1)
                if banner:
                    banner = banner.decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            service = COMMON_PORTS.get(port, "unknown")
            
            writer.close()
            await writer.wait_closed()
            
            return HostResult(
                ip=ip,
                port=port,
                protocol="tcp",
                service=service,
                banner=banner[:512]
            )
        except:
            return None
    
    async def scan(self, targets: List[str]) -> AsyncGenerator[HostResult, None]:
        """执行扫描"""
        # 展开目标
        all_targets = self._expand_targets(targets)
        total = len(all_targets) * len(self.ports_to_scan)
        current = 0
        
        # 创建信号量控制并发
        semaphore = asyncio.Semaphore(self.maxConcurrency)
        
        async def scan_with_sem(ip: str, port: int):
            async with semaphore:
                return await self._scan_port(ip, port)
        
        # 创建所有扫描任务
        tasks = []
        for ip in all_targets:
            for port in self.ports_to_scan:
                tasks.append((ip, port))
        
        # 并发执行
        results = await asyncio.gather(
            *[scan_with_sem(ip, port) for ip, port in tasks],
            return_exceptions=True
        )
        
        for i, result in enumerate(results):
            current += 1
            if isinstance(result, HostResult):
                await self.report_progress(
                    current=current,
                    total=total,
                    target=f"{result.ip}:{result.port}",
                    message=f"发现开放端口 {result.service}"
                )
                yield result
            else:
                # 报告失败进度
                ip, port = tasks[i]
                await self.report_progress(
                    current=current,
                    total=total,
                    target=f"{ip}:{port}",
                    message="端口关闭"
                )
        
        await self.close()
    
    async def close(self):
        """清理"""
        pass
