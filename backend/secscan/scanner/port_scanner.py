"""
TCP端口扫描器
"""

import asyncio
import socket
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
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb"
}

# Top 100 ports
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5632, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152
]

class PortScanner(ScannerBase):
    """TCP端口扫描器"""
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        super().__init__(task_id, options)
        self.timeout = options.get("timeout", 3)
        self.maxConcurrency = options.get("maxConcurrency", 100)
        
        # 端口选项
        port_mode = options.get("port_mode", "common")  # common | top100 | all | custom
        if port_mode == "top100":
            self.ports_to_scan = TOP_100_PORTS
        elif port_mode == "all":
            self.ports_to_scan = list(range(1, 1001))  # 前1000端口
        elif port_mode == "custom":
            custom_ports = options.get("ports", "")
            if custom_ports:
                self.ports_to_scan = self._parse_ports(custom_ports)
            else:
                self.ports_to_scan = list(COMMON_PORTS.keys())
        else:  # common
            self.ports_to_scan = list(COMMON_PORTS.keys())
    
    def _parse_ports(self, port_str: str) -> List[int]:
        """解析端口字符串"""
        ports = set()
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)
    
    async def validate_target(self, target: str) -> bool:
        """验证目标"""
        try:
            target = target.strip()
            if "/" in target:
                # CIDR
                ipaddress.ip_network(target, strict=False)
            else:
                # 域名或IP
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
                    if network.num_addresses > 256:
                        # 限制扫描范围
                        expanded.extend([str(ip) for ip in list(network.hosts())[:256]])
                    else:
                        expanded.extend([str(ip) for ip in network.hosts()])
                else:
                    # 尝试DNS解析
                    try:
                        ip = socket.gethostbyname(target)
                        expanded.append(ip)
                    except:
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
                writer.write(b"\r\n")
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
        # 验证并展开目标
        valid_targets = []
        for t in targets:
            if await self.validate_target(t):
                valid_targets.append(t)
        
        all_targets = self._expand_targets(valid_targets)
        
        if not all_targets:
            return
        
        # 去重
        all_targets = list(set(all_targets))
        total = len(all_targets) * len(self.ports_to_scan)
        current = 0
        
        if total == 0:
            return
        
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
                    message=f"发现开放端口 {result.service}",
                    vulns=0
                )
                yield result
            else:
                # 报告失败进度
                ip, port = tasks[i]
                await self.report_progress(
                    current=current,
                    total=total,
                    target=f"{ip}:{port}",
                    message="端口关闭",
                    vulns=0
                )
        
        await self.close()
    
    async def close(self):
        """清理"""
        pass
