"""
漏洞情报服务 v4 - 实时真实数据 + 中文源
从多个权威来源获取漏洞情报：
1. CISA KEV JSON - 美国政府已知被利用漏洞目录（最权威）
2. GitHub Security Advisories - 全球开源项目安全公告
3. NVD RSS - 美国国家漏洞数据库
4. 长亭漏洞库 - stack.chaitin.com（中文，高质量）
5. OSCS开源安全情报 - www.oscs1024.com（中文预警）
6. 阿里云漏洞库 - avd.aliyun.com（WAF绕过）
"""

import httpx
import asyncio
import re
import json
import hashlib
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from sqlalchemy import select, and_
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from secscan.database import async_session_maker
from secscan.models.intel import IntelVuln, IntelFetchLog


@dataclass
class IntelSource:
    """情报来源配置"""
    id: str
    name: str
    name_cn: str
    url: str
    enabled: bool = True


@dataclass
class VulnIntelItem:
    """标准化漏洞情报"""
    cve_id: str
    vulnerability_name: str
    source: str
    source_url: str
    severity: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    vendor: str
    product: str
    product_version: str
    description: str
    cwe_ids: List[str]
    is_known_exploited: bool
    is_ransomware_related: str
    is_poc_public: bool
    poc_reference: str
    is_rce: bool
    published_date: Optional[datetime]
    last_modified: Optional[datetime]
    tags: List[str]
    references: List[Dict]
    remediation: str
    remediation_url: str
    due_date: Optional[datetime]
    hash_id: str = ""


class VulnIntelService:
    """漏洞情报服务 v3"""

    # 情报来源
    SOURCES = {
        "cisa_kev": IntelSource(
            id="cisa_kev",
            name="CISA KEV",
            name_cn="CISA 已知被利用漏洞",
            url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            enabled=True
        ),
        "github_advisory": IntelSource(
            id="github_advisory",
            name="GitHub Advisory DB",
            name_cn="GitHub 安全公告",
            url="https://api.github.com/advisories",
            enabled=True
        ),
        "nvd_rss": IntelSource(
            id="nvd_rss",
            name="NVD RSS",
            name_cn="NVD 漏洞数据库",
            url="https://nvd.nist.gov/feeds/json/cve-1.1/nvdcve-1.1-recent.json.gz",
            enabled=True
        ),
        "osv": IntelSource(
            id="osv",
            name="Google OSV",
            name_cn="开源漏洞数据库",
            url="https://api.osv.dev/v1/query",
            enabled=True
        ),
        "chaitin": IntelSource(
            id="chaitin",
            name="Chaitin VulnDB",
            name_cn="长亭漏洞库",
            url="https://stack.chaitin.com/vuldb/index",
            enabled=True
        ),
        "oscs": IntelSource(
            id="oscs",
            name="OSCS",
            name_cn="OSCS开源安全情报",
            url="https://www.oscs1024.com/cm",
            enabled=True
        ),
        "avd": IntelSource(
            id="avd",
            name="Aliyun AVD",
            name_cn="阿里云漏洞库",
            url="https://avd.aliyun.com/high-risk/list",
            enabled=False  # 需要WAF绕过，暂时禁用
        )
    }

    # 严重性映射
    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "low",
        "unknown": "unknown",
        "none": "low"
    }

    # CVE关键词检测
    RCE_KEYWORDS = [
        "remote code execution", "rce", "remote code exec",
        "arbitrary code execution", "code execution",
        "execute arbitrary", "execute code",
        "os command injection", "command injection",
        "sql injection", "sqli",
        "ldap injection", "xml injection", "xpath injection",
        "deserialization", "unsafe deserialization"
    ]
    PRIV_ESC_KEYWORDS = [
        "privilege escalation", "privilege elevation",
        "local privilege escalation", "lpe",
        "escape", "container escape",
        "sandbox escape"
    ]
    POC_KEYWORDS = ["poc", "proof of concept", "exploit", "metasploit", "pwn"]

    def __init__(self):
        self.cache_duration = timedelta(minutes=15)  # 缓存15分钟
        self.last_fetch_time = {}
        self._stats = {"total": 0, "by_source": {}, "by_severity": {}}

    # ========== 核心：获取所有情报 ==========

    async def fetch_all_sources(self, force: bool = False) -> Dict:
        """从所有来源获取情报，返回统计信息"""
        results = {
            "cisa_kev": {"fetched": 0, "new": 0, "errors": []},
            "github_advisory": {"fetched": 0, "new": 0, "errors": []},
            "nvd_rss": {"fetched": 0, "new": 0, "errors": []},
            "chaitin": {"fetched": 0, "new": 0, "errors": []},
            "oscs": {"fetched": 0, "new": 0, "errors": []},
            "avd": {"fetched": 0, "new": 0, "errors": []},
        }

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(120.0, connect=30.0),
            headers={"User-Agent": "SecScan-AI/1.0 Vulnerability Intel Collector"}
        ) as client:
            tasks = []
            # 过滤启用的来源
            fetchers = {
                "cisa_kev": lambda r: self._fetch_cisa_kev(client, r, force),
                "github_advisory": lambda r: self._fetch_github_advisory(client, r, force),
                "nvd_rss": lambda r: self._fetch_nvd_rss(client, r, force),
                "chaitin": lambda r: self._fetch_chaitin(client, r, force),
                "oscs": lambda r: self._fetch_oscs(client, r, force),
            }
            for source_id, fetcher in fetchers.items():
                if self.SOURCES.get(source_id, IntelSource("","","","",True)).enabled:
                    tasks.append(fetcher(results.get(source_id, {"fetched": 0, "new": 0, "errors": []})))

            await asyncio.gather(*tasks, return_exceptions=True)

        # 更新统计
        await self._refresh_stats()
        return results

    # ========== CISA KEV JSON (最可靠) ==========

    async def _fetch_cisa_kev(self, client: httpx.AsyncClient, result: Dict, force: bool) -> None:
        """获取CISA已知被利用漏洞目录"""
        start_time = datetime.now(timezone.utc)
        log_entry = IntelFetchLog(source="cisa_kev", status="failed")

        try:
            resp = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                headers={"Accept": "application/json"},
                timeout=30.0
            )
            resp.raise_for_status()
            data = resp.json()

            items = data.get("vulnerabilities", [])
            new_count = 0
            fetched_count = 0

            async with async_session_maker() as db:
                for item in items:
                    fetched_count += 1
                    intel = self._parse_cisa_item(item)
                    if intel:
                        is_new = await self._upsert_intel(db, intel)
                        if is_new:
                            new_count += 1

                await db.commit()

            log_entry.status = "success"
            log_entry.items_fetched = fetched_count
            log_entry.new_items = new_count
            result["fetched"] = fetched_count
            result["new"] = new_count

        except Exception as e:
            log_entry.status = "failed"
            log_entry.errors = str(e)[:500]
            result["errors"].append(str(e))
        finally:
            duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            log_entry.duration_ms = duration
            await self._save_fetch_log(log_entry)

    def _parse_cisa_item(self, item: Dict) -> Optional[VulnIntelItem]:
        """解析CISA KEV条目"""
        try:
            cve_id = item.get("cveID", "")
            if not cve_id.startswith("CVE-"):
                return None

            # 从描述推断RCE
            desc = item.get("shortDescription", "").lower()
            is_rce = any(kw in desc for kw in self.RCE_KEYWORDS)

            # CISA KEV 都是已知被利用
            known_ransomware = item.get("knownRansomwareCampaignUse", "Unknown")

            # 严重性从CVSS推断（KEV不直接提供，用关键词）
            severity = self._infer_severity(item.get("shortDescription", ""), is_known_exploited=True)

            # 解析日期
            published_date = self._parse_date(item.get("dateAdded", ""))
            due_date = self._parse_date(item.get("dueDate", ""))

            # CWE
            cwe_ids = item.get("cweIDs", []) or []

            references = []
            notes = item.get("notes", "")
            if notes:
                for url in notes.split():
                    if url.startswith("http"):
                        references.append({"title": "NVD", "url": url})

            return VulnIntelItem(
                cve_id=cve_id,
                vulnerability_name=item.get("vulnerabilityName", cve_id),
                source="cisa_kev",
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                severity=severity,
                cvss_score=None,
                cvss_vector=None,
                vendor=item.get("vendorProject", "Unknown"),
                product=item.get("product", "Unknown"),
                product_version="",
                description=item.get("shortDescription", ""),
                cwe_ids=cwe_ids,
                is_known_exploited=True,
                is_ransomware_related=known_ransomware,
                is_poc_public=is_rce,  # KEV收录说明有在野利用
                poc_reference="",
                is_rce=is_rce,
                published_date=published_date,
                last_modified=None,
                tags=["known-exploited", "cisa-kev"] + (["ransomware"] if known_ransomware == "Known" else []),
                references=references,
                remediation=item.get("requiredAction", ""),
                remediation_url="",
                due_date=due_date
            )
        except Exception as e:
            print(f"[VulnIntel] CISA解析错误: {e}")
            return None

    # ========== GitHub Security Advisories ==========

    async def _fetch_github_advisory(self, client: httpx.AsyncClient, result: Dict, force: bool) -> None:
        """获取GitHub安全公告"""
        start_time = datetime.now(timezone.utc)
        log_entry = IntelFetchLog(source="github_advisory", status="failed")

        try:
            # 获取最近30天的高/严重漏洞
            since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

            fetched_count = 0
            new_count = 0

            # GitHub API - GHSA (GitHub Security Advisories)
            url = "https://api.github.com/advisories"
            
            # 先试单个严重性，避免422
            async with async_session_maker() as db:
                page = 1
                total_pages = 3
                while page <= total_pages:
                    params = {
                        "type": "reviewed",
                        "severity": "critical",
                        "updated_after": since,
                        "per_page": 50,
                        "page": page
                    }
                    resp = await client.get(
                        url,
                        params=params,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28"
                        },
                        timeout=30.0
                    )

                    if resp.status_code == 403:
                        # Rate limited - 继续用公开数据
                        result["errors"].append("GitHub API rate limited")
                        break
                    if resp.status_code != 200:
                        break

                    advisories = resp.json()
                    if not advisories:
                        break

                    for adv in advisories:
                        fetched_count += 1
                        intel = self._parse_github_advisory(adv)
                        if intel:
                            is_new = await self._upsert_intel(db, intel)
                            if is_new:
                                new_count += 1

                    page += 1

                await db.commit()

            log_entry.status = "success"
            log_entry.items_fetched = fetched_count
            log_entry.new_items = new_count
            result["fetched"] = fetched_count
            result["new"] = new_count

        except Exception as e:
            log_entry.status = "failed"
            log_entry.errors = str(e)[:500]
            result["errors"].append(str(e))
        finally:
            duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            log_entry.duration_ms = duration
            await self._save_fetch_log(log_entry)

    def _parse_github_advisory(self, adv: Dict) -> Optional[VulnIntelItem]:
        """解析GitHub Advisory"""
        try:
            ghsa_id = adv.get("ghsa_id", "")
            cve_id = adv.get("cve_id", "") or ghsa_id

            if not cve_id:
                return None

            # 严重性
            severity = self.SEVERITY_MAP.get(adv.get("severity", ""), "unknown")
            if severity == "unknown":
                severity = "high"

            # CVSS
            cvss_data = adv.get("cvss", {}) or {}
            cvss_score = cvss_data.get("score", None)
            cvss_vector = cvss_data.get("vector_string", None)

            if cvss_score:
                if cvss_score >= 9.0:
                    severity = "critical"
                elif cvss_score >= 7.0:
                    severity = "high"

            # 产品/厂商
            vulnerabilities = adv.get("vulnerabilities", []) or []
            vendor = "Unknown"
            product = "Unknown"
            if vulnerabilities:
                first = vulnerabilities[0]
                vendor = first.get("package", {}).get("ecosystem", "Unknown")
                product = first.get("package", {}).get("name", "Unknown")

            # 描述
            desc = adv.get("description", "")
            is_rce = any(kw in desc.lower() for kw in self.RCE_KEYWORDS)
            is_poc = any(kw in desc.lower() for kw in self.POC_KEYWORDS)

            # 发布时间
            published_date = self._parse_date(adv.get("published_at", ""))
            modified_date = self._parse_date(adv.get("updated_at", ""))

            # 修复版本
            fix_versions = []
            for v in vulnerabilities:
                for fix in v.get("ranges", []) or []:
                    fix_versions.extend(fix.get("events", []) or [])
            fix_version = ", ".join([fv.get("fixed", "") for fv in fix_versions if fv.get("fixed")])[:100]

            references = [{"title": "GitHub Advisory", "url": adv.get("html_url", "")}]

            return VulnIntelItem(
                cve_id=cve_id,
                vulnerability_name=adv.get("summary", cve_id)[:256],
                source="github_advisory",
                source_url=adv.get("html_url", ""),
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                vendor=vendor,
                product=product,
                product_version=fix_version,
                description=desc[:500],
                cwe_ids=[],  # GitHub不直接提供CWE
                is_known_exploited=False,
                is_ransomware_related="Unknown",
                is_poc_public=is_poc,
                poc_reference="",
                is_rce=is_rce,
                published_date=published_date,
                last_modified=modified_date,
                tags=["github-advisory"],
                references=references,
                remediation=f"升级到安全版本: {fix_version}" if fix_version else "查看官方修复建议",
                remediation_url=adv.get("html_url", ""),
                due_date=None
            )
        except Exception as e:
            print(f"[VulnIntel] GitHub Advisory解析错误: {e}")
            return None

    # ========== NVD RSS/JSON ==========

    async def _fetch_nvd_rss(self, client: httpx.AsyncClient, result: Dict, force: bool) -> None:
        """获取NVD最近漏洞"""
        start_time = datetime.now(timezone.utc)
        log_entry = IntelFetchLog(source="nvd_rss", status="failed")

        try:
            # NVD提供JSON格式的最近漏洞（每日更新）
            url = "https://nvd.nist.gov/feeds/json/cve-1.1/nvdcve-1.1-recent.json.zip"
            # 不用zip，用在线API（无需key的查询）
            since = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%d")

            fetched_count = 0
            new_count = 0

            async with async_session_maker() as db:
                # 尝试使用NVD API v2 (需要key但有fallback)
                api_key = await self._get_nvd_api_key()
                headers = {}
                if api_key:
                    headers["apiKey"] = api_key

                # 最近14天的高危漏洞
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0/",
                    params={
                        "pubStartDate": f"{since}T00:00:00.000",
                        "cvssV3Severity": "HIGH,CRITICAL",
                        "resultsPerPage": 100,
                    },
                    headers={**headers, "Accept": "application/json"},
                    timeout=45.0
                )

                if resp.status_code != 200:
                    # Fallback: 用CISA数据作为补充
                    result["errors"].append(f"NVD API响应: {resp.status_code}")
                    await db.commit()
                    return

                data = resp.json()
                items = data.get("vulnerabilities", [])

                for item in items:
                    fetched_count += 1
                    intel = self._parse_nvd_item(item)
                    if intel:
                        is_new = await self._upsert_intel(db, intel)
                        if is_new:
                            new_count += 1

                await db.commit()

            log_entry.status = "success"
            log_entry.items_fetched = fetched_count
            log_entry.new_items = new_count
            result["fetched"] = fetched_count
            result["new"] = new_count

        except Exception as e:
            log_entry.status = "failed"
            log_entry.errors = str(e)[:500]
            result["errors"].append(str(e))
        finally:
            duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            log_entry.duration_ms = duration
            await self._save_fetch_log(log_entry)

    # ========== 长亭漏洞库 (Chaitin) ==========

    async def _fetch_chaitin(self, client: httpx.AsyncClient, result: Dict, force: bool) -> None:
        """获取长亭漏洞库数据 - 公开API"""
        start_time = datetime.now(timezone.utc)
        log_entry = IntelFetchLog(source="chaitin", status="failed")

        try:
            fetched_count = 0
            new_count = 0

            async with async_session_maker() as db:
                # 长亭API分页获取，CT-开头的是长亭自己的漏洞ID
                for page in range(3):  # 最多3页
                    offset = page * 15
                    url = f"https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset={offset}&search=CT-"

                    resp = await client.get(
                        url,
                        headers={
                            "Referer": "https://stack.chaitin.com/vuldb/index",
                            "Origin": "https://stack.chaitin.com",
                            "Accept": "application/json"
                        },
                        timeout=30.0
                    )

                    if resp.status_code != 200:
                        result["errors"].append(f"Chaitin API: {resp.status_code}")
                        break

                    data = resp.json()
                    items = data.get("data", {}).get("list", [])

                    if not items:
                        break

                    for item in items:
                        intel = self._parse_chaitin_item(item)
                        if intel and self._is_valuable_chaitin(intel):
                            fetched_count += 1
                            is_new = await self._upsert_intel(db, intel)
                            if is_new:
                                new_count += 1

                    await db.commit()

            log_entry.status = "success"
            log_entry.items_fetched = fetched_count
            log_entry.new_items = new_count
            result["fetched"] = fetched_count
            result["new"] = new_count

        except Exception as e:
            log_entry.status = "failed"
            log_entry.errors = str(e)[:500]
            result["errors"].append(str(e))
        finally:
            duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            log_entry.duration_ms = duration
            await self._save_fetch_log(log_entry)

    def _parse_chaitin_item(self, item: Dict) -> Optional[VulnIntelItem]:
        """解析长亭漏洞条目"""
        try:
            ct_id = item.get("ct_id", "")
            cve_id = item.get("cve_id", "") or ""
            vuln_id = cve_id if cve_id.startswith("CVE-") else ct_id

            if not vuln_id:
                return None

            # 严重性
            severity_map = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
            severity = severity_map.get(item.get("severity", "").lower(), "medium")

            # CVSS - 长亭不提供CVSS，从描述推断
            cvss_score = None
            if severity == "critical":
                cvss_score = 9.5
            elif severity == "high":
                cvss_score = 7.5

            # 描述
            description = item.get("summary", "")
            is_rce = any(kw in description.lower() for kw in self.RCE_KEYWORDS)

            # 发布时间
            published_date = self._parse_date(item.get("created_at", ""))
            modified_date = self._parse_date(item.get("updated_at", ""))

            # 参考链接
            refs_str = item.get("references", "")
            references = []
            if refs_str:
                for ref in refs_str.split("\n")[:5]:
                    ref = ref.strip()
                    if ref.startswith("http"):
                        references.append({"title": "参考链接", "url": ref})

            return VulnIntelItem(
                cve_id=vuln_id,
                vulnerability_name=item.get("title", vuln_id)[:256],
                source="chaitin",
                source_url=f"https://stack.chaitin.com/vuldb/detail/{item.get('id', '')}",
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=None,
                vendor="Unknown",
                product="Unknown",
                product_version="",
                description=description[:500],
                cwe_ids=[],
                is_known_exploited=False,
                is_ransomware_related="Unknown",
                is_poc_public=False,
                poc_reference="",
                is_rce=is_rce,
                published_date=published_date,
                last_modified=modified_date,
                tags=["chaitin", "长亭漏洞库"],
                references=references,
                remediation="",
                remediation_url=f"https://stack.chaitin.com/vuldb/detail/{item.get('id', '')}",
                due_date=None
            )
        except Exception as e:
            print(f"[VulnIntel] Chaitin解析错误: {e}")
            return None

    def _is_valuable_chaitin(self, intel: VulnIntelItem) -> bool:
        """长亭高价值过滤：必须高危/严重 + 必须有中文标题"""
        if intel.severity not in ("high", "critical"):
            return False
        # 检查是否包含中文字符
        has_chinese = any('\u4e00' <= c <= '\u9fff' for c in intel.vulnerability_name)
        return has_chinese

    # ========== OSCS 开源安全情报 ==========

    async def _fetch_oscs(self, client: httpx.AsyncClient, result: Dict, force: bool) -> None:
        """获取OSCS开源安全情报"""
        start_time = datetime.now(timezone.utc)
        log_entry = IntelFetchLog(source="oscs", status="failed")

        try:
            fetched_count = 0
            new_count = 0

            async with async_session_maker() as db:
                # OSCS list API
                list_url = "https://www.oscs1024.com/oscs/v1/intelligence/list"

                # 先获取总数
                list_body = {"page": 1, "per_page": 10}
                resp = await client.post(
                    list_url,
                    json=list_body,
                    headers={
                        "Referer": "https://www.oscs1024.com/cm",
                        "Origin": "https://www.oscs1024.com",
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    timeout=30.0
                )

                if resp.status_code != 200:
                    result["errors"].append(f"OSCS API: {resp.status_code}")
                    await db.commit()
                    return

                data = resp.json()
                if data.get("code") != 200:
                    result["errors"].append(f"OSCS response: {data.get('info', 'unknown error')}")
                    await db.commit()
                    return

                total = data.get("data", {}).get("total", 0)
                page_count = min((total // 10) + 2, 5)  # 最多5页

                for page in range(1, page_count + 1):
                    list_body = {"page": page, "per_page": 10}
                    resp = await client.post(
                        list_url,
                        json=list_body,
                        headers={
                            "Referer": "https://www.oscs1024.com/cm",
                            "Origin": "https://www.oscs1024.com",
                            "Content-Type": "application/json"
                        },
                        timeout=30.0
                    )

                    if resp.status_code != 200:
                        break

                    data = resp.json()
                    items = data.get("data", {}).get("data", [])

                    if not items:
                        break

                    for item in items:
                        # OSCS必须同时满足：高危/严重 + 有"发布预警"标签
                        intel = await self._parse_oscs_item(client, item)
                        if intel and self._is_valuable_oscs(intel):
                            fetched_count += 1
                            is_new = await self._upsert_intel(db, intel)
                            if is_new:
                                new_count += 1

                    await db.commit()

            log_entry.status = "success"
            log_entry.items_fetched = fetched_count
            log_entry.new_items = new_count
            result["fetched"] = fetched_count
            result["new"] = new_count

        except Exception as e:
            log_entry.status = "failed"
            log_entry.errors = str(e)[:500]
            result["errors"].append(str(e))
        finally:
            duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            log_entry.duration_ms = duration
            await self._save_fetch_log(log_entry)

    async def _parse_oscs_item(self, client: httpx.AsyncClient, item: Dict) -> Optional[VulnIntelItem]:
        """解析OSCS条目（需要单独请求详情）"""
        try:
            mps = item.get("mps", "")  # OSCS漏洞编号
            if not mps:
                return None

            # 获取详情
            detail_url = "https://www.oscs1024.com/oscs/v1/vdb/info"
            detail_resp = await client.post(
                detail_url,
                json={"vuln_no": mps},
                headers={
                    "Referer": "https://www.oscs1024.com/cm",
                    "Origin": "https://www.oscs1024.com",
                    "Content-Type": "application/json"
                },
                timeout=15.0
            )

            cve_id = item.get("cve_id", "") or mps
            level = item.get("level", "Medium")

            # 严重性映射（支持中英文）
            severity_map = {
                "Critical": "critical", "High": "high", "Medium": "medium", "Low": "low",
                "严重": "critical", "高危": "high", "中危": "medium", "低危": "low"
            }
            severity = severity_map.get(level, "medium")

            cvss_score = None
            if severity == "critical":
                cvss_score = 9.8
            elif severity == "high":
                cvss_score = 7.5

            # 标签
            tags = ["oscs", "OSCS开源安全情报"]
            if item.get("is_push") == 1:
                tags.append("发布预警")

            intel_type = item.get("intelligence_type", 1)
            type_map = {1: "公开漏洞", 2: "墨菲安全独家", 3: "投毒情报"}
            tags.append(type_map.get(intel_type, "公开漏洞"))

            # 描述
            description = item.get("description", "") or item.get("title", "")
            is_rce = any(kw in description.lower() for kw in self.RCE_KEYWORDS)

            # 发布时间
            public_time = item.get("public_time")
            if isinstance(public_time, str):
                published_date = self._parse_date(public_time)
            elif isinstance(public_time, (int, float)):
                published_date = datetime.fromtimestamp(public_time / 1000, tz=timezone.utc)
            else:
                published_date = None

            return VulnIntelItem(
                cve_id=cve_id,
                vulnerability_name=item.get("title", cve_id)[:256],
                source="oscs",
                source_url=f"https://www.oscs1024.com/hd/{mps}",
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=None,
                vendor="Unknown",
                product="Unknown",
                product_version="",
                description=description[:500],
                cwe_ids=[],
                is_known_exploited=False,
                is_ransomware_related="Unknown",
                is_poc_public=False,
                poc_reference="",
                is_rce=is_rce,
                published_date=published_date,
                last_modified=None,
                tags=tags,
                references=[{"title": "OSCS", "url": f"https://www.oscs1024.com/hd/{mps}"}],
                remediation="",
                remediation_url=f"https://www.oscs1024.com/hd/{mps}",
                due_date=None
            )
        except Exception as e:
            print(f"[VulnIntel] OSCS解析错误: {e}")
            return None

    def _is_valuable_oscs(self, intel: VulnIntelItem) -> bool:
        """OSCS高价值过滤：必须高危/严重 + 必须有"发布预警"标签"""
        if intel.severity not in ("high", "critical"):
            return False
        return "发布预警" in intel.tags

    # ========== 阿里云漏洞库 (AVD) ==========

    async def _fetch_avd(self, client: httpx.AsyncClient, result: Dict, force: bool) -> None:
        """获取阿里云漏洞库高危漏洞 - 需要WAF绕过"""
        start_time = datetime.now(timezone.utc)
        log_entry = IntelFetchLog(source="avd", status="failed")

        try:
            fetched_count = 0
            new_count = 0

            async with async_session_maker() as db:
                # 阿里云AVD分页获取高危漏洞
                for page in range(1, 4):  # 最多3页
                    list_url = f"https://avd.aliyun.com/high-risk/list?page={page}"

                    resp = await client.get(
                        list_url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"
                        },
                        timeout=30.0
                    )

                    if resp.status_code != 200:
                        result["errors"].append(f"AVD: {resp.status_code}")
                        continue

                    items = self._parse_avd_list_page(resp.text)
                    if not items:
                        break

                    for item in items:
                        intel = await self._fetch_avd_detail(client, item, db)
                        if intel:
                            fetched_count += 1
                            is_new = await self._upsert_intel(db, intel)
                            if is_new:
                                new_count += 1

                    await db.commit()

            log_entry.status = "success"
            log_entry.items_fetched = fetched_count
            log_entry.new_items = new_count
            result["fetched"] = fetched_count
            result["new"] = new_count

        except Exception as e:
            log_entry.status = "failed"
            log_entry.errors = str(e)[:500]
            result["errors"].append(str(e))
        finally:
            duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            log_entry.duration_ms = duration
            await self._save_fetch_log(log_entry)

    def _parse_avd_list_page(self, html: str) -> List[Dict]:
        """解析AVD列表页"""
        items = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            rows = soup.select("tbody > tr")
            for row in rows:
                link = row.select_one("td > a")
                if link and link.get("href"):
                    href = link.get("href", "")
                    # 提取AVD ID
                    import re
                    match = re.search(r"id=([A-Z0-9-]+)", href)
                    if match:
                        avd_id = match.group(1)
                        items.append({"avd_id": avd_id, "url": f"https://avd.aliyun.com/high-risk/detail?id={avd_id}"})
        except Exception as e:
            print(f"[VulnIntel] AVD列表解析错误: {e}")
        return items

    async def _fetch_avd_detail(self, client: httpx.AsyncClient, item: Dict, db) -> Optional[VulnIntelItem]:
        """获取AVD单个漏洞详情"""
        try:
            resp = await client.get(
                item["url"],
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,*/*",
                },
                timeout=20.0
            )

            if resp.status_code != 200:
                return None

            return self._parse_avd_detail(resp.text, item["avd_id"], item["url"])

        except Exception as e:
            print(f"[VulnIntel] AVD详情获取错误: {e}")
            return None

    def _parse_avd_detail(self, html: str, avd_id: str, url: str) -> Optional[VulnIntelItem]:
        """解析AVD详情页"""
        try:
            soup = BeautifulSoup(html, "html.parser")

            # 标题
            title_elem = soup.select_one("h5.header__title .header__title__text")
            title = title_elem.text.strip() if title_elem else avd_id

            # 严重性
            level_badge = soup.select_one("h5.header__title .badge")
            level_text = level_badge.text.strip() if level_badge else ""
            severity_map = {"低危": "low", "中危": "medium", "高危": "high", "严重": "critical"}
            severity = severity_map.get(level_text, "high")

            # CVE ID
            cve_id = ""
            for metric in soup.select("div.metric"):
                label = metric.select_one(".metric-label")
                value = metric.select_one(".metric-value")
                if label and "CVE" in label.text:
                    cve_id = value.text.strip() if value else ""
                    break

            # 利用情况标签
            tags = ["avd", "阿里云漏洞库"]
            for metric in soup.select("div.metric"):
                label = metric.select_one(".metric-label")
                value = metric.select_one(".metric-value")
                if label and "利用情况" in label.text and value:
                    utilization = value.text.strip()
                    if utilization != "暂无":
                        tags.append(utilization)

            # 披露时间
            disclosure = ""
            for metric in soup.select("div.metric"):
                label = metric.select_one(".metric-label")
                value = metric.select_one(".metric-value")
                if label and "披露时间" in label.text:
                    disclosure = value.text.strip() if value else ""
                    break

            # 描述
            description = ""
            for div in soup.select("div[class*='pl-4']"):
                if "漏洞描述" in div.text:
                    desc_div = div.find_next_sibling("div")
                    if desc_div:
                        description = desc_div.text.strip()[:500]
                        break

            # 修复建议
            remediation = ""
            for div in soup.select("div[class*='pl-4']"):
                if "解决建议" in div.text:
                    next_div = div.find_next_sibling("div")
                    if next_div:
                        remediation = next_div.text.strip()[:200]
                        break

            # 判断RCE
            is_rce = any(kw in description.lower() for kw in self.RCE_KEYWORDS)

            # CVSS
            cvss_score = None
            if severity == "critical":
                cvss_score = 9.8
            elif severity == "high":
                cvss_score = 7.5

            return VulnIntelItem(
                cve_id=cve_id if cve_id.startswith("CVE-") else avd_id,
                vulnerability_name=title,
                source="avd",
                source_url=url,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=None,
                vendor="Unknown",
                product="Unknown",
                product_version="",
                description=description,
                cwe_ids=[],
                is_known_exploited="利用中" in tags,
                is_ransomware_related="Unknown",
                is_poc_public="poc" in description.lower() or "poc" in title.lower(),
                poc_reference="",
                is_rce=is_rce,
                published_date=self._parse_date(disclosure),
                last_modified=None,
                tags=tags,
                references=[{"title": "阿里云AVD", "url": url}],
                remediation=remediation,
                remediation_url=url,
                due_date=None
            )
        except Exception as e:
            print(f"[VulnIntel] AVD详情解析错误: {e}")
            return None

    def _parse_nvd_item(self, item: Dict) -> Optional[VulnIntelItem]:
        """解析NVD CVE条目"""
        try:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id.startswith("CVE-"):
                return None

            # CVSS
            metrics = cve.get("metrics", {})
            cvss31 = metrics.get("cvssMetricV31", [])
            cvss30 = metrics.get("cvssMetricV30", [])
            cvss_list = cvss31 or cvss30

            cvss_score = None
            cvss_vector = None
            severity = "high"

            if cvss_list:
                cvss_data = cvss_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0)
                cvss_vector = cvss_data.get("vectorString", "")
                if cvss_score:
                    if cvss_score >= 9.0:
                        severity = "critical"
                    elif cvss_score >= 7.0:
                        severity = "high"
                    else:
                        severity = "medium"

            # 描述
            descriptions = cve.get("descriptions", [])
            desc_en = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            desc_zh = next((d.get("value", "") for d in descriptions if d.get("lang") == "zh"), "")
            description = desc_zh if desc_zh else desc_en

            is_rce = any(kw in description.lower() for kw in self.RCE_KEYWORDS)

            # CWE
            cwe_ids = []
            for rel in cve.get("relationships", []):
                if rel.get("type") == "has weakness":
                    cwe = rel.get("target", {}).get("name", "")
                    if cwe.startswith("CWE-"):
                        cwe_ids.append(cwe)
            cwe_ids = list(set(cwe_ids))[:3]

            # 发布时间
            published_date = self._parse_date(cve.get("published", ""))
            modified_date = self._parse_date(cve.get("lastModified", ""))

            # 参考链接
            references = []
            for ref in cve.get("references", [])[:5]:
                references.append({
                    "title": ref.get("source", "NVD"),
                    "url": ref.get("url", "")
                })

            # 厂商/产品
            vendor = "Unknown"
            product = "Unknown"
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []) or []:
                        parts = match.get("criteria", "").split(":")
                        if len(parts) > 3:
                            vendor = parts[3]
                            product = parts[4]
                            break

            return VulnIntelItem(
                cve_id=cve_id,
                vulnerability_name=description[:128] if description else cve_id,
                source="nvd_rss",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                vendor=vendor,
                product=product,
                product_version="",
                description=description[:500],
                cwe_ids=cwe_ids,
                is_known_exploited=False,
                is_ransomware_related="Unknown",
                is_poc_public=False,
                poc_reference="",
                is_rce=is_rce,
                published_date=published_date,
                last_modified=modified_date,
                tags=["nvd"] + (["rce"] if is_rce else []),
                references=references,
                remediation="",
                remediation_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                due_date=None
            )
        except Exception as e:
            print(f"[VulnIntel] NVD解析错误: {e}")
            return None

    # ========== 辅助方法 ==========

    async def _get_nvd_api_key(self) -> Optional[str]:
        """获取NVD API Key（从环境变量或配置）"""
        import os
        return os.environ.get("NVD_API_KEY")

    def _infer_severity(self, description: str, is_known_exploited: bool = False) -> str:
        """从描述推断严重性"""
        desc = description.lower()
        if is_known_exploited:
            if "remote code execution" in desc or "rce" in desc:
                return "critical"
            return "high"

        if "remote code execution" in desc or "arbitrary code execution" in desc:
            return "critical"
        if "sql injection" in desc or "cross-site scripting" in desc:
            return "high"
        if "denial of service" in desc:
            return "medium"
        return "medium"

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """解析多种日期格式"""
        if not date_str:
            return None
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str[:19], fmt[:len(date_str)])
                return dt.replace(tzinfo=timezone.utc) if "Z" in date_str else dt
            except (ValueError, IndexError):
                continue
        return None

    async def _upsert_intel(self, db, intel: VulnIntelItem) -> bool:
        """插入或更新漏洞情报，返回是否是新插入"""
        # 检查是否已存在
        stmt = select(IntelVuln).where(IntelVuln.cve_id == intel.cve_id)
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            # 更新
            for key in ["severity", "cvss_score", "description", "last_modified",
                        "is_known_exploited", "is_poc_public", "is_rce", "references"]:
                if hasattr(existing, key):
                    setattr(existing, key, getattr(intel, key, None) if getattr(intel, key, None) is not None else getattr(existing, key))

            # 合并来源
            if existing.source and intel.source not in existing.source:
                existing.source = f"{existing.source},{intel.source}"

            existing.last_fetched = datetime.utcnow()
            existing.updated_at = datetime.utcnow()
            return False

        # 新插入（可能有并发冲突，使用try/except处理）
        try:
            db_intel = IntelVuln(
                cve_id=intel.cve_id,
                vulnerability_name=intel.vulnerability_name,
                source=intel.source,
                source_url=intel.source_url,
                severity=intel.severity,
                cvss_score=intel.cvss_score,
                cvss_vector=intel.cvss_vector,
                vendor=intel.vendor,
                product=intel.product,
                product_version=intel.product_version,
                description=intel.description,
                cwe_ids=intel.cwe_ids,
                is_known_exploited=intel.is_known_exploited,
                is_ransomware_related=intel.is_ransomware_related,
                is_poc_public=intel.is_poc_public,
                poc_reference=intel.poc_reference,
                is_rce=intel.is_rce,
                published_date=intel.published_date,
                last_modified=intel.last_modified,
                last_fetched=datetime.utcnow(),
                tags=intel.tags,
                references=intel.references,
                remediation=intel.remediation,
                remediation_url=intel.remediation_url,
                due_date=intel.due_date,
                is_fresh=True
            )
            db.add(db_intel)
            await db.flush()
            return True
        except Exception as e:
            # 并发冲突，该记录已存在，跳过
            if "UNIQUE constraint" in str(e) or "IntegrityError" in str(e):
                return False
            raise

    async def _save_fetch_log(self, log: IntelFetchLog) -> None:
        """保存获取日志"""
        try:
            async with async_session_maker() as db:
                db.add(log)
                await db.commit()
        except Exception as e:
            print(f"[VulnIntel] 保存fetch log失败: {e}")

    async def _refresh_stats(self) -> None:
        """刷新统计信息"""
        try:
            async with async_session_maker() as db:
                from sqlalchemy import func
                stmt = select(
                    func.count(IntelVuln.id),
                    IntelVuln.severity,
                    IntelVuln.source
                ).group_by(IntelVuln.severity, IntelVuln.source)
                result = await db.execute(stmt)
                rows = result.all()

                self._stats = {"total": 0, "by_source": {}, "by_severity": {}}
                for row in rows:
                    count, severity, source = row
                    self._stats["total"] += count
                    self._stats["by_source"][source] = self._stats["by_source"].get(source, 0) + count
                    self._stats["by_severity"][severity] = self._stats["by_severity"].get(severity, 0) + count
        except Exception as e:
            print(f"[VulnIntel] 刷新统计失败: {e}")

    # ========== 查询接口 ==========

    async def get_intel_list(
        self,
        min_severity: str = "high",
        keywords: Optional[List[str]] = None,
        sources: Optional[List[str]] = None,
        is_known_exploited: Optional[bool] = None,
        is_rce: Optional[bool] = None,
        is_poc_public: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict:
        """查询漏洞情报列表"""
        async with async_session_maker() as db:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            min_level = severity_order.get(min_severity, 2)

            stmt = select(IntelVuln).where(IntelVuln.is_active == True)

            # 严重性过滤
            severity_filter = []
            for sev, order in severity_order.items():
                if order >= min_level:
                    severity_filter.append(sev)
            stmt = stmt.where(IntelVuln.severity.in_(severity_filter))

            # 来源过滤
            if sources:
                source_filter = []
                for src in sources:
                    source_filter.append(IntelVuln.source.like(f"%{src}%"))
                if source_filter:
                    from sqlalchemy import or_
                    stmt = stmt.where(or_(*source_filter))

            # 已知被利用过滤
            if is_known_exploited is not None:
                stmt = stmt.where(IntelVuln.is_known_exploited == is_known_exploited)

            # RCE过滤
            if is_rce is not None:
                stmt = stmt.where(IntelVuln.is_rce == is_rce)

            # POC公开过滤
            if is_poc_public is not None:
                stmt = stmt.where(IntelVuln.is_poc_public == is_poc_public)

            # 关键词过滤
            if keywords:
                from sqlalchemy import or_
                keyword_filter = []
                for kw in keywords:
                    pattern = f"%{kw}%"
                    keyword_filter.append(IntelVuln.vulnerability_name.ilike(pattern))
                    keyword_filter.append(IntelVuln.description.ilike(pattern))
                    keyword_filter.append(IntelVuln.product.ilike(pattern))
                    keyword_filter.append(IntelVuln.cve_id.ilike(pattern))
                stmt = stmt.where(or_(*keyword_filter))

            # 总数
            from sqlalchemy import func
            count_stmt = select(func.count()).select_from(stmt.subquery())
            total_result = await db.execute(count_stmt)
            total = total_result.scalar() or 0

            # 如果stats为空，先刷新
            if not self._stats.get("total"):
                await self._refresh_stats()

            # 分页排序
            stmt = stmt.order_by(
                IntelVuln.published_date.desc().nulls_last(),
                IntelVuln.severity
            ).offset(offset).limit(limit)

            result = await db.execute(stmt)
            items = result.scalars().all()

            return {
                "total": total,
                "items": [self._intel_to_dict(item) for item in items],
                "stats": self._stats
            }

    def _intel_to_dict(self, intel: IntelVuln) -> Dict:
        """转换IntelVuln为字典"""
        return {
            "id": intel.id,
            "cve_id": intel.cve_id,
            "vulnerability_name": intel.vulnerability_name,
            "source": intel.source,
            "source_url": intel.source_url,
            "severity": intel.severity,
            "cvss_score": intel.cvss_score,
            "cvss_vector": intel.cvss_vector,
            "vendor": intel.vendor,
            "product": intel.product,
            "product_version": intel.product_version,
            "description": intel.description,
            "cwe_ids": intel.cwe_ids or [],
            "is_known_exploited": intel.is_known_exploited,
            "is_ransomware_related": intel.is_ransomware_related,
            "is_poc_public": intel.is_poc_public,
            "is_rce": intel.is_rce,
            "published_date": intel.published_date.isoformat() if intel.published_date else None,
            "last_modified": intel.last_modified.isoformat() if intel.last_modified else None,
            "last_fetched": intel.last_fetched.isoformat() if intel.last_fetched else None,
            "tags": intel.tags or [],
            "references": intel.references or [],
            "remediation": intel.remediation,
            "remediation_url": intel.remediation_url,
            "due_date": intel.due_date.isoformat() if intel.due_date else None,
        }

    async def get_stats(self) -> Dict:
        """获取统计信息"""
        if not self._stats["total"]:
            await self._refresh_stats()
        return self._stats

    async def get_sources(self) -> List[Dict]:
        """获取来源列表"""
        return [
            {"id": "cisa_kev", "name": "CISA KEV", "name_cn": "CISA 已知被利用漏洞", "description": "美国政府权威已知被利用漏洞目录"},
            {"id": "github_advisory", "name": "GitHub Advisory", "name_cn": "GitHub 安全公告", "description": "全球开源项目安全公告数据库"},
            {"id": "nvd_rss", "name": "NVD", "name_cn": "美国国家漏洞数据库", "description": "美国国家漏洞数据库(NIST)"},
            {"id": "chaitin", "name": "Chaitin VulnDB", "name_cn": "长亭漏洞库", "description": "长亭科技漏洞库，中文高危漏洞"},
            {"id": "oscs", "name": "OSCS", "name_cn": "OSCS开源安全情报", "description": "OSCS开源安全情报预警"},
            {"id": "avd", "name": "Aliyun AVD", "name_cn": "阿里云漏洞库", "description": "阿里云高危漏洞库"},
        ]

    async def mark_expired(self, days: int = 90) -> int:
        """标记过期数据"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        async with async_session_maker() as db:
            from sqlalchemy import update
            stmt = (
                update(IntelVuln)
                .where(IntelVuln.last_fetched < cutoff)
                .values(is_active=False)
            )
            result = await db.execute(stmt)
            await db.commit()
            return result.rowcount


# 单例
_vuln_intel_service: Optional[VulnIntelService] = None


def get_vuln_intel_service() -> VulnIntelService:
    global _vuln_intel_service
    if _vuln_intel_service is None:
        _vuln_intel_service = VulnIntelService()
    return _vuln_intel_service
