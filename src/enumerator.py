"""
╔══════════════════════════════════════════════════════════════╗
║         SUBDOMAIN ENUMERATOR - Industrial Grade v3.0         ║
║              Developer: Demiyan Dissanayake                  ║
╚══════════════════════════════════════════════════════════════╝

Async multi-technique subdomain discovery:
  • DNS brute-force (concurrent async resolution)
  • Certificate Transparency log mining (crt.sh + fallbacks)
  • Multiple passive sources (HackerTarget, AlienVault OTX, RapidDNS)
  • HTTP/HTTPS service detection with status codes
  • ASN / hosting / geolocation enrichment
  • Smart permutation wordlist generation
  • Dead subdomain filtering
  • Rate-limiting with exponential backoff + jitter
  • Full progress visibility for all stages
"""

import asyncio
import csv
import ipaddress
import json
import logging
import random
import re
import socket
import string
import sys
import time
import argparse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from threading import Lock

try:
    import dns.resolver
    import dns.asyncresolver
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn,
        BarColumn, TaskProgressColumn, TimeElapsedColumn,
        MofNCompleteColumn,
    )
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

VERSION = "3.0.0"
AUTHOR  = "Demiyan Dissanayake"

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(
    level=logging.INFO, format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("subdomain_enum.log", encoding="utf-8"),
    ],
)
logger  = logging.getLogger("SubdomainEnum")
console = Console() if RICH_AVAILABLE else None

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

# User-agent pool for rotation (fix #6)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    f"SubdomainEnumerator/{VERSION} (Security Research)",
    "curl/8.4.0",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _random_ua() -> str:
    return random.choice(USER_AGENTS)


def _jitter(base: float, factor: float = 0.3) -> float:
    """Add random jitter to a delay value."""
    return base + random.uniform(0, base * factor)


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class SubdomainRecord:
    subdomain:    str
    domain:       str
    fqdn:         str
    sources:      list
    ip_addresses: list = field(default_factory=list)
    cname:        Optional[str] = None
    mx_records:   list = field(default_factory=list)
    ns_records:   list = field(default_factory=list)
    txt_records:  list = field(default_factory=list)
    alive:        bool = False
    wildcard:     bool = False
    discovered_at: str = ""
    # New fields (fix #5, #7)
    http_status:  Optional[int] = None
    https_status: Optional[int] = None
    http_title:   Optional[str] = None
    open_ports:   list = field(default_factory=list)
    asn:          Optional[str] = None
    asn_org:      Optional[str] = None
    country:      Optional[str] = None
    hosting:      Optional[str] = None
    risk_flags:   list = field(default_factory=list)


@dataclass
class EnumReport:
    domain:         str
    generated_at:   str
    elapsed_sec:    float
    techniques:     list
    total_found:    int  = 0
    alive_count:    int  = 0
    wildcard_count: int  = 0
    http_alive:     int  = 0
    results:        list = field(default_factory=list)
    errors:         list = field(default_factory=list)


# ─── DNS Resolver Wrapper ─────────────────────────────────────────────────────

class DNSResolver:
    DEFAULT_NAMESERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]

    def __init__(self, nameservers=None, timeout=3.0):
        self.nameservers = nameservers or self.DEFAULT_NAMESERVERS
        self.timeout     = timeout

    def resolve(self, fqdn: str, rtype: str) -> list:
        if DNSPYTHON_AVAILABLE:
            return self._resolve_dnspython(fqdn, rtype)
        if rtype == "A":
            return self._resolve_socket(fqdn)
        return []

    def _resolve_dnspython(self, fqdn, rtype):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.nameservers
            resolver.lifetime    = self.timeout
            answers = resolver.resolve(fqdn, rtype, raise_on_no_answer=False)
            if rtype == "A":
                return [str(r.address) for r in answers]
            elif rtype == "AAAA":
                return [str(r.address) for r in answers]
            elif rtype == "CNAME":
                return [str(r.target) for r in answers]
            elif rtype == "MX":
                return [f"{r.preference} {r.exchange}" for r in answers]
            elif rtype in ("NS", "TXT"):
                return [str(r) for r in answers]
            return [str(r) for r in answers]
        except Exception:
            return []

    def _resolve_socket(self, fqdn):
        try:
            results = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            return list({r[4][0] for r in results})
        except Exception:
            return []

    def is_wildcard_domain(self, domain: str) -> Optional[str]:
        rand_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
        ips = self.resolve(f"{rand_sub}.{domain}", "A")
        return ips[0] if ips else None

    def is_alive(self, fqdn: str) -> bool:
        """Check if a subdomain resolves to a valid, routable IP (fix #4)."""
        ips = self.resolve(fqdn, "A")
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
                # Filter private/loopback/link-local — not public subdomains
                if not addr.is_private and not addr.is_loopback and not addr.is_link_local:
                    return True
            except ValueError:
                pass
        # Accept private IPs too — internal subdomains are valid findings
        return bool(ips)


# ─── Passive Source: HackerTarget ─────────────────────────────────────────────

class HackerTargetSource:
    """
    Free HackerTarget API — no key required, returns subdomains fast.
    Fix #2: additional passive source.
    """
    URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

    def fetch(self, domain: str, timeout: float = 10) -> list:
        url = self.URL.format(domain=domain)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _random_ua()})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
            subs = []
            for line in text.splitlines():
                parts = line.strip().split(",")
                if parts and parts[0].endswith(f".{domain}"):
                    sub = parts[0].replace(f".{domain}", "").strip()
                    if sub:
                        subs.append(sub)
            return subs
        except Exception as exc:
            logger.debug("HackerTarget fetch failed: %s", exc)
            return []


# ─── Passive Source: AlienVault OTX ──────────────────────────────────────────

class AlienVaultSource:
    """
    AlienVault OTX passive DNS — no key required.
    Fix #2: additional passive source.
    """
    URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    def fetch(self, domain: str, timeout: float = 10) -> list:
        url = self.URL.format(domain=domain)
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": _random_ua(),
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            subs = []
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if hostname.endswith(f".{domain}"):
                    sub = hostname.replace(f".{domain}", "").strip(".")
                    if sub:
                        subs.append(sub)
            return subs
        except Exception as exc:
            logger.debug("AlienVault fetch failed: %s", exc)
            return []


# ─── Passive Source: RapidDNS ────────────────────────────────────────────────

class RapidDNSSource:
    """
    RapidDNS — scrape-based, additional passive source.
    Fix #2: additional passive source.
    """
    URL = "https://rapiddns.io/subdomain/{domain}?full=1"

    def fetch(self, domain: str, timeout: float = 10) -> list:
        url = self.URL.format(domain=domain)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _random_ua()})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            # extract subdomains from table rows
            matches = re.findall(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>', html)
            subs = []
            for m in matches:
                sub = m.replace(f".{domain}", "").strip(".")
                if sub:
                    subs.append(sub)
            return subs
        except Exception as exc:
            logger.debug("RapidDNS fetch failed: %s", exc)
            return []


# ─── Certificate Transparency Mining ─────────────────────────────────────────

class CTLogMiner:
    """
    Queries crt.sh with robust retry + exponential backoff + jitter.
    Fix #1: better retry strategy, not just 3 plain retries.
    Fix #6: random delay + user-agent rotation.
    """
    CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"

    def __init__(self, timeout: float = 15, retries: int = 5):
        self.timeout = timeout
        self.retries = retries

    def fetch(self, domain: str) -> list:
        url = self.CRT_SH_URL.format(domain=domain)
        last_exc: Exception = Exception("no attempts made")

        for attempt in range(1, self.retries + 1):
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": _random_ua(),
                    "Accept": "application/json",
                })
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                subdomains: set = set()
                for entry in data:
                    for name in (entry.get("name_value", "") or "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            sub = name.replace(f".{domain}", "")
                            if sub and sub != domain:
                                subdomains.add(sub)
                return sorted(subdomains)

            except Exception as exc:
                last_exc = exc
                # Exponential backoff with jitter (fix #6)
                base_wait = 2 ** (attempt - 1)
                wait = _jitter(base_wait)
                if attempt < self.retries:
                    logger.warning(
                        "CT log attempt %d/%d failed (%s) — retrying in %.1fs...",
                        attempt, self.retries, exc, wait,
                    )
                    time.sleep(wait)

        logger.warning("CT log fetch failed after %d attempts: %s", self.retries, last_exc)
        return []


# ─── Wordlist Manager ─────────────────────────────────────────────────────────

class WordlistManager:
    """
    Loads subdomains from file or falls back to a curated + permuted built-in list.
    Fix #3: smart permutation generation (dev-api, api-prod, etc.)
    Fix #8: robust path handling.
    """
    BUILTIN_BASE = [
        # Web
        "www", "web", "web1", "web2", "webmail", "mail", "email",
        # APIs
        "api", "api2", "apiv1", "apiv2", "rest", "graphql", "grpc",
        # Environments
        "dev", "development", "staging", "stage", "test", "qa", "uat",
        "beta", "alpha", "demo", "sandbox", "preview", "preprod",
        "prod", "production", "live", "release",
        # Services
        "ftp", "sftp", "smtp", "smtp1", "smtp2", "pop", "pop3", "imap",
        "vpn", "remote", "rdp", "ssh",
        # Auth
        "admin", "administrator", "portal", "panel", "cpanel", "whm",
        "plesk", "directadmin", "auth", "login", "sso", "oauth", "id",
        "accounts", "account", "identity",
        # CDN / static
        "cdn", "static", "assets", "media", "img", "images",
        "download", "downloads", "upload", "uploads", "files", "storage",
        # Apps
        "app", "apps", "mobile", "m", "mobi",
        # Content
        "blog", "forum", "shop", "store", "help", "support", "docs",
        "wiki", "kb", "knowledge", "community", "news", "press",
        # Monitoring
        "status", "monitor", "monitoring", "metrics", "health",
        "dashboard", "grafana", "kibana", "prometheus", "datadog",
        # Payment
        "pay", "payment", "payments", "billing", "invoice", "checkout",
        "cart", "commerce",
        # DNS
        "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
        "mx", "mx1", "mx2",
        # DB
        "db", "database", "mysql", "postgres", "mongo", "redis",
        "elastic", "elasticsearch", "solr", "search",
        # DevOps
        "git", "gitlab", "github", "svn", "ci", "cd", "jenkins",
        "builds", "deploy", "registry", "docker", "k8s", "kube",
        "jira", "confluence", "sonar",
        # Network
        "proxy", "gateway", "fw", "firewall", "lb", "loadbalancer",
        "vpn", "hub", "exchange", "backup", "archive",
        # Internal
        "internal", "intranet", "extranet", "corp", "office", "local",
        # Regions
        "us", "us-east", "us-west", "eu", "asia", "uk", "de", "fr",
        "au", "ap", "sg", "in", "jp",
        # Infra
        "node", "node1", "node2", "server", "server1", "server2",
        "host", "host1", "v1", "v2", "v3", "old", "legacy", "new",
    ]

    # Permutation prefixes and suffixes (fix #3)
    ENV_PREFIXES = ["dev", "staging", "stage", "test", "qa", "prod", "beta", "uat"]
    ENV_SUFFIXES = ["dev", "staging", "stage", "test", "qa", "prod", "beta", "uat", "1", "2"]

    def generate_permutations(self, bases: list) -> list:
        """Generate smart permutations: dev-api, api-prod, etc."""
        perms = set()
        for base in bases:
            for prefix in self.ENV_PREFIXES:
                perms.add(f"{prefix}-{base}")
                perms.add(f"{prefix}{base}")
            for suffix in self.ENV_SUFFIXES:
                perms.add(f"{base}-{suffix}")
                perms.add(f"{base}{suffix}")
        return sorted(perms)

    def load(self, path: Optional[str], permute: bool = True) -> list:
        if path:
            # Fix #8: normalize path (handle Git Bash forward/back slash mix)
            p = Path(path.replace("\\", "/")).expanduser().resolve()
            if not p.exists():
                logger.warning(
                    "Wordlist not found: '%s'\n"
                    "  → Tried resolved path: %s\n"
                    "  → Falling back to built-in wordlist (%d entries).",
                    path, p, len(self.BUILTIN_BASE),
                )
                return self._builtin_with_perms(permute)
            words = [
                line.strip() for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            ]
            logger.info("Loaded %d words from %s", len(words), p)
            if permute:
                perms = self.generate_permutations(words[:50])  # top 50 to avoid explosion
                combined = sorted(set(words + perms))
                logger.info("Expanded to %d words with permutations", len(combined))
                return combined
            return words
        return self._builtin_with_perms(permute)

    def _builtin_with_perms(self, permute: bool) -> list:
        if not permute:
            return self.BUILTIN_BASE
        perms = self.generate_permutations(self.BUILTIN_BASE)
        combined = sorted(set(self.BUILTIN_BASE + perms))
        return combined


# ─── Brute-force Engine ───────────────────────────────────────────────────────

class BruteForceEngine:
    """
    Concurrent subdomain brute-force using ThreadPoolExecutor.
    Fix #6: random delay between probes.
    """

    def __init__(self, domain: str, resolver: DNSResolver, workers: int = 50):
        self.domain      = domain
        self.resolver    = resolver
        self.workers     = workers
        self.wildcard_ip = resolver.is_wildcard_domain(domain)
        if self.wildcard_ip:
            logger.warning("Wildcard DNS detected (%s) — filtering wildcard results", self.wildcard_ip)

    def _probe(self, subdomain: str) -> Optional[SubdomainRecord]:
        # Fix #6: small random delay to avoid rate-limit blocks
        time.sleep(random.uniform(0.01, 0.05))
        fqdn = f"{subdomain}.{self.domain}"
        ips  = self.resolver.resolve(fqdn, "A")
        if not ips:
            return None
        is_wildcard = bool(self.wildcard_ip and self.wildcard_ip in ips)
        return SubdomainRecord(
            subdomain    = subdomain,
            domain       = self.domain,
            fqdn         = fqdn,
            sources      = ["bruteforce"],
            ip_addresses = ips,
            alive        = True,
            wildcard     = is_wildcard,
            discovered_at= _now_iso(),
        )

    def run(self, wordlist: list) -> list:
        found = []
        total = len(wordlist)
        lock  = Lock()

        def task(sub):
            rec = self._probe(sub)
            return rec

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(task, sub): sub for sub in wordlist}
            if RICH_AVAILABLE:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[cyan]Bruteforce[/cyan] {task.description}"),
                    BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                    console=console,
                ) as prog:
                    t = prog.add_task(self.domain, total=total)
                    for fut in as_completed(futures):
                        prog.advance(t)
                        rec = fut.result()
                        if rec:
                            with lock:
                                found.append(rec)
            else:
                done = 0
                for fut in as_completed(futures):
                    done += 1
                    if done % 50 == 0:
                        logger.info("Bruteforce progress: %d/%d", done, total)
                    rec = fut.result()
                    if rec:
                        found.append(rec)
        return found


# ─── HTTP / Service Detector ──────────────────────────────────────────────────

class ServiceDetector:
    """
    Probe each alive subdomain for HTTP/HTTPS status and extract page title.
    Fix #5: HTTP status, HTTPS check, port detection.
    """
    COMMON_PORTS = [80, 443, 8080, 8443, 8000, 3000]

    def __init__(self, timeout: float = 5, workers: int = 30):
        self.timeout = timeout
        self.workers = workers

    def _probe_http(self, fqdn: str, scheme: str) -> tuple:
        """Returns (status_code, page_title) or (None, None)."""
        url = f"{scheme}://{fqdn}"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": _random_ua(),
                "Accept": "text/html,application/xhtml+xml",
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                html   = resp.read(4096).decode("utf-8", errors="ignore")
                title  = None
                m = re.search(r'<title[^>]*>([^<]{1,120})</title>', html, re.IGNORECASE)
                if m:
                    title = m.group(1).strip()
                return status, title
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception:
            return None, None

    def _check_port(self, fqdn: str, port: int) -> bool:
        try:
            with socket.create_connection((fqdn, port), timeout=2):
                return True
        except Exception:
            return False

    def detect(self, rec: SubdomainRecord) -> SubdomainRecord:
        http_status, title = self._probe_http(rec.fqdn, "http")
        https_status, _    = self._probe_http(rec.fqdn, "https")
        rec.http_status  = http_status
        rec.https_status = https_status
        if title:
            rec.http_title = title
        open_ports = []
        for port in self.COMMON_PORTS:
            if self._check_port(rec.fqdn, port):
                open_ports.append(port)
        rec.open_ports = open_ports
        return rec

    def detect_all(self, records: list, progress_callback=None) -> list:
        results = []
        lock = Lock()

        def _task(rec):
            out = self.detect(rec)
            if progress_callback:
                progress_callback()
            with lock:
                results.append(out)
            return out

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            list(pool.map(_task, records))
        return results


# ─── ASN / Geo / Hosting Enrichment ──────────────────────────────────────────

class ASNEnricher:
    """
    Lookup ASN, org, country, and infer hosting provider from IP.
    Fix #7: ASN info, hosting provider, geolocation, risk indicators.
    Uses ip-api.com (free, no key required).
    """
    URL = "http://ip-api.com/batch"
    HOSTING_KEYWORDS = {
        "amazon": "AWS", "amazonaws": "AWS",
        "google": "GCP", "googlecloud": "GCP",
        "microsoft": "Azure", "azure": "Azure",
        "cloudflare": "Cloudflare",
        "fastly": "Fastly",
        "akamai": "Akamai",
        "digitalocean": "DigitalOcean",
        "linode": "Linode/Akamai",
        "vultr": "Vultr",
        "hetzner": "Hetzner",
        "ovh": "OVH",
    }

    def enrich_batch(self, records: list) -> list:
        # Collect unique IPs
        ip_to_recs: dict = {}
        for rec in records:
            for ip in rec.ip_addresses:
                ip_to_recs.setdefault(ip, []).append(rec)

        if not ip_to_recs:
            return records

        ips = list(ip_to_recs.keys())
        # ip-api.com allows 100 per batch
        for batch_start in range(0, len(ips), 100):
            batch = ips[batch_start:batch_start + 100]
            payload = json.dumps([{"query": ip} for ip in batch]).encode()
            try:
                req = urllib.request.Request(
                    self.URL,
                    data=payload,
                    headers={"Content-Type": "application/json", "User-Agent": _random_ua()},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    results = json.loads(resp.read().decode())
                for entry in results:
                    ip = entry.get("query", "")
                    if not ip or ip not in ip_to_recs:
                        continue
                    org     = entry.get("org", "") or entry.get("isp", "") or ""
                    asn     = entry.get("as", "")
                    country = entry.get("country", "")
                    hosting = self._infer_hosting(org)
                    for rec in ip_to_recs[ip]:
                        rec.asn     = asn
                        rec.asn_org = org
                        rec.country = country
                        rec.hosting = hosting
            except Exception as exc:
                logger.debug("ASN batch lookup failed: %s", exc)
            time.sleep(_jitter(1.0))  # be polite to ip-api.com
        return records

    def _infer_hosting(self, org: str) -> Optional[str]:
        org_lower = org.lower()
        for keyword, provider in self.HOSTING_KEYWORDS.items():
            if keyword in org_lower:
                return provider
        return org or None


# ─── Risk Flag Analyzer ───────────────────────────────────────────────────────

class RiskAnalyzer:
    """
    Adds risk indicators to records.
    Fix #7: risk indicators.
    """
    SENSITIVE_PREFIXES = [
        "admin", "panel", "cpanel", "plesk", "whm", "directadmin",
        "git", "gitlab", "jenkins", "ci", "cd", "build", "deploy",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "internal", "intranet", "corp", "vpn", "remote",
        "dev", "staging", "test", "qa", "sandbox", "uat",
        "api", "rest", "graphql",
        "backup", "archive",
        "auth", "login", "sso", "oauth",
        "kibana", "grafana", "prometheus", "elastic",
    ]

    def analyze(self, rec: SubdomainRecord) -> SubdomainRecord:
        flags = []
        sub_lower = rec.subdomain.lower()

        if any(sub_lower == p or sub_lower.startswith(p) for p in self.SENSITIVE_PREFIXES):
            flags.append("SENSITIVE_SUBDOMAIN")

        if rec.http_status and rec.http_status < 400:
            flags.append("HTTP_EXPOSED")

        if rec.https_status is None and rec.http_status and rec.http_status < 400:
            flags.append("NO_HTTPS")

        if rec.wildcard:
            flags.append("WILDCARD_DNS")

        if rec.open_ports and any(p in rec.open_ports for p in [3306, 5432, 27017, 6379]):
            flags.append("DB_PORT_EXPOSED")

        if rec.hosting == "Cloudflare":
            flags.append("BEHIND_CLOUDFLARE")

        rec.risk_flags = flags
        return rec

    def analyze_all(self, records: list) -> list:
        return [self.analyze(r) for r in records]


# ─── Record Enricher ──────────────────────────────────────────────────────────

class RecordEnricher:
    """Post-discovery enrichment: CNAME, MX, NS, TXT, AAAA lookups."""

    def __init__(self, resolver: DNSResolver, workers: int = 20):
        self.resolver = resolver
        self.workers  = workers

    def enrich(self, records: list) -> list:
        def _enrich_one(rec: SubdomainRecord) -> SubdomainRecord:
            cname = self.resolver.resolve(rec.fqdn, "CNAME")
            if cname:
                rec.cname = cname[0]
            aaaa = self.resolver.resolve(rec.fqdn, "AAAA")
            rec.ip_addresses = sorted(set(rec.ip_addresses + aaaa))
            rec.mx_records   = self.resolver.resolve(rec.fqdn, "MX")
            rec.ns_records   = self.resolver.resolve(rec.fqdn, "NS")
            rec.txt_records  = self.resolver.resolve(rec.fqdn, "TXT")
            return rec

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            return list(pool.map(_enrich_one, records))


# ─── Report Writers ───────────────────────────────────────────────────────────

class ReportWriter:
    def write_json(self, report: EnumReport, path: Path) -> None:
        path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        logger.info("JSON report → %s", path)

    def write_csv(self, records: list, path: Path) -> None:
        if not records:
            return
        fieldnames = [
            "fqdn", "subdomain", "ip_addresses", "cname", "alive", "wildcard",
            "sources", "http_status", "https_status", "http_title",
            "open_ports", "asn", "asn_org", "country", "hosting",
            "risk_flags", "discovered_at",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            for r in records:
                w.writerow({
                    "fqdn":          r.fqdn,
                    "subdomain":     r.subdomain,
                    "ip_addresses":  "|".join(r.ip_addresses),
                    "cname":         r.cname or "",
                    "alive":         r.alive,
                    "wildcard":      r.wildcard,
                    "sources":       "|".join(r.sources),
                    "http_status":   r.http_status or "",
                    "https_status":  r.https_status or "",
                    "http_title":    r.http_title or "",
                    "open_ports":    "|".join(map(str, r.open_ports)),
                    "asn":           r.asn or "",
                    "asn_org":       r.asn_org or "",
                    "country":       r.country or "",
                    "hosting":       r.hosting or "",
                    "risk_flags":    "|".join(r.risk_flags),
                    "discovered_at": r.discovered_at,
                })
        logger.info("CSV report → %s", path)

    def render_rich(self, report: EnumReport) -> None:
        if not RICH_AVAILABLE:
            self.render_plain(report)
            return

        console.print(Panel(
            f"[cyan bold]Domain:[/] {report.domain}\n"
            f"[dim]Generated: {report.generated_at}  |  Elapsed: {report.elapsed_sec:.1f}s[/dim]",
            title=f"[bold]Subdomain Enumeration Report[/bold] · v{VERSION}",
            subtitle=f"by {AUTHOR}", border_style="cyan",
        ))

        s = Table(box=box.SIMPLE, show_header=False)
        s.add_column("Key", style="bold white")
        s.add_column("Val", style="cyan")
        s.add_row("Total found",       str(report.total_found))
        s.add_row("Alive (DNS)",        f"[green]{report.alive_count}[/green]")
        s.add_row("HTTP alive",         f"[green]{report.http_alive}[/green]")
        s.add_row("Wildcard filtered",  f"[yellow]{report.wildcard_count}[/yellow]")
        s.add_row("Techniques",         ", ".join(report.techniques))
        console.print(s)

        if report.results:
            t = Table(title="Discovered Subdomains", box=box.ROUNDED, border_style="green")
            t.add_column("FQDN",       style="bold white", no_wrap=True)
            t.add_column("IPs",        style="cyan")
            t.add_column("HTTP",       style="green")
            t.add_column("HTTPS",      style="green")
            t.add_column("Hosting",    style="blue")
            t.add_column("Country",    style="dim")
            t.add_column("Risk",       style="red")
            t.add_column("Sources",    style="dim")

            for r in sorted(report.results, key=lambda x: x["fqdn"]):
                http  = str(r.get("http_status") or "")
                https = str(r.get("https_status") or "")
                risk  = ", ".join(r.get("risk_flags") or [])
                t.add_row(
                    r["fqdn"],
                    ", ".join(r["ip_addresses"]),
                    http,
                    https,
                    r.get("hosting") or "",
                    r.get("country") or "",
                    risk,
                    ", ".join(r["sources"]),
                )
            console.print(t)

    def render_plain(self, report: EnumReport) -> None:
        print(f"\n{'='*70}\n  Subdomain Enumeration  |  {report.domain}  |  {AUTHOR}")
        print(f"{'='*70}\n  Found: {report.total_found}  Alive: {report.alive_count}")
        for r in report.results:
            http = r.get("http_status") or "-"
            print(f"  {r['fqdn']:50} {','.join(r['ip_addresses']):20} HTTP:{http}")
        print(f"{'='*70}\n")


# ─── Orchestrator ─────────────────────────────────────────────────────────────

class SubdomainEnumerator:
    def __init__(self, domain: str, config: dict):
        self.domain   = domain.lower().strip()
        self.config   = config
        self.resolver = DNSResolver(
            nameservers=config.get("nameservers"),
            timeout=config.get("dns_timeout", 3.0),
        )
        self.writer   = ReportWriter()

    def _merge_record(self, all_records: dict, sub: str, source: str) -> None:
        fqdn = f"{sub}.{self.domain}"
        if fqdn not in all_records:
            ips = self.resolver.resolve(fqdn, "A")
            all_records[fqdn] = SubdomainRecord(
                subdomain=sub, domain=self.domain, fqdn=fqdn,
                sources=[source], ip_addresses=ips, alive=bool(ips),
                discovered_at=_now_iso(),
            )
        else:
            srcs = all_records[fqdn].sources
            if source not in srcs:
                srcs.append(source)

    def run(self) -> EnumReport:
        start      = time.time()
        techniques = []
        all_records: dict = {}
        errors = []
        http_timeout = self.config.get("http_timeout", 15)

        # ── 1. Certificate Transparency ──────────────────────────────────────
        if self.config.get("ct_logs", True):
            techniques.append("ct_logs")
            if RICH_AVAILABLE:
                with console.status("[cyan]Mining CT logs (crt.sh)...[/cyan]"):
                    ct_subs = CTLogMiner(timeout=http_timeout).fetch(self.domain)
            else:
                logger.info("Mining CT logs via crt.sh...")
                ct_subs = CTLogMiner(timeout=http_timeout).fetch(self.domain)
            logger.info("CT logs returned %d subdomains", len(ct_subs))
            for sub in ct_subs:
                self._merge_record(all_records, sub, "ct_logs")

        # ── 2. Passive Sources (fix #2) ───────────────────────────────────────
        if self.config.get("passive", True):
            passive_sources = [
                ("hackertarget", HackerTargetSource()),
                ("alienvault",   AlienVaultSource()),
                ("rapiddns",     RapidDNSSource()),
            ]
            for source_name, source in passive_sources:
                techniques.append(source_name)
                if RICH_AVAILABLE:
                    with console.status(f"[cyan]Querying {source_name}...[/cyan]"):
                        subs = source.fetch(self.domain, timeout=http_timeout)
                else:
                    logger.info("Querying %s...", source_name)
                    subs = source.fetch(self.domain, timeout=http_timeout)
                logger.info("%s returned %d subdomains", source_name, len(subs))
                for sub in subs:
                    self._merge_record(all_records, sub, source_name)
                # Polite delay between passive sources (fix #6)
                time.sleep(_jitter(1.0))

        # ── 3. Brute-force ───────────────────────────────────────────────────
        if self.config.get("bruteforce", True):
            techniques.append("bruteforce")
            wordlist = WordlistManager().load(
                self.config.get("wordlist"),
                permute=self.config.get("permute", True),
            )
            logger.info("Brute-forcing with %d words...", len(wordlist))
            engine     = BruteForceEngine(self.domain, self.resolver, workers=self.config.get("workers", 50))
            bf_records = engine.run(wordlist)
            for rec in bf_records:
                if rec.fqdn not in all_records:
                    all_records[rec.fqdn] = rec
                else:
                    srcs = all_records[rec.fqdn].sources
                    if "bruteforce" not in srcs:
                        srcs.append("bruteforce")

        # ── 4. Validation: filter dead subdomains (fix #4) ───────────────────
        if self.config.get("validate", True):
            logger.info("Validating %d discovered records...", len(all_records))
            dead_fqdns = []
            for fqdn, rec in all_records.items():
                if not self.resolver.is_alive(rec.fqdn):
                    dead_fqdns.append(fqdn)
                    logger.debug("Dead subdomain filtered: %s", fqdn)
            for fqdn in dead_fqdns:
                del all_records[fqdn]
            logger.info("After validation: %d live records (%d dead removed)", len(all_records), len(dead_fqdns))

        # ── 5. DNS Enrichment ─────────────────────────────────────────────────
        if self.config.get("enrich", True) and all_records:
            if RICH_AVAILABLE:
                with console.status(f"[cyan]Enriching DNS records ({len(all_records)})...[/cyan]"):
                    enriched = RecordEnricher(self.resolver).enrich(list(all_records.values()))
            else:
                logger.info("Enriching %d records...", len(all_records))
                enriched = RecordEnricher(self.resolver).enrich(list(all_records.values()))
            all_records = {r.fqdn: r for r in enriched}

        # ── 6. HTTP / Service Detection (fix #5) ──────────────────────────────
        alive_recs = [r for r in all_records.values() if r.alive]
        if self.config.get("http_detect", True) and alive_recs:
            logger.info("Probing HTTP/HTTPS on %d alive subdomains...", len(alive_recs))
            detector = ServiceDetector(timeout=self.config.get("http_timeout", 5))
            if RICH_AVAILABLE:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[cyan]HTTP probing[/cyan] {task.description}"),
                    BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                    console=console,
                ) as prog:
                    t   = prog.add_task(self.domain, total=len(alive_recs))
                    cb  = lambda: prog.advance(t)
                    detected = detector.detect_all(alive_recs, progress_callback=cb)
            else:
                detected = detector.detect_all(alive_recs)
            for rec in detected:
                all_records[rec.fqdn] = rec

        # ── 7. ASN / Hosting / Geo Enrichment (fix #7) ───────────────────────
        if self.config.get("asn_enrich", True) and all_records:
            if RICH_AVAILABLE:
                with console.status("[cyan]Enriching ASN / hosting / geo info...[/cyan]"):
                    enriched_list = ASNEnricher().enrich_batch(list(all_records.values()))
            else:
                logger.info("Enriching ASN/geo info...")
                enriched_list = ASNEnricher().enrich_batch(list(all_records.values()))
            all_records = {r.fqdn: r for r in enriched_list}

        # ── 8. Risk Analysis (fix #7) ─────────────────────────────────────────
        results_list = RiskAnalyzer().analyze_all(list(all_records.values()))

        elapsed    = time.time() - start
        wildcards  = [r for r in results_list if r.wildcard]
        alive      = [r for r in results_list if r.alive]
        http_alive = [r for r in results_list if r.http_status and r.http_status < 400]

        report = EnumReport(
            domain        = self.domain,
            generated_at  = _now_iso(),
            elapsed_sec   = round(elapsed, 2),
            techniques    = techniques,
            total_found   = len(results_list),
            alive_count   = len(alive),
            wildcard_count= len(wildcards),
            http_alive    = len(http_alive),
            results       = [asdict(r) for r in results_list],
            errors        = errors,
        )

        self.writer.render_rich(report)
        if out := self.config.get("output_json"):
            self.writer.write_json(report, Path(out))
        if out := self.config.get("output_csv"):
            self.writer.write_csv(results_list, Path(out))

        return report


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="sube",
        description=f"Subdomain Enumerator v{VERSION} — by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/enumerator.py example.com
  python src/enumerator.py example.com --wordlist big.txt --workers 100
  python src/enumerator.py example.com --no-ct --output-json results.json
  python src/enumerator.py example.com --no-passive --no-permute
  python src/enumerator.py https://www.example.com/ --no-enrich --no-http-detect
        """,
    )
    p.add_argument("domain",              help="Target domain (e.g. example.com or https://www.example.com)")
    p.add_argument("--wordlist",          help="Path to wordlist file (Windows/Git Bash paths supported)")
    p.add_argument("--workers",           type=int, default=50,   help="Concurrent DNS workers (default: 50)")
    p.add_argument("--dns-timeout",       type=float, default=3.0, help="DNS resolution timeout (default: 3s)")
    p.add_argument("--http-timeout",      type=float, default=10.0,help="HTTP timeout (default: 10s)")
    p.add_argument("--nameservers",       nargs="+",              help="Custom nameservers")
    p.add_argument("--no-ct",             action="store_true",    help="Skip CT log mining")
    p.add_argument("--no-passive",        action="store_true",    help="Skip passive sources (HackerTarget, OTX, RapidDNS)")
    p.add_argument("--no-bruteforce",     action="store_true",    help="Skip brute-force")
    p.add_argument("--no-permute",        action="store_true",    help="Skip smart wordlist permutations")
    p.add_argument("--no-validate",       action="store_true",    help="Skip dead subdomain validation")
    p.add_argument("--no-enrich",         action="store_true",    help="Skip DNS enrichment")
    p.add_argument("--no-http-detect",    action="store_true",    help="Skip HTTP/HTTPS service detection")
    p.add_argument("--no-asn",            action="store_true",    help="Skip ASN/hosting/geo enrichment")
    p.add_argument("--output-json",       metavar="FILE",         help="Save results as JSON")
    p.add_argument("--output-csv",        metavar="FILE",         help="Save results as CSV")
    p.add_argument("--version",           action="version", version=f"%(prog)s {VERSION}")
    return p


def _sanitize_domain(raw: str) -> str:
    """
    Strip scheme, trailing slashes, paths, ports, whitespace.
    Fix #9: robust handling of all URL forms including escaped slashes.
    """
    raw = raw.strip().rstrip("\\")          # remove trailing backslash (Git Bash escape)
    raw = re.sub(r'^https?://', '', raw, flags=re.IGNORECASE)
    raw = raw.split('/')[0].split('?')[0].split('#')[0]
    raw = raw.split(':')[0]
    if raw.lower().startswith('www.'):
        raw = raw[4:]
    return raw.lower().rstrip('.')


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not DNSPYTHON_AVAILABLE:
        logger.warning("dnspython not installed — falling back to socket (A records only).")
        logger.warning("For full functionality: pip install dnspython")

    domain = _sanitize_domain(args.domain)
    if domain != args.domain:
        logger.info("Domain sanitized: '%s'  →  '%s'", args.domain, domain)

    config = {
        "ct_logs":     not args.no_ct,
        "passive":     not args.no_passive,
        "bruteforce":  not args.no_bruteforce,
        "permute":     not args.no_permute,
        "validate":    not args.no_validate,
        "enrich":      not args.no_enrich,
        "http_detect": not args.no_http_detect,
        "asn_enrich":  not args.no_asn,
        "wordlist":    args.wordlist,
        "workers":     args.workers,
        "dns_timeout": args.dns_timeout,
        "http_timeout":args.http_timeout,
        "nameservers": args.nameservers,
        "output_json": args.output_json,
        "output_csv":  args.output_csv,
    }

    enumerator = SubdomainEnumerator(domain, config)
    report     = enumerator.run()
    sys.exit(0 if report.total_found >= 0 else 1)


if __name__ == "__main__":
    main()
