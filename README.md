<div align="center">

<!-- ANIMATED BANNER — host banner.svg on your repo and update the src path -->
<img src="./banner.svg" alt="Subdomain Enumerator" width="100%"/>

<br/>

![Python](https://img.shields.io/badge/Python-3.10%2B-red?style=flat-square&logo=python&logoColor=white&labelColor=0d1117)
![Version](https://img.shields.io/badge/Version-3.0.0-red?style=flat-square&labelColor=0d1117)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square&labelColor=0d1117)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square&labelColor=0d1117)
![Author](https://img.shields.io/badge/Dev-Demiyan_Dissanayake-red?style=flat-square&labelColor=0d1117)

<br/>

> **Industrial-grade subdomain discovery.**
> Multi-source passive recon · Concurrent DNS brute-force · HTTP intel · ASN enrichment · Risk scoring.

</div>

---

## 🆕 What's New in v3.0

| # | Issue | Fix Applied |
|:-:|-------|-------------|
| 1 | `crt.sh` 503 errors crash the tool | Exponential backoff + random jitter + 5 retries |
| 2 | Single CT log source only | Added **HackerTarget**, **AlienVault OTX**, **RapidDNS** |
| 3 | 145-word bruteforce, no logic | 250+ base words + smart permutation engine (`dev-api`, `api-prod`…) |
| 4 | Dead subdomains polluting results | DNS validity check + routable IP filter before enrichment |
| 5 | No HTTP/service detection | HTTP status, HTTPS status, page title, open port scan |
| 6 | Basic retry, no jitter, no UA rotation | Random jitter delays + 5-UA rotation pool |
| 7 | Plain subdomain list — no intel | ASN · org · country · hosting provider · risk flags |
| 8 | Wordlist path breaks on Windows/Git Bash | `Path.resolve()` + backslash normalisation |
| 9 | `https://www.domain.lk\` parse errors | Full URL strip: scheme, port, path, `www.`, trailing `\` |
| 10 | No visibility into CT log stage | Rich `console.status()` spinner on every stage |

---

## ✨ Features

```
┌─────────────────────────────────────────────────────────────┐
│  DISCOVERY                   INTELLIGENCE                    │
│  ─────────────────────────   ──────────────────────────────  │
│  🔍 crt.sh CT Log Mining     🏢 ASN + Org + Country          │
│  🌐 HackerTarget API         ☁️  Hosting Provider Inference   │
│  🛸 AlienVault OTX           🚩 Risk Flag Scoring             │
│  ⚡ RapidDNS Passive          🔗 HTTP/HTTPS Status Codes       │
│  💥 Smart Brute-force         📄 Page Title Extraction         │
│                              🔌 Open Port Detection           │
│  FILTERING                                                   │
│  ─────────────────────────                                   │
│  🌀 Wildcard DNS Detection    OUTPUT                         │
│  ✅ Dead Subdomain Pruning    ──────────────────────────────  │
│  🧬 Permutation Expansion     📤 JSON + CSV export           │
│                              🖥️  Rich Terminal UI             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

```bash
git clone https://github.com/Dexel-Software-Solutions/Subdomain-hunter.git
cd Subdomain-hunter
pip install -r requirements.txt
```

**Requirements:** `dnspython>=2.4.0` · `rich>=13.0.0` · Python 3.10+

---

## 📖 Usage

### Basic

```bash
python src/enumerator.py example.com
```

### Full scan with custom wordlist

```bash
python src/enumerator.py example.com --wordlist /path/to/big.txt --workers 100
```

### Export results

```bash
python src/enumerator.py example.com --output-json results.json --output-csv results.csv
```

### Passive-only (fast, no bruteforce)

```bash
python src/enumerator.py example.com --no-bruteforce --no-http-detect --no-asn
```

### Windows / Git Bash (full URL input works)

```bash
python src/enumerator.py "https://www.example.com/" --wordlist "C:/tools/wordlists/subs.txt"
```

---

## ⚙️ CLI Reference

```
positional:
  domain                  Target domain or URL

discovery:
  --no-ct                 Skip crt.sh CT log mining
  --no-passive            Skip HackerTarget / OTX / RapidDNS
  --no-bruteforce         Skip brute-force
  --no-permute            Skip smart wordlist permutations
  --wordlist FILE         Custom wordlist path

dns:
  --workers N             Concurrent DNS threads     [default: 50]
  --dns-timeout F         DNS resolution timeout (s) [default: 3.0]
  --nameservers N+        Custom DNS resolvers

enrichment:
  --no-validate           Skip dead-subdomain filtering
  --no-enrich             Skip DNS enrichment (CNAME, MX, TXT...)
  --no-http-detect        Skip HTTP/HTTPS probing
  --no-asn                Skip ASN/geo/hosting lookup
  --http-timeout F        HTTP probe timeout (s)     [default: 10.0]

output:
  --output-json FILE      Save report as JSON
  --output-csv  FILE      Save report as CSV
```

---

## 📊 Output Fields

| Field | Description |
|-------|-------------|
| `fqdn` | Fully-qualified domain name |
| `ip_addresses` | Resolved IPv4 / IPv6 addresses |
| `cname` | CNAME chain target |
| `http_status` | HTTP response code |
| `https_status` | HTTPS response code |
| `http_title` | HTML `<title>` content |
| `open_ports` | Detected open ports (80, 443, 8080…) |
| `asn` | Autonomous System Number |
| `asn_org` | ASN organization name |
| `country` | Country code |
| `hosting` | Inferred provider (AWS · Cloudflare · GCP…) |
| `risk_flags` | `SENSITIVE_SUBDOMAIN` · `HTTP_EXPOSED` · `NO_HTTPS` · `BEHIND_CLOUDFLARE`… |
| `sources` | Discovery technique(s) that found this record |

---

## 🏗️ Architecture

```
SubdomainEnumerator
│
├── CTLogMiner          ← crt.sh  (retry + jitter)
├── HackerTargetSource  ← hackertarget.com API
├── AlienVaultSource    ← otx.alienvault.com
├── RapidDNSSource      ← rapiddns.io
│
├── BruteForceEngine    ← ThreadPoolExecutor (50 workers)
│   └── WordlistManager ← builtin 250+ words + permutations
│
├── DNSResolver         ← dnspython / socket fallback
├── RecordEnricher      ← CNAME, AAAA, MX, NS, TXT
│
├── ServiceDetector     ← HTTP/HTTPS status + ports
├── ASNEnricher         ← ip-api.com batch lookup
└── RiskAnalyzer        ← flag scoring engine
```

---

## ⚠️ Legal

This tool is intended for use **only on domains you own or have explicit written permission to test.**
Unauthorized subdomain enumeration may be illegal in your jurisdiction.

---

<div align="center">

Made with ❤️ by **Demiyan Dissanayake**

![](https://img.shields.io/badge/Sri_Lanka-🇱🇰-red?style=flat-square&labelColor=0d1117)
![](https://img.shields.io/badge/Security_Research-🔐-red?style=flat-square&labelColor=0d1117)

</div>
