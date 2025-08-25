
---

### `README.md`


# recon-pipeline

Fast, robust, and repeatable recon pipeline for bug bounty / attack surface mapping.  
Generates per-run artifacts, takes screenshots, optionally runs Nuclei, and produces **reports in Markdown and HTML**.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Preparation](#preparation)
- [Quickstart](#quickstart)
- [Profiles](#profiles)
- [Input Files](#input-files)
- [Output & Reports](#output--reports)
- [Flags & Environment Variables](#flags--environment-variables)
- [Recommended Workflow](#recommended-workflow)
- [Tips](#tips)
- [Troubleshooting](#troubleshooting)
- [Legal](#legal)
- [Cheatsheet](#cheatsheet)

---

## Features

- Passive & active subdomain discovery (subfinder, amass, assetfinder, puredns, dnsgen/shuffledns)
- **Wildcard DNS detection** with optional exclusion of wildcard IPs
- DNS resolve → IP (v4/v6), **ASN/CIDR allow/deny**, blacklists
- **Naabu port scan** (incremental: caches already scanned IPs)
- **TLS cert scraping (tlsx)** → more subdomains (CN/SAN), auto-merge in-scope
- httpx fingerprinting (status, titles, tech, server), history (gau/waybackurls)
- Katana crawling (optional), **gowitness screenshots** (optional)
- **Per-run output directory** `out/YYYYmmdd-HHMMSS/` + symlink `out.latest`
- **Reports**: `report.md` and `report.html` (Pandoc if available, otherwise a built-in HTML)

---

## Requirements

- Debian/Ubuntu/Kali base with `apt`
- Go 1.20+ recommended

## Installation

```bash
make install
````

This installs system packages (including `libpcap-dev` for naabu) and Go tools:
subfinder, dnsx, naabu, httpx, shuffledns, asnmap, mapcidr, katana, nuclei,
gau, waybackurls, gowitness, assetfinder, puredns, and `pandoc` for HTML report.

> **Note:** `make install` attempts `setcap` on `naabu` to enable raw sockets without sudo (if available).

## Preparation

```bash
make prepare
```

Creates structure `~/recon/<project>/{input,raw,out}` and seeds the `input/` basics.

## Quickstart

```bash
# Default: "home" profile
make run

# VPS profile (more aggressive rate limits)
make run PROFILE=vps

# Only (re)build report from the latest run (no new scanning)
make report
make report-open    # open the HTML report (Linux desktop)
```

## Profiles

`PROFILE=mobile|home|office|vps` tunes rate limits and timeouts:

* **mobile** – conservative / minimal impact
* **home** – default
* **office** – faster
* **vps** – aggressive (for servers with good connectivity)

## Input Files

`input/` (created by `make prepare`):

* `domains.txt` – apex, `*.example.com` (normalized), or `example.*` (needs `tlds.txt`)
* `tlds.txt` – suffixes to expand `example.*` (supports multi-label like `co.uk`)
* `resolvers.txt` – DNS resolvers (one per line)
* `ips.txt` / `cidrs.txt` – optional extra targets
* `asns.txt` – optional allowlist (one ASN per line)
* `blacklist_ips.txt` / `blacklist_cidrs.txt` – optional denylist

## Output & Reports

Each run writes to its **own directory**:

```
out/
  2025xxxx-XXXXXX/   ← artifacts for that run
  out.latest -> out/2025xxxx-XXXXXX  (symlink to the latest run)
```

Key files:

* `subdomains.txt`
* `resolved.txt`
* `ips_in_scope.txt`
* `open_ports.json`, `open_ports.txt`, `ip_port_pairs.csv`, `ip_port_hosts.csv`, `ports_by_ip.txt`
* `services_httpx.json`, `services_httpx.txt`, `urls_httpx.txt`
* `historical_endpoints.txt`, `katana_endpoints.txt`
* `subs_from_certs.in_scope.txt` (from **tlsx**)
* `nuclei_findings.txt` (if run)
* `screenshots/` (if gowitness ran)
* **Reports**: `report.md` and `report.html`

> **Quick reporting:** `make report` rebuilds `report.md/html` from **existing** artifacts in `out.latest/`.

## Flags & Environment Variables

Run directly:

```bash
./recon.sh -p vps --from 1 --to 13
```

Or via `make` (passes `PROFILE`, etc).

Common variables:

* `PROFILE=mobile|home|office|vps`
* `WORDLIST=/path/to/dns-wordlist.txt`
* `DRY_RUN=1` – show the plan, run nothing
* `INCREMENTAL=1` – port scan only **new** IPs (cache in `out/state/`)
* `WILDCARD_EXCLUDE=1` – filter IPs seen only via wildcard DNS
* `GW_LIMIT=200` – max URLs for screenshots
* `REPORT_ONLY=1` – build **only** the report (no scanning)

Step range:

* `--from <N> --to <M>` – run a subset of the chain (see “UI / steps” in the script)

Skip parts:

* `SKIP_BRUTE=1`, `SKIP_PORTSCAN=1`, `SKIP_KATANA=1`, `SKIP_NUCLEI=1`

## Recommended Workflow

1. `make prepare` → edit `input/domains.txt` with your targets.

2. `make run PROFILE=vps` (or `home` locally).

3. Watch progress in `out/<run>/run.log` or in your terminal.

4. Once done: open `out/<run>/report.html` or run `make report-open`.

5. Triage focus:

   * `nuclei_findings.txt` (high/critical first)
   * `ip_port_hosts.csv` (interesting ports + hostnames)
   * `services_httpx.txt` (titles/tech)
   * `historical_endpoints.txt` + `katana_endpoints.txt`
   * Screenshots in `screenshots/`

6. Need a fresh report without re-scanning? → `make report`.

## Tips

* **Subfinder API keys**: put them in `~/.config/subfinder/provider-config.yaml` to improve results.
* **Resolvers**: better resolvers → faster/stable `dnsx`/`puredns`.
* **ASN allowlist** (`input/asns.txt`): reduce the scan surface to “your” networks.
* **Blacklist**: exclude third-party CDNs or shared hosting via `blacklist_*`.
* **tlsx**: scraping CN/SAN from 443/8443 often finds gold subdomains.
* **Nuclei**: tune tags/severity to your needs (e.g., `-severity high,critical`).
* **Katana depth**: default 3—raise with care (volume explodes).

## Troubleshooting

**`pcap.h: No such file or directory` during `go install naabu`**
→ `sudo apt install -y libpcap-dev pkg-config` then `make install` again.

**`naabu` requires sudo / permission denied**
→ `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v naabu)"`.

**`gowitness` fails (headless)**
→ Ensure `chromium` and `fonts-liberation` are installed (`make install` handles it).

**`pandoc` missing / no HTML report**
→ The script has a simple HTML fallback. Install `pandoc` for nicer HTML.

**Huge scopes (thousands of apex)**
→ Use `PROFILE=vps`, `--from/--to`, `INCREMENTAL=1`, and `WILDCARD_EXCLUDE=1`.
→ Skip confirmation with `--yes`.

**DNS timeouts / long runs**
→ Adjust `resolvers.txt`, or pick a lower profile (e.g., `home`).

## Legal

Only run against **authorized** targets within program scope. You are responsible for all usage.

---

## Cheatsheet

```bash
# Full run (home)
make run

# Aggressive (VPS), full chain
make run PROFILE=vps

# Report-only from latest run
make report
make report-open

# Only steps 1–6 (e.g., through port scan)
PROFILE=home ./recon.sh --from 1 --to 6

# Quick pass: skip heavy steps
SKIP_BRUTE=1 SKIP_PORTSCAN=1 ./recon.sh -p home

# Incremental port scan + wildcard filtering
INCREMENTAL=1 WILDCARD_EXCLUDE=1 make run PROFILE=vps
```

---
