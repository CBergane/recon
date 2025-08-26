# Recon (robust) — Automated Bug Bounty Recon Pipeline

A batteries-included recon pipeline that ties together modern open-source tools with sane defaults, guardrails, and clean reporting.

* Passive & active subdomain discovery (wildcard-aware)
* DNS resolution with per-root wildcard filtering
* Optional scope expansion from **ORG/ASN → CIDR**
* Two-phase **port scanning** (fast top-ports, then deep only on hits)
* HTTP probing wired to discovered **ip\:port** + common web ports
* Headless crawling, historical URLs, screenshots
* Nuclei with **template validation** and auto-exclusions
* Markdown + HTML report, plus `out/latest` symlink

> Built around ProjectDiscovery’s ecosystem (`subfinder`, `dnsx`, `naabu`, `httpx`, `katana`, `nuclei`) with a few extra classics (`puredns`, `gau`, `waybackurls`, `gowitness`). httpx uses smart HTTPS→HTTP fallback; naabu performs fast SYN/CONNECT scans; dnsx supports wildcard filtering per domain; katana supports headless/JS crawling; nuclei can validate/exclude templates; ASN scope via `asnmap` + `mapcidr`. ([ProjectDiscovery Dokumentation][1], [GitHub][2])

---

## Contents

* [What this does](#what-this-does)
* [Quick start](#quick-start)
* [Files](#files)
* [Requirements](#requirements)
* [Installation](#installation)
* [Usage](#usage)
* [Configuration](#configuration)
* [Outputs](#outputs)
* [Design choices](#design-choices)
* [Troubleshooting](#troubleshooting)
* [Ethics & legality](#ethics--legality)
* [Credits](#credits)

---

## What this does

1. **Enumerate subdomains** using passive sources (`subfinder`, optionally `assetfinder`, `amass -passive`). Subfinder is built for fast passive subdomain enumeration. ([ProjectDiscovery Dokumentation][3], [GitHub][4], [ProjectDiscovery][5])
2. **Resolve & de-wildcard** with `dnsx` and custom resolvers per root (`-wd <root>`). Wildcard filtering in `dnsx` requires the domain and helps eliminate noise. ([ProjectDiscovery Dokumentation][6])
3. (Optional) **Expand scope** from organization names or ASNs to CIDR ranges via `asnmap` then aggregate/normalize with `mapcidr`. ([ProjectDiscovery][7], [GitHub][2], [pkg.go.dev][8])
4. **Scan ports in two phases** with `naabu`: quick top-ports over all IPs/CIDRs, then full-range only on IPs that had hits—faster and more targeted. Naabu supports fast SYN/CONNECT/UDP modes. ([ProjectDiscovery Dokumentation][9])
5. **Probe HTTP** with `httpx` against (a) subdomains across common web ports and (b) URLs constructed from `ip:port` (guessing https for 443/8443/9443/10443). httpx probes **HTTPS first and falls back to HTTP** by default. ([GitHub][10], [ProjectDiscovery Dokumentation][1])
6. **Crawl** live targets via `katana` (depth-limited, **headless** if Chromium is present) to surface hidden endpoints/params and JS references. ([ProjectDiscovery Dokumentation][11], [GitHub][12], [ProjectDiscovery][13])
7. **Historical URLs** with `gau` & `waybackurls` (Wayback, OTX, CommonCrawl, URLScan). ([pkg.go.dev][14], [GitHub][15])
8. **Screenshots** using `gowitness` (Chrome/Chromium headless). ([GitHub][16])
9. **Nuclei scanning** with template update/validate, auto-exclude broken templates, and optional exclude of `headless` tag if no Chromium. ([ProjectDiscovery Dokumentation][17], [GitHub][18])

---

## Quick start

### 1) Get the files into your repo

* `recon.sh` (the robust pipeline)
* `Makefile` (installer + runners)
* `cloud_init.yaml` (optional: spin up a fresh VPS with everything pre-installed)

> If you pulled them under different names, rename to `recon.sh`, `Makefile`, `cloud_init.yaml`.

### 2) Install & prep

```bash
make install     # installs Go tools + dependencies and updates nuclei-templates
make prepare     # creates input/ and sample files if missing
make envcheck    # verifies tool presence
```

### 3) Run

```bash
# pick a profile based on hardware/network (see Profiles below)
make run PROFILE=vps
```

---

## Files

* `recon.sh` — the pipeline script (timeouts, guardrails, reporting)
* `Makefile` — installer and convenience targets
* `cloud_init.yaml` — user-data for cloud-init that installs everything on a new box
* `input/` — scope and configuration:

  * `domains.txt` (required) — apex domains
  * `resolvers.txt` — your DNS resolvers
  * `asn.txt` — one ASN per line (e.g., `AS13335`)
  * `orgs.txt` — organization names (e.g., `GOOGLE`)

---

## Requirements

* Linux/macOS shell with `bash`, `jq`, `make`, `git`
* Go toolchain in `PATH` (for `go install`-ed tools)
* Chromium/Chrome **recommended** (for katana headless & gowitness) ([ProjectDiscovery Dokumentation][11], [GitHub][16])

### Core tools (installed by `make install`)

* ProjectDiscovery: `subfinder`, `dnsx`, `naabu`, `httpx`, `katana`, `nuclei`, `tlsx`, `asnmap`, `mapcidr`
  (official docs highlight: httpx HTTPS→HTTP fallback; naabu fast SYN/CONNECT; dnsx wildcard filtering; katana depth/JS crawl; nuclei exclude/validate; asnmap+mapcidr scope ops). ([ProjectDiscovery Dokumentation][1], [GitHub][2])
* Extras: `gau`, `waybackurls`, `gowitness`, `puredns` (optional but recommended). Gau/waybackurls fetch historical URLs; gowitness uses Chrome Headless for screenshots; puredns filters wildcards/poisoning with trusted resolvers. ([pkg.go.dev][14], [GitHub][19], [trickest.com][20])

> **Tip (naabu permissions):** for fast SYN scans without running as root, set Linux capabilities:
> `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v naabu)"` ([GitHub][21], [Unix & Linux Stack Exchange][22])

---

## Installation

```bash
# from project root
make install
make prepare
```

`make install` uses `go install` for each tool (as per PD docs, e.g., `go install .../subfinder@latest`). ([ProjectDiscovery Dokumentation][23])

---

## Usage

### Minimal

1. Put your apex domains in `input/domains.txt`.
2. (Optional) Put ASNs in `input/asn.txt` and/or ORG names in `input/orgs.txt`.
3. Run:

```bash
make run PROFILE=vps
```

### Profiles

`PROFILE` tunes rate limits/parallelism for different environments:

* `mobile`, `home`, `office`, `vps` (increasing aggressiveness).

### Skipping heavy steps

You can skip costly phases when you just need a quick pass:

```bash
SKIP_KATANA=1 SKIP_HISTORY=1 SKIP_NUCLEI=1 make run PROFILE=home
```

### Scope filtering for endpoints

Only keep endpoints matching a regex:

```bash
SCOPE_URL_REGEX='(app\.example\.com|cdn\.example\.com)' make run PROFILE=vps
```

---

## Configuration (env vars)

* **TOP\_PORTS** (default `100`) — naabu Phase-A quick sweep
* **DEEP\_PORTS** (default `1-65535`) — Phase-B full sweep on hits
* **NAABU\_RATE** — packets/sec for naabu (varies by profile)
* **HTTPX\_RL / HTTPX\_C** — rate limit & concurrency for httpx
* **KATANA\_C** — katana concurrency (auto-scaled to CPU by default)
* **GAU\_OPTS** — customize historical providers (`wayback,otx,commoncrawl,urlscan`) ([Kali Linux][24])
* **SKIP\_ASN / SKIP\_KATANA / SKIP\_HISTORY / SKIP\_NUCLEI / SKIP\_SCREEN** — toggle modules
* **SCOPE\_URL\_REGEX** — post-filter for discovered endpoints

> DNS brute-force (`puredns`) obeys `--rate-limit` and `--rate-limit-trusted`. Trusted resolvers and rate tuning can reduce stalls/poisoning and speed wildcard validation. ([GitHub][25])

---

## Outputs

Each run writes to `out/YYYYMMDD-HHMMSS/` and a convenience symlink `out/latest/`.

* `subdomains.txt` — de-wildcarded, resolvable subdomains
* `ips.txt` — IPs from DNS A records
* `cidrs.txt` — scope expanded from ASNs/ORGs (if provided)
* `open_ports_A.json` / `open_ports_B.json` / `open_ports.json` — naabu results (JSON)
* `open_ports.txt` — `ip:port` list
* `httpx_*.json` / `http_services.txt` — live HTTP endpoints
* `katana.txt` — crawled endpoints (depth-limited)
* `historical_endpoints.txt` — gau/waybackurls merged history
* `screenshots/` — gowitness PNGs + `index.txt`
* `nuclei_findings.txt` — Nuclei results (quiet mode)
* `report.md` / `report.html` — human-readable summary

---

## Design choices

* **Two-phase port scanning** dramatically reduces scan time while keeping coverage: fast top-ports → deep only on real hosts. (Naabu supports SYN/CONNECT/UDP and is designed for speed.) ([ProjectDiscovery Dokumentation][9])
* **httpx on both domains and ip\:port** avoids blind spots; by default it tries HTTPS first and falls back to HTTP, which mirrors real-world services. ([GitHub][10], [ProjectDiscovery Dokumentation][1])
* **Wildcard-aware DNS** via dnsx `-wd` per root to reduce false positives from wildcard DNS. ([ProjectDiscovery Dokumentation][6])
* **Headless crawling** only when Chromium is available; otherwise katana still crawls without a browser. Depth, time, and JS parsing flags are kept conservative. ([ProjectDiscovery Dokumentation][11])
* **Template hygiene**: nuclei updates & validates templates; broken ones are excluded; optionally excludes `headless` when no Chromium. ([ProjectDiscovery Dokumentation][17])
* **Historical sources**: gau/waybackurls aggregate Wayback, OTX, CommonCrawl (and URLScan in gau), which routinely surfaces parameters and dead links worth retesting. ([pkg.go.dev][14], [GitHub][19])

---

## Troubleshooting

* **Naabu is slow / no SYN**
  Ensure capabilities are set so it can do SYN scanning without root:
  `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v naabu)"` ([GitHub][21])

* **dnsx wildcard filtering**
  Use `-wd <root>` to enable wildcard elimination (required for correct filtering). ([ProjectDiscovery Dokumentation][6])

* **httpx shows only HTTP or only HTTPS**
  httpx normally tries HTTPS then falls back to HTTP. You can use `-no-fallback` to see both results separately. ([GitHub][10])

* **Katana headless fails**
  Make sure Chromium/Chrome is installed and accessible; katana supports passing a system Chrome and headless options. ([GitHub][12])

* **GAU command conflict**
  If you use oh-my-zsh, the `gau` alias might collide with “git add --update”; see repo notes. Use full path or rename. ([GitHub][15])

* **puredns stalls on trusted validation**
  Provide a dedicated `resolvers-trusted.txt` and tune `--rate-limit-trusted`. ([GitHub][25])

---

## Cloud init (optional)

Drop `cloud_init.yaml` into your provider’s user-data to bootstrap a fresh box. It sets up Go paths, installs tools, and prepares the `recon` workspace. Then SSH in and run:

```bash
cd ~/recon/<repo> && make envcheck && make run PROFILE=vps
```

---

## Ethics & legality

Only scan assets **you have permission to test** (e.g., a bug bounty scope). Respect rate limits and provider policies.

---

## Credits

* **ProjectDiscovery** tools: subfinder, dnsx, naabu, httpx, katana, nuclei, asnmap, mapcidr (docs & blogs). ([ProjectDiscovery Dokumentation][26], [GitHub][2])
* **Historical URL tooling**: `gau` and `waybackurls`. ([pkg.go.dev][14], [GitHub][19])
* **Screenshots**: `gowitness` (Chrome Headless). ([GitHub][16])
* **Wildcard/poisoning-aware DNS brute**: `puredns`. ([trickest.com][20])

---

## License

MIT (or your preference) — add a LICENSE file if you plan to publish.

---

### Appendix: Key references

* httpx overview & fallback behavior. ([ProjectDiscovery Dokumentation][1], [GitHub][10])
* Naabu overview & scanning modes; Linux capabilities for SYN. ([ProjectDiscovery Dokumentation][9], [GitHub][21])
* dnsx wildcard filtering requirements. ([ProjectDiscovery Dokumentation][6])
* Katana usage (depth, JS crawl, crawl duration, headless flags). ([ProjectDiscovery Dokumentation][11], [GitHub][12])
* Nuclei running (exclude templates/tags). ([ProjectDiscovery Dokumentation][17])
* ASN scope (`asnmap` + `mapcidr`). ([GitHub][2], [ProjectDiscovery][7])
* GAU & waybackurls (historical URLs). ([pkg.go.dev][14], [GitHub][19])
* Gowitness & Chrome Headless. ([GitHub][16])

---
