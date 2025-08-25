### `README.sv.md`

# recon-pipeline

Snabb, robust och repeterbar recon-pipeline för bug bounty / attackytkartläggning.  
Bygger artefakter per körning, tar skärmdumpar, kör valfritt Nuclei och genererar **rapport i Markdown och HTML**.

## Innehåll

- [Funktioner](#funktioner)
- [Krav](#krav)
- [Installation](#installation)
- [Förberedelser](#förberedelser)
- [Snabbstart](#snabbstart)
- [Profiler](#profiler)
- [Inputfiler](#inputfiler)
- [Output & rapport](#output--rapport)
- [Flaggor & miljövariabler](#flaggor--miljövariabler)
- [Arbetsflöde (rekommenderat)](#arbetsflöde-rekommenderat)
- [Tips](#tips)
- [Felsökning](#felsökning)
- [Juridik](#juridik)
- [Cheatsheet](#cheatsheet)

---

## Funktioner

- Passiv & aktiv subdomäninsamling (subfinder, amass, assetfinder, puredns, dnsgen/shuffledns)
- **Wildcard-DNS-detektion** med valfri exkludering av wildcard-IP
- DNS-upplösning → IP (v4/v6), **ASN/CIDR allow/deny**, blacklist
- **Naabu portscan** (inkrementell: cachar redan skannade IP)
- **TLS cert scraping (tlsx)** → fler subdomäner (CN/SAN), auto-merge in-scope
- httpx fingerprinting (status, titel, tech, server), historik (gau/waybackurls)
- Katana-crawl (valfritt), **gowitness-skärmdumpar** (valfritt)
- **Per-körningens outputmapp** `out/YYYYmmdd-HHMMSS/` + symlink `out.latest`
- **Rapporter**: `report.md` och `report.html` (Pandoc om finns, annars inbyggd HTML)

---

## Krav

- Debian/Ubuntu/Kali med `apt`
- Go 1.20+ rekommenderas

## Installation

```bash
make install
````

Installerar systempaket (inkl. `libpcap-dev` till naabu) och Go-verktyg:
subfinder, dnsx, naabu, httpx, shuffledns, asnmap, mapcidr, katana, nuclei,
gau, waybackurls, gowitness, assetfinder, puredns, samt `pandoc` för HTML-rapport.

> **Obs:** `make install` försöker ge `naabu` raw-sockets via `setcap` (om möjligt).

## Förberedelser

```bash
make prepare
```

Skapar struktur `~/recon/<projekt>/{input,raw,out}` och fyller på `input/` med basfiler.

## Snabbstart

```bash
# Standard: "home"-profil
make run

# VPS-profil (aggressivare rate limits)
make run PROFILE=vps

# Generera enbart rapport från senaste körningen (ingen ny scanning)
make report
make report-open    # öppnar HTML-rapport (Linux desktop)
```

## Profiler

`PROFILE=mobile|home|office|vps` styr rate limits och timeouts:

* **mobile** – försiktig / låg påverkan
* **home** – standard
* **office** – snabbare
* **vps** – aggressiv (för server/box med bra nät)

## Inputfiler

`input/` (skapas av `make prepare`):

* `domains.txt` – apex, `*.exempel.com` (normaliseras), eller `exempel.*` (kräver `tlds.txt`)
* `tlds.txt` – suffix för att expandera `exempel.*` (stödjer multi-label som `co.uk`)
* `resolvers.txt` – DNS-resolvers (en per rad)
* `ips.txt` / `cidrs.txt` – valfria extra mål
* `asns.txt` – valfri allowlist (en ASN per rad)
* `blacklist_ips.txt` / `blacklist_cidrs.txt` – valfri denylist

## Output & rapport

Varje körning skriver till **egen mapp**:

```
out/
  2025xxxx-XXXXXX/   ← artefakter för körningen
  out.latest -> out/2025xxxx-XXXXXX  (symlink till senaste körningen)
```

Nyckelfiler:

* `subdomains.txt`
* `resolved.txt`
* `ips_in_scope.txt`
* `open_ports.json`, `open_ports.txt`, `ip_port_pairs.csv`, `ip_port_hosts.csv`, `ports_by_ip.txt`
* `services_httpx.json`, `services_httpx.txt`, `urls_httpx.txt`
* `historical_endpoints.txt`, `katana_endpoints.txt`
* `subs_from_certs.in_scope.txt` (från **tlsx**)
* `nuclei_findings.txt` (om kört)
* `screenshots/` (om gowitness kört)
* **Rapporter**: `report.md` och `report.html`

> **Snabb rapportsnurr:** `make report` bygger om `report.md/html` från **befintliga** artefakter i `out.latest/`.

## Flaggor & miljövariabler

Kör direkt:

```bash
./recon.sh -p vps --from 1 --to 13
```

Eller via `make` (skickar vidare `PROFILE`, m.m.).

Vanliga variabler:

* `PROFILE=mobile|home|office|vps`
* `WORDLIST=/path/to/dns-wordlist.txt`
* `DRY_RUN=1` – visa plan, kör inget
* `INCREMENTAL=1` – portscan skannar bara **nya** IP (cache i `out/state/`)
* `WILDCARD_EXCLUDE=1` – filtrera bort IP som bara uppstår via wildcard-DNS
* `GW_LIMIT=200` – max antal URL\:er för skärmdumpar
* `REPORT_ONLY=1` – bygg **endast** rapport (ingen scanning)

Stegintervall:

* `--from <N> --to <M>` – kör en delmängd (se “UI / steg” i skriptet)

Skippa delar:

* `SKIP_BRUTE=1`, `SKIP_PORTSCAN=1`, `SKIP_KATANA=1`, `SKIP_NUCLEI=1`

## Arbetsflöde (rekommenderat)

1. `make prepare` → fyll `input/domains.txt` med dina mål.

2. `make run PROFILE=vps` (eller `home` lokalt).

3. Följ loggen i `out/<run>/run.log` eller direkt i terminalen.

4. När klart: öppna `out/<run>/report.html` eller kör `make report-open`.

5. Prioritera:

   * `nuclei_findings.txt` (börja med high/critical)
   * `ip_port_hosts.csv` (intressanta portar + hostnames)
   * `services_httpx.txt` (titlar/teknologier)
   * `historical_endpoints.txt` + `katana_endpoints.txt`
   * Skärmdumpar i `screenshots/`

6. Behöver ny rapport utan ny scanning? → `make report`.

## Tips

* **Subfinder API-nycklar**: lägg i `~/.config/subfinder/provider-config.yaml` för bättre träff.
* **Resolvers**: bra resolvers → snabbare/stabilare `dnsx`/`puredns`.
* **ASN allowlist** (`input/asns.txt`): krymp skanningsyta till ”dina” nät.
* **Blacklist**: exkludera tredjeparts-CDN eller shared hosting via `blacklist_*`.
* **tlsx**: CN/SAN från 443/8443 hittar ofta guldkorn till subdomäner.
* **Nuclei**: trimma tags/severity efter behov (t.ex. `-severity high,critical`).
* **Katana djup**: default 3—höj försiktigt (volymen exploderar).

## Felsökning

**`pcap.h: No such file or directory` vid `go install naabu`**
→ `sudo apt install -y libpcap-dev pkg-config` och kör `make install` igen.

**`naabu` kräver sudo / permission denied**
→ `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v naabu)"`.

**`gowitness` krånglar (headless)**
→ Säkerställ `chromium` och `fonts-liberation` (hanteras i `make install`).

**`pandoc` saknas / ingen HTML-rapport**
→ Skriptet har enkel HTML-fallback. Installera `pandoc` för snyggare HTML.

**Stora mål (tusentals apex)**
→ Använd `PROFILE=vps`, `--from/--to`, `INCREMENTAL=1` och `WILDCARD_EXCLUDE=1`.
→ Hoppa över bekräftelsen med `--yes`.

**DNS-timeouts / långsam körning**
→ Byt/trimm `resolvers.txt`, eller välj lägre profil (t.ex. `home`).

## Juridik

Kör endast mot **tillåtna** mål inom programmens scope. Du ansvarar själv för all användning.

---

## Cheatsheet

```bash
# Full körning (home)
make run

# Aggressivt (VPS), hela kedjan
make run PROFILE=vps

# Bara rapport från senaste körningen
make report
make report-open

# Endast steg 1–6 (t.ex. fram till portscan)
PROFILE=home ./recon.sh --from 1 --to 6

# Snabb körning: skippa tunga steg
SKIP_BRUTE=1 SKIP_PORTSCAN=1 ./recon.sh -p home

# Inkrementell portscan + wildcard-filter
INCREMENTAL=1 WILDCARD_EXCLUDE=1 make run PROFILE=vps
```


