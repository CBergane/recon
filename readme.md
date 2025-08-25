# recon-pipeline

Snabb, robust och repeterbar recon-pipeline för bug bounty / attackytkartläggning.
Bygger per-körning-artefakter, tar skärmdumpar, kör frivillig Nuclei och genererar **rapport i både Markdown och HTML**.

## Innehåll

* [Funktioner](#funktioner)
* [Krav](#krav)
* [Installation](#installation)
* [Förberedelser](#förberedelser)
* [Snabbstart](#snabbstart)
* [Profiler](#profiler)
* [Inputfiler](#inputfiler)
* [Output & rapport](#output--rapport)
* [Flaggor & miljövariabler](#flaggor--miljövariabler)
* [Arbetsflöde (rekommenderat)](#arbetsflöde-rekommenderat)
* [Tips](#tips)
* [Felsökning](#felsökning)
* [Juridik](#juridik)

---

## Funktioner

* Passiv & aktiv subdomäninsamling (subfinder, amass, assetfinder, puredns, dnsgen/shuffledns)
* **Wildcard-DNS-detektion** med valfri exkludering av wildcard-IP
* DNS-upplösning → IP (v4/v6), **ASN/CIDR-allow/deny**, blacklist
* **Naabu portscan** (inkrementell caching av redan skannade IP)
* **TLS cert scraping (tlsx)** → fler subdomäner (CN/SAN), auto-merge in-scope
* httpx fingerprinting (status, titel, tech, server), historik (gau/waybackurls)
* Katana crawl (valfritt), **gowitness skärmdumpar** (valfritt)
* **Nuclei** (valfritt, selektiv tags/severity)
* **Per-körningens outputmapp** `out/YYYYmmdd-HHMMSS/` + symlink `out.latest`
* **Rapporter**: `report.md` och `report.html` (Pandoc om tillgängligt, annars inbyggd HTML)

---

## Krav

* Debian/Ubuntu-bas: `apt`
* Go 1.20+ rekommenderas

## Installation

```bash
make install
```

Detta installerar systempaket (inkl. `libpcap-dev` för naabu) och Go-verktyg:
subfinder, dnsx, naabu, httpx, shuffledns, asnmap, mapcidr, katana, nuclei,
gau, waybackurls, gowitness, assetfinder, puredns, samt `pandoc` för HTML-rapport.

> **Tips:** Naabu får raw-sockets via `setcap` om möjligt (körs i `make install`).

## Förberedelser

```bash
make prepare
```

Skapar struktur `~/recon/<projekt>/{input,raw,out}` och lägger basfiler i `input/`.

## Snabbstart

```bash
# Standard: "home"-profil
make run

# VPS-profil (aggressivare rate limits)
make run PROFILE=vps

# Endast generera rapport från senaste körningen (ingen ny scanning)
make report
make report-open    # öppnar HTML-rapporten (Linux desktop)
```

## Profiler

`PROFILE=mobile|home|office|vps` styr rate-limits och timeouts:

* **mobile** – försiktigt/minimal påverkan
* **home** – default
* **office** – snabbare
* **vps** – aggressiv (för server/box med bra nät)

## Inputfiler

`input/` (skapas av `make prepare`):

* `domains.txt` – apex, `*.exempel.com` (normaliseras), `exempel.*` (kräver `tlds.txt`)
* `tlds.txt` – suffix för att expandera `exempel.*` (stödjer multi-label som `co.uk`)
* `resolvers.txt` – DNS-resolvers (en per rad)
* `ips.txt` / `cidrs.txt` – valfria extra mål
* `asns.txt` – valfri allowlist (ASN, en per rad)
* `blacklist_ips.txt` / `blacklist_cidrs.txt` – valfri denylist

## Output & rapport

Varje körning skriver till **egen mapp**:

```
out/
  2025xxxx-XXXXXX/   ← denna körnings artefakter
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
* `WILDCARD_EXCLUDE=1` – filtrera bort IP som matchar wildcard-DNS
* `GW_LIMIT=200` – max antal URL\:er för skärmdumpar
* `REPORT_ONLY=1` – bygg **bara** rapport (ingen scanning)

Stegintervall:

* `--from <N> --to <M>` – kör endast delmängd av kedjan (se “UI / steg” i skriptet)

Skippa delar:

* `SKIP_BRUTE=1`, `SKIP_PORTSCAN=1`, `SKIP_KATANA=1`, `SKIP_NUCLEI=1`

## Arbetsflöde (rekommenderat)

1. `make prepare` → lägg in targets i `input/domains.txt`.
2. `make run PROFILE=vps` (eller `home` lokalt).
3. Följ loggen i `out/<run>/run.log` eller i terminalen.
4. När körningen är klar: öppna `out/<run>/report.html` eller `make report-open`.
5. Prioritera fynd:

   * `nuclei_findings.txt` (high/critical)
   * `ip_port_hosts.csv` (intressanta portar + hosts)
   * `services_httpx.txt` (titlar/tech)
   * `historical_endpoints.txt` + `katana_endpoints.txt`
   * Screenshots i `screenshots/`
6. Behöver ny rapport utan ny scanning? → `make report`.

## Tips

* **Subfinder API-nycklar**: lägg i `~/.config/subfinder/provider-config.yaml` för bättre träff.
* **Resolvers**: bra resolvers ger snabbare/stabilare `dnsx`/`puredns`.
* **ASN allowlist** (`input/asns.txt`): krymp skanningsyta till “rätt” nät.
* **Blacklist**: exkludera tredjeparts-CDN eller shared hosting med `blacklist_*`.
* **tlsx**: vi skrapar CN/SAN från 443/8443 för att hitta fler subdomäner – ofta guld!
* **Nuclei**: Byt taggar/severity efter behov (ex. `-severity high,critical`).
* **Katana djup**: default depth 3 – höj sällan, det exploderar snabbt i volym.

## Felsökning

**`pcap.h: No such file or directory` vid `go install naabu`**
→ `sudo apt install -y libpcap-dev pkg-config` och kör `make install` igen.

**`naabu` kräver sudo / permission denied**
→ `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v naabu)"`.

**`gowitness` funkar inte (headless)**
→ Se till att `chromium` och `fonts-liberation` är installerade (görs i `make install`).

**`pandoc` saknas / ingen HTML-rapport**
→ Skriptet har en enkel HTML-fallback. Installera `pandoc` för snyggare HTML.

**Stora mål (tusentals apex)**
→ Använd `PROFILE=vps`, `--from/--to`, `INCREMENTAL=1`, samt `WILDCARD_EXCLUDE=1`.
→ Bekräftelsen kan hoppas över med `--yes`.

**DNS timeouts/long runs**
→ Byt/trimma `resolvers.txt`, eller sänk profil (ex. `home`).

## Juridik

Kör endast mot **tillåtna** mål inom programmens scope. Du ansvarar själv för all användning.

---

### Snabbkommandon (cheatsheet)

```bash
# Full körning (home)
make run

# Aggressivt (VPS), kör hela kedjan
make run PROFILE=vps

# Bara rapport från senaste körningen
make report
make report-open

# Endast steg 1–6 (t.ex. fram till portscan)
PROFILE=home ./recon.sh --from 1 --to 6

# Skippa tunga steg & kör snabbt
SKIP_BRUTE=1 SKIP_PORTSCAN=1 ./recon.sh -p home

# Inkrementell portscan + wildcard-filter
INCREMENTAL=1 WILDCARD_EXCLUDE=1 make run PROFILE=vps
```

Klar! Om du vill kan jag även lägga till en liten **sample-rapport** att checka in i repo\:t som referens.
