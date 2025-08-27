#!/usr/bin/env bash
# recon.sh — robust bug bounty recon (IPv6-aware, wildcard-aware, hosts seed)
set -Eeuo pipefail
shopt -s lastpipe

tslog() { printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$*"; }
log_info() { tslog "[i] $*"; }
log_warn() { tslog "[!] $*"; }
log_err()  { tslog "[x] $*" >&2; }
die() { log_err "$*"; exit 1; }
trap 'log_err "Error on line $LINENO in $0. Aborting."; exit 1' ERR

# ---------- Config ----------
BASE="${BASE:-$(pwd)}"
IN="${IN:-$BASE/input}"
OUTROOT="${OUTROOT:-$BASE/out}"
RAW="${RAW:-$BASE/raw}"
WORDLIST="${WORDLIST:-/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt}"
RESOLVERS="${RESOLVERS:-$IN/resolvers.txt}"
RESOLVERS6="${RESOLVERS6:-$IN/resolvers6.txt}"
RESOLVERS_TRUSTED="${RESOLVERS_TRUSTED:-$IN/resolvers-trusted.txt}"
HOSTS_TXT="${HOSTS_TXT:-$IN/hosts.txt}"    # <- enskilda värdar (t.ex. scanme.nmap.org)
PROFILE="${PROFILE:-home}"                 # mobile|home|office|vps

# steg-switchar
SKIP_ASN="${SKIP_ASN:-0}"
SKIP_KATANA="${SKIP_KATANA:-0}"
SKIP_HISTORY="${SKIP_HISTORY:-0}"
SKIP_NUCLEI="${SKIP_NUCLEI:-0}"
SKIP_SCREEN="${SKIP_SCREEN:-0}"

# valfri URL-filter (regex)
SCOPE_URL_REGEX="${SCOPE_URL_REGEX:-}"

# concurrency
NPROC="$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)"
HTTPX_C="${HTTPX_C:-$(( NPROC*8 ))}"
KATANA_C="${KATANA_C:-$(( NPROC*2 ))}"

case "$PROFILE" in
  mobile)  SUBF_RL=2;   PUREDNS_RATE=80;   PUREDNS_TRUSTED_RATE=40;  NAABU_RATE=80;   HTTPX_RL=30;  ;;
  home)    SUBF_RL=10;  PUREDNS_RATE=300;  PUREDNS_TRUSTED_RATE=100; NAABU_RATE=200;  HTTPX_RL=60;  ;;
  office)  SUBF_RL=25;  PUREDNS_RATE=900;  PUREDNS_TRUSTED_RATE=250; NAABU_RATE=400;  HTTPX_RL=120; ;;
  vps)     SUBF_RL=50;  PUREDNS_RATE=1500; PUREDNS_TRUSTED_RATE=400; NAABU_RATE=800;  HTTPX_RL=200; ;;
  *) die "Unknown PROFILE: $PROFILE";;
esac

# Timeouts
T_SUBF="${T_SUBF:-6m}"
T_DNSX="${T_DNSX:-6m}"
T_NAABU="${T_NAABU:-12m}"
T_HTTPX="${T_HTTPX:-14m}"
T_KATANA="${T_KATANA:-12m}"
T_HISTORY="${T_HISTORY:-15m}"
T_NUCLEI="${T_NUCLEI:-16m}"

TOP_PORTS="${TOP_PORTS:-100}"
DEEP_PORTS="${DEEP_PORTS:-1-65535}"
HIST_P="${HIST_P:-6}"

need(){ command -v "$1" >/dev/null || die "Missing: $1"; }
opt(){ command -v "$1" >/dev/null || log_info "(optional) $1 missing — skipping related step."; }

# Hårda beroenden
for b in subfinder dnsx naabu httpx jq; do need "$b"; done
command -v timeout >/dev/null || need gtimeout

# Mjuka beroenden
opt assetfinder; opt amass; opt puredns; opt shuffledns; opt dnsgen; opt tlsx; opt katana; opt nuclei; opt gau; opt waybackurls; opt gowitness; opt pandoc; opt chromium; opt asnmap; opt mapcidr

# Binaries
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout)"
SUBF_BIN="$(command -v subfinder)"
ASSETF_BIN="$(command -v assetfinder || true)"
AMASS_BIN="$(command -v amass || true)"
DNSX_BIN="$(command -v dnsx)"
NAABU_BIN="$(command -v naabu)"
HTTPX_BIN="$(command -v httpx)"
PUREDNS_BIN="$(command -v puredns || true)"
SHUFFLE_BIN="$(command -v shuffledns || true)"
DNSGEN_BIN="$(command -v dnsgen || true)"
TLXS_BIN="$(command -v tlsx || true)"
KATANA_BIN="$(command -v katana || true)"
NUCLEI_BIN="$(command -v nuclei || true)"
GAU_BIN="$(command -v gau || true)"
WBU_BIN="$(command -v waybackurls || true)"
GOW_BIN="$(command -v gowitness || true)"
ASNMAP_BIN="$(command -v asnmap || true)"
MAPCIDR_BIN="$(command -v mapcidr || true)"
JQ_BIN="$(command -v jq)"
PANDOC_BIN="$(command -v pandoc || true)"
CHROMIUM_BIN="$(command -v chromium || true)"

# Dir setup & logging
mkdir -p "$IN" "$RAW"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT="$OUTROOT/$RUN_ID"
mkdir -p "$OUT"
LOG="$OUT/run.log"
exec > >(ts '[%Y-%m-%d %H:%M:%S]' | tee -a "$LOG") 2> >(ts '[%Y-%m-%d %H:%M:%S]' | tee -a "$LOG" >&2)

# Inputs
DOMAINS_TXT="${DOMAINS_TXT:-$IN/domains.txt}"
DOMAINS_NORM="$IN/domains.norm.txt"
ORGS_FILE="${ORGS_FILE:-$IN/orgs.txt}"
ASNS_FILE="${ASNS_FILE:-$IN/asn.txt}"

[[ -s "$DOMAINS_TXT" ]] || die "Missing $DOMAINS_TXT"
tr '[:upper:]' '[:lower:]' < "$DOMAINS_TXT" | sed 's/\r$//' | grep -E '^[a-z0-9.-]+$' | sed 's/^*\.*//' | sort -u > "$DOMAINS_NORM"

log_info "RUN_ID   : $RUN_ID"
log_info "OUT_DIR  : $OUT"
log_info "PROFILE  : $PROFILE"
log_info "DOMAINS  : $DOMAINS_TXT"
log_info "RESOLVERS: $RESOLVERS"
log_info "RESOLVERS6: $RESOLVERS6"
log_info "TRUSTED  : $RESOLVERS_TRUSTED"
[[ -s "$HOSTS_TXT" ]] && log_info "HOSTS    : $HOSTS_TXT"

# Merge IPv4+IPv6 resolvers
MERGED_RES="$OUT/resolvers.merged.txt"
( [ -f "$RESOLVERS" ] && cat "$RESOLVERS" || true
  [ -f "$RESOLVERS6" ] && cat "$RESOLVERS6" || true ) \
  | sed 's/\r$//' | grep -E '^[0-9a-fA-F:.]+$' | sort -u > "$MERGED_RES"
if [[ ! -s "$MERGED_RES" ]]; then
  log_warn "No resolvers found in $RESOLVERS or $RESOLVERS6."
fi

# Valfritt URL-filter
scope_filter() { if [[ -n "$SCOPE_URL_REGEX" ]]; then grep -E "$SCOPE_URL_REGEX" || true; else cat; fi; }

# Wildcard-detektor (två slumpmässiga labels som båda resolvas => wildcard)
is_wildcard() {
  local root="$1"
  local a b
  a="$(tr -dc 'a-z0-9' </dev/urandom | head -c 10).$root"
  b="$(tr -dc 'a-z0-9' </dev/urandom | head -c 10).$root"
  printf '%s\n%s\n' "$a" "$b" | "$DNSX_BIN" -silent -a -r "$MERGED_RES" | wc -l | awk '{print ($1>=2)?"yes":"no"}'
}

# ---------- Steg 1: Passiv enum ----------
step1_passive() {
  : > "$RAW/subs_passive.txt"

  "$TIMEOUT_BIN" "$T_SUBF" "$SUBF_BIN" -silent -all -recursive -nc -rl "$SUBF_RL" -dL "$DOMAINS_NORM" -o "$RAW/subs_subfinder.txt" || true

  if [[ -n "$ASSETF_BIN" ]]; then
    "$TIMEOUT_BIN" "$T_SUBF" bash -lc '
      set -euo pipefail
      xargs -a "'"$DOMAINS_NORM"'" -I{} -P '"$NPROC"' '"$ASSETF_BIN"' --subs-only "{}" | sort -u
    ' > "$RAW/subs_assetfinder.txt" || true
  fi

  if [[ -n "$AMASS_BIN" ]]; then
    "$TIMEOUT_BIN" "$T_SUBF" "$AMASS_BIN" enum -passive -dL "$DOMAINS_NORM" -silent -norecursive -noalts | sort -u > "$RAW/subs_amass.txt" || true
  fi

  cat "$RAW"/subs_*.txt 2>/dev/null | sort -u > "$RAW/subs_passive.txt"
  log_info "Passive subdomains: $(wc -l < "$RAW/subs_passive.txt" 2>/dev/null || echo 0)"
}

# ---------- Steg 2: Brute + permutations ----------
step2_bruteforce() {
  : > "$RAW/brute.txt"; : > "$RAW/perms.txt"
  if [[ -n "$PUREDNS_BIN" ]]; then
    while read -r d; do
      if [[ -s "$RESOLVERS_TRUSTED" ]]; then
        "$TIMEOUT_BIN" "$T_DNSX" "$PUREDNS_BIN" bruteforce "$WORDLIST" "$d" -r "$MERGED_RES" \
          --resolvers-trusted "$RESOLVERS_TRUSTED" --rate-limit "$PUREDNS_RATE" --rate-limit-trusted "$PUREDNS_TRUSTED_RATE" -q || true
      else
        "$TIMEOUT_BIN" "$T_DNSX" "$PUREDNS_BIN" bruteforce "$WORDLIST" "$d" -r "$MERGED_RES" \
          --rate-limit "$PUREDNS_RATE" --rate-limit-trusted "$PUREDNS_TRUSTED_RATE" -q || true
      fi
    done < "$DOMAINS_NORM" | sort -u > "$RAW/brute.txt"
  fi
  if [[ -n "$DNSGEN_BIN" && -n "$SHUFFLE_BIN" ]]; then
    "$DNSGEN_BIN" "$RAW/subs_passive.txt" | "$SHUFFLE_BIN" -list - -r "$MERGED_RES" -mode resolve -silent > "$RAW/perms.txt" || true
  fi
  cat "$RAW/brute.txt" "$RAW/perms.txt" 2>/dev/null | sort -u > "$RAW/subs_active.txt"
  log_info "Active (brute+perms): $(wc -l < "$RAW/subs_active.txt" 2>/dev/null || echo 0)"
}

# ---------- Steg 3: Resolve med wildcard-hantering ----------
step3_resolve() {
  : > "$OUT/subdomains_unfiltered.txt"
  cat "$RAW/subs_passive.txt" "$RAW/subs_active.txt" 2>/dev/null | sort -u >> "$OUT/subdomains_unfiltered.txt"

  : > "$OUT/subdomains.txt"
  : > "$OUT/wildcard_domains.txt"

  while read -r d; do
    candidates="$(grep -E "\.(${d//./\\.})$" "$OUT/subdomains_unfiltered.txt" || true)"
    [[ -z "$candidates" ]] && continue

    if [[ "$(is_wildcard "$d")" == "yes" ]]; then
      echo "$d" >> "$OUT/wildcard_domains.txt"
      # wildcard-zon: behåll passiva träffar utan wildcard-filter (låter httpx/nuclei avgöra)
      printf '%s\n' "$candidates" >> "$OUT/subdomains.txt"
    else
      # normal: resolva + wildcard-filter
      printf '%s\n' "$candidates" | "$DNSX_BIN" -silent -r "$MERGED_RES" -wd "$d" >> "$OUT/subdomains.txt" || true
    fi
  done < "$DOMAINS_NORM"

  sort -u -o "$OUT/subdomains.txt" "$OUT/subdomains.txt"
  log_info "Resolved subdomains (after wildcard policy): $(wc -l < "$OUT/subdomains.txt" 2>/dev/null || echo 0)"

  # IP-lista (endast det som faktiskt resolvats via dnsx)
  "$DNSX_BIN" -silent -a -r "$MERGED_RES" -l "$OUT/subdomains.txt" | awk '{print $2}' | sed 's/.$//' | sort -u > "$OUT/ips.txt" || true
  log_info "IPs in scope (from DNS): $(wc -l < "$OUT/ips.txt" 2>/dev/null || echo 0)"
}

# ---------- Steg 4: tlsx (SANs -> subdomains) ----------
step4_tlsx() {
  if [[ -n "$TLXS_BIN" && -s "$OUT/ips.txt" ]]; then
    "$TLXS_BIN" -silent -a -l "$OUT/ips.txt" | awk '{print $NF}' | sed 's/,/\n/g' | sed 's/^\*\.//' \
      | grep -E '^[A-Za-z0-9.-]+$' | sort -u >> "$OUT/subdomains.txt" || true
    sort -u -o "$OUT/subdomains.txt" "$OUT/subdomains.txt"
    log_info "Subdomains + tlsx SANs: $(wc -l < "$OUT/subdomains.txt" 2>/dev/null || echo 0)"
  fi
}

# ---------- Steg 5: ASN/ORG -> CIDRs ----------
step5_asn_scope() {
  [[ "${SKIP_ASN}" == "1" ]] && { log_info "Skip ASN scope (SKIP_ASN=1)"; : > "$OUT/cidrs.txt"; return 0; }
  : > "$OUT/cidrs.txt"
  if command -v asnmap >/dev/null; then
    [[ -s "$ASNS_FILE" ]] && asnmap -silent -f "$ASNS_FILE" >> "$OUT/cidrs.txt" || true
    if [[ -s "$ORGS_FILE" ]]; then
      while read -r org; do [[ -n "$org" ]] && echo "$org" | asnmap -silent || true; done < "$ORGS_FILE" >> "$OUT/cidrs.txt" || true
    fi
  fi
  if command -v mapcidr >/dev/null && [[ -s "$OUT/cidrs.txt" ]]; then
    mapcidr -aggregate -cidr -l "$OUT/cidrs.txt" > "$OUT/cidrs.agg.txt" 2>/dev/null || cp "$OUT/cidrs.txt" "$OUT/cidrs.agg.txt"
    mv "$OUT/cidrs.agg.txt" "$OUT/cidrs.txt"
  fi
  sort -u -o "$OUT/cidrs.txt" "$OUT/cidrs.txt" || true
  log_info "CIDRs (ASN/ORG): $(wc -l < "$OUT/cidrs.txt" 2>/dev/null || echo 0)"
}

# ---------- Steg 6: Portscan fas A (top-ports) ----------
step6_ports_phaseA() {
  : > "$OUT/open_ports_A.json"
  : > "$OUT/targets_scan.txt"
  [[ -s "$OUT/ips.txt" ]]   && cat "$OUT/ips.txt"   >> "$OUT/targets_scan.txt"
  [[ -s "$OUT/cidrs.txt" ]] && cat "$OUT/cidrs.txt" >> "$OUT/targets_scan.txt"

  if [[ ! -s "$OUT/targets_scan.txt" ]]; then
    log_warn "No IP/CIDR for Phase A — skipping."
    return 0
  fi

  if ! getcap "$NAABU_BIN" >/dev/null 2>&1; then
    log_warn "naabu lacks cap_net_raw — run as root or: setcap cap_net_raw,cap_net_admin+eip $(command -v naabu)"
  fi

  "$TIMEOUT_BIN" "$T_NAABU" "$NAABU_BIN" -list "$OUT/targets_scan.txt" \
    -top-ports "$TOP_PORTS" -rate "$NAABU_RATE" -json -o "$OUT/open_ports_A.json" || true

  log_info "Phase A JSON rows: $(wc -l < "$OUT/open_ports_A.json" 2>/dev/null || echo 0)"
}

# ---------- Steg 7: Portscan fas B (djup) ----------
step7_ports_phaseB() {
  : > "$OUT/hit_ips.txt"
  [[ -s "$OUT/open_ports_A.json" ]] && jq -r '.ip' "$OUT/open_ports_A.json" | grep -E '^[0-9.]+$' | sort -u > "$OUT/hit_ips.txt" || true
  if [[ ! -s "$OUT/hit_ips.txt" ]]; then
    log_warn "No Phase A hits — skipping Phase B."
    : > "$OUT/open_ports_B.json"
  else
    "$TIMEOUT_BIN" "$T_NAABU" "$NAABU_BIN" -list "$OUT/hit_ips.txt" \
      -p "$DEEP_PORTS" -rate "$NAABU_RATE" -json -o "$OUT/open_ports_B.json" || true
  fi
  cat "$OUT/open_ports_A.json" "$OUT/open_ports_B.json" 2>/dev/null > "$OUT/open_ports.json" || cp "$OUT/open_ports_A.json" "$OUT/open_ports.json" 2>/dev/null || true
  jq -r '.ip+":"+(.port|tostring)' "$OUT/open_ports.json" 2>/dev/null | sort -u > "$OUT/open_ports.txt" || : > "$OUT/open_ports.txt"
  log_info "Open ports (ip:port): $(wc -l < "$OUT/open_ports.txt" 2>/dev/null || echo 0)"
}

# ---------- Steg 8: HTTPX (från subdomäner + ports + hosts.txt) ----------
step8_httpx() {
  : > "$OUT/urls_from_ports.txt"; : > "$OUT/httpx_all.json"

  # ip:port -> URL
  declare -A P2S=([443]=https [8443]=https [9443]=https [10443]=https)
  if [[ -s "$OUT/open_ports.txt" ]]; then
    while IFS=: read -r ip port; do
      scheme="${P2S[$port]:-http}"; echo "${scheme}://${ip}:${port}"
    done < "$OUT/open_ports.txt" | sort -u > "$OUT/urls_from_ports.txt"
  fi

  # hosts.txt -> seed URLs (force)
  : > "$OUT/seed_urls.txt"
  if [[ -s "$HOSTS_TXT" ]]; then
    awk '{print "http://"$1"\nhttps://"$1}' "$HOSTS_TXT" | sort -u >> "$OUT/seed_urls.txt"
  fi

  PORTS="${HTTPX_PORTS:-443,80,8080,8443,8000,8888,3000,5000,7001,9000,9200}"

  # httpx för subdomäner
  "$TIMEOUT_BIN" "$T_HTTPX" "$HTTPX_BIN" -l "$OUT/subdomains.txt" -ports "$PORTS" \
    -title -tech-detect -status-code -follow-redirects -no-color -json -o "$OUT/httpx_domains.json" -rl "$HTTPX_RL" -c "$HTTPX_C" || true

  # httpx för ip:port
  if [[ -s "$OUT/urls_from_ports.txt" ]]; then
    "$TIMEOUT_BIN" "$T_HTTPX" "$HTTPX_BIN" -l "$OUT/urls_from_ports.txt" \
      -title -tech-detect -status-code -follow-redirects -no-color -json -o "$OUT/httpx_ports.json" -rl "$HTTPX_RL" -c "$HTTPX_C" || true
  fi

  # httpx för seed-hosts
  if [[ -s "$OUT/seed_urls.txt" ]]; then
    "$TIMEOUT_BIN" "$T_HTTPX" "$HTTPX_BIN" -l "$OUT/seed_urls.txt" \
      -title -tech-detect -status-code -follow-redirects -no-color -json -o "$OUT/httpx_seeds.json" -rl "$HTTPX_RL" -c "$HTTPX_C" || true
  fi

  # sammanfoga
  cat "$OUT"/httpx_*.json 2>/dev/null > "$OUT/httpx_all.json" || true
  jq -r '.url' "$OUT/httpx_all.json" 2>/dev/null | scope_filter | sort -u > "$OUT/http_services.txt" || : > "$OUT/http_services.txt"
  log_info "HTTP endpoints: $(wc -l < "$OUT/http_services.txt" 2>/dev/null || echo 0)"
}

# ---------- Steg 9: Katana ----------
step9_katana() {
  [[ "$SKIP_KATANA" == "1" ]] && { log_info "Skip Katana (SKIP_KATANA=1)"; : > "$OUT/katana.txt"; return 0; }
  : > "$OUT/katana.txt"
  if [[ -n "$KATANA_BIN" && -s "$OUT/http_services.txt" ]]; then
    if [[ -n "$CHROMIUM_BIN" ]]; then
      "$TIMEOUT_BIN" "$T_KATANA" "$KATANA_BIN" -list "$OUT/http_services.txt" -headless -d 2 -jc -silent -concurrency "$KATANA_C" \
        -fx -store-response -rate-limit 0 -aff -ct 10m | scope_filter > "$OUT/katana.txt" || true
    else
      "$TIMEOUT_BIN" "$T_KATANA" "$KATANA_BIN" -list "$OUT/http_services.txt" -d 2 -jc -silent -concurrency "$KATANA_C" \
        -fx -store-response -rate-limit 0 -aff -ct 10m | scope_filter > "$OUT/katana.txt" || true
    fi
    log_info "Katana endpoints: $(wc -l < "$OUT/katana.txt" 2>/dev/null || echo 0)"
  fi
}

# ---------- Steg 10: Historiska endpoints ----------
step10_history() {
  [[ "$SKIP_HISTORY" == "1" ]] && { log_info "Skip History (SKIP_HISTORY=1)"; : > "$OUT/historical_endpoints.txt"; return 0; }
  : > "$OUT/historical_endpoints.txt"; : > "$OUT/historical_endpoints.gau.txt"; : > "$OUT/historical_endpoints.wbu.txt"
  GAU_OPTS=${GAU_OPTS:-"--subs -t 8 --from wayback,otx,commoncrawl,urlscan"}
  if [[ -n "$GAU_BIN" ]]; then
    xargs -a "$DOMAINS_NORM" -I{} -P "$HIST_P" bash -lc '
      d="$1"; tbin="$2"; dur="$3"; gau="$4"; opts="$5"
      "$tbin" -k 5s "$dur" "$gau" $opts <<< "$d" | sort -u
    ' _ {} "$TIMEOUT_BIN" "$T_HISTORY" "$GAU_BIN" "$GAU_OPTS" >> "$OUT/historical_endpoints.gau.txt" 2>/dev/null || true
  fi
  if [[ -n "$WBU_BIN" && -s "$OUT/subdomains.txt" ]]; then
    xargs -a "$OUT/subdomains.txt" -I{} -P "$HIST_P" bash -lc '
      s="$1"; tbin="$2"; dur="$3"; wbu="$4"
      "$tbin" -k 5s "$dur" "$wbu" <<< "$s" | sort -u
    ' _ {} "$TIMEOUT_BIN" "$T_HISTORY" "$WBU_BIN" >> "$OUT/historical_endpoints.wbu.txt" 2>/dev/null || true
  fi
  cat "$OUT/historical_endpoints.gau.txt" "$OUT/historical_endpoints.wbu.txt" 2>/dev/null | tr -d '\r' | scope_filter | LC_ALL=C sort -u > "$OUT/historical_endpoints.txt"
  log_info "Historical endpoints: $(wc -l < "$OUT/historical_endpoints.txt" 2>/dev/null || echo 0)"
}

# ---------- Steg 11: Screenshots ----------
step11_screens() {
  [[ "$SKIP_SCREEN" == "1" ]] && { log_info "Skip Screenshots (SKIP_SCREEN=1)"; : > "$OUT/screenshots/index.txt"; return 0; }
  mkdir -p "$OUT/screenshots"
  : > "$OUT/screenshots/index.txt"
  if [[ -n "$GOW_BIN" && -s "$OUT/http_services.txt" ]]; then
    head -n "${GW_LIMIT:-400}" "$OUT/http_services.txt" > "$OUT/urls_for_shots.txt"
    "$GOW_BIN" file -f "$OUT/urls_for_shots.txt" -P "$OUT/screenshots" --threads 4 --timeout 15 --log-level warn || true
    find "$OUT/screenshots" -type f -name '*.png' -printf '%f\n' | sort > "$OUT/screenshots/index.txt" || true
  else
    log_info "gowitness missing or no http endpoints — skipping screenshots."
  fi
}

# ---------- Steg 12: Nuclei ----------
step12_nuclei() {
  [[ "$SKIP_NUCLEI" == "1" ]] && { log_info "Skip Nuclei (SKIP_NUCLEI=1)"; : > "$OUT/nuclei_findings.txt"; return 0; }
  : > "$OUT/nuclei_findings.txt"
  [[ -z "$NUCLEI_BIN" ]] && { log_info "nuclei missing — skipping"; return 0; }
  TPL_DIR="${NUCLEI_TPL_DIR:-$HOME/nuclei-templates}"
  mkdir -p "$TPL_DIR"
  "$NUCLEI_BIN" -update-templates -silent || true
  "$NUCLEI_BIN" -validate -t "$TPL_DIR" 2> "$OUT/nuclei_validate.log" || true
  awk '/syntax error|runtime error/ {for(i=1;i<=NF;i++) if ($i ~ /\.yaml$/) print $i}' "$OUT/nuclei_validate.log" | sort -u > "$OUT/nuclei_exclude.txt" || true
  EXCL=()
  [[ -s "$OUT/nuclei_exclude.txt" ]] && EXCL=(-exclude-templates "$(paste -sd, "$OUT/nuclei_exclude.txt")")
  if [[ -n "$CHROMIUM_BIN" ]]; then
    export NUCLEI_BROWSER_PATH="$CHROMIUM_BIN"; HLEX=()
  else
    HLEX=(-exclude-tags headless)
  fi
  "$TIMEOUT_BIN" "$T_NUCLEI" "$NUCLEI_BIN" -l "$OUT/http_services.txt" -t "$TPL_DIR" \
    -severity "${NUCLEI_SEVERITY:-medium,high,critical}" -rl 60 -c "$(( NPROC*8 ))" -silent -no-color -stats \
    "${EXCL[@]}" "${HLEX[@]}" -o "$OUT/nuclei_findings.txt" || true
  log_info "Nuclei findings: $(wc -l < "$OUT/nuclei_findings.txt" 2>/dev/null || echo 0)"
}

# ---------- Steg 13: Rapport ----------
step13_report() {
  {
    echo "# Recon report ($RUN_ID)"
    echo
    echo "## Overview"
    echo "- Apex domains: $(wc -l < "$DOMAINS_NORM")"
    echo "- Subdomains (resolved): $(wc -l < "$OUT/subdomains.txt" 2>/dev/null || echo 0)"
    echo "- IPs (from DNS): $(wc -l < "$OUT/ips.txt" 2>/dev/null || echo 0)"
    echo "- CIDRs (ASN/ORG): $(wc -l < "$OUT/cidrs.txt" 2>/dev/null || echo 0)"
    echo "- Phase A (rows): $(wc -l < "$OUT/open_ports_A.json" 2>/dev/null || echo 0)"
    echo "- Phase B (rows): $(wc -l < "$OUT/open_ports_B.json" 2>/dev/null || echo 0)"
    echo "- Open ports (unique ip:port): $(wc -l < "$OUT/open_ports.txt" 2>/dev/null || echo 0)"
    echo "- HTTP endpoints: $(wc -l < "$OUT/http_services.txt" 2>/dev/null || echo 0)"
    echo "- Katana endpoints: $(wc -l < "$OUT/katana.txt" 2>/dev/null || echo 0)"
    echo "- Nuclei findings: $(wc -l < "$OUT/nuclei_findings.txt" 2>/dev/null || echo 0)"
    echo
    echo "## Ports (A+B) — sample"
    if [[ -s "$OUT/open_ports.json" && -n "$JQ_BIN" ]]; then
      echo '```'
      jq -r '. | [.ip, .port, .protocol, (.host//"-")] | @tsv' "$OUT/open_ports.json" 2>/dev/null | column -t | sed -n '1,80p' || true
      echo '```'
    else
      echo "_No ports or jq missing_"
    fi
    echo
    echo "## HTTP services (httpx) — top 40"
    if [[ -s "$OUT/httpx_all.json" && -n "$JQ_BIN" ]]; then
      echo '```'
      jq -r '[.url, (.status_code|tostring), (.title//"-"), ((.tech|join(","))//"-")] | @tsv' "$OUT/httpx_all.json" | sed -n '1,40p' | column -t || true
      echo '```'
    fi
    echo
    echo "## Nuclei — high/critical (top 50)"
    if [[ -s "$OUT/nuclei_findings.txt" ]]; then
      echo '```'
      grep -E "\[(critical|high)\]" "$OUT/nuclei_findings.txt" | sed -n '1,50p' || true
      echo '```'
    fi
    echo
    echo "## Katana — sample (top 60)"
    if [[ -s "$OUT/katana.txt" ]]; then
      echo '```'
      sed -n '1,60p' "$OUT/katana.txt" || true
      echo '```'
    fi
  } > "$OUT/report.md"

  if [[ -n "$PANDOC_BIN" ]]; then
    "$PANDOC_BIN" "$OUT/report.md" -f gfm -t html -s -o "$OUT/report.html" || true
  else
    {
      echo '<!doctype html><meta charset="utf-8"><title>Recon Report</title><style>body{font-family:system-ui,Segoe UI,Roboto,Ubuntu,sans-serif;padding:24px;max-width:1100px;margin:auto} code,pre{background:#111;color:#eee;padding:8px;border-radius:8px;display:block;overflow:auto} .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px} img{max-width:100%;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.2)}</style><body>'
      sed 's/&/\&amp;/g;s/"/\&quot;/g;s/'"'"'/\&#39;/g;s/</\&lt;/g;s/>/\&gt;/g' "$OUT/report.md" | sed '1s/^/<pre>/' -e '$s/$/<\/pre>/'
      if [[ -s "$OUT/screenshots/index.txt" ]]; then
        echo '<h2>Screenshots (sample)</h2><div class="grid">'
        n=0
        while read -r f; do
          echo '<div><img src="screenshots/'"$f"'" alt="shot"><div><code>'"$f"'</code></div></div>'; n=$((n+1)); [[ $n -ge 24 ]] && break
        done < "$OUT/screenshots/index.txt"
        echo '</div>'
      fi
      echo '</body></html>'
    } > "$OUT/report.html"
  fi

  ln -sfn "$OUT" "$OUTROOT/latest" || true
  log_info "Report ready: $OUT/report.html (symlink: $OUTROOT/latest)"
}

main() {
  log_info "Starting pipeline…"
  step1_passive
  step2_bruteforce
  step3_resolve
  step4_tlsx
  step5_asn_scope
  step6_ports_phaseA
  step7_ports_phaseB
  step8_httpx
  step9_katana
  step10_history
  step11_screens
  step12_nuclei
  step13_report
  log_info "Done. (log: $LOG, report: $OUT/report.html)"
}

main "$@"
