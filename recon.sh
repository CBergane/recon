#!/usr/bin/env bash
set -Eeuo pipefail

# ---------- Felhantering ----------
trap 'echo; echo "[!] Fel på rad $LINENO i $0. Avbryter."; exit 1' ERR
trap 'echo; echo "[!] Avbrutet (SIGINT/SIGTERM)."; exit 130' INT TERM

# ---------- Paths ----------
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
IN_BASE="$BASE_DIR/input"
OUT_BASE="$BASE_DIR/out"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUT_RUN="$OUT_BASE/$RUN_ID"
mkdir -p "$IN_BASE" "$OUT_RUN"
ln -sfn "$OUT_RUN" "$BASE_DIR/out.latest"

# Per-run dirs
IN="$IN_BASE"
OUT="$OUT_RUN"
RAW="$OUT/raw"
mkdir -p "$RAW"

# ---------- Låsfil ----------
LOCKFILE="$BASE_DIR/.recon.lock"
cleanup_lock() { rm -f "$LOCKFILE" 2>/dev/null || true; }
if [[ -f "$LOCKFILE" ]]; then
  oldpid="$(cat "$LOCKFILE" 2>/dev/null || true)"
  if [[ -n "${oldpid:-}" && -d "/proc/$oldpid" ]]; then
    echo "[!] En annan körning pågår (PID $oldpid). Avbryter."
    exit 1
  fi
fi
echo $$ > "$LOCKFILE"
trap 'cleanup_lock' EXIT

# ---------- Inmatning ----------
DOMAINS="$IN/domains.txt"
DOMAINS_NORM="$IN/domains.norm.txt"
TLDS_FILE="$IN/tlds.txt"
IPS_EXTRA="$IN/ips.txt"
CIDRS_EXTRA="$IN/cidrs.txt"
RESOLVERS="$IN/resolvers.txt"
ASNS="$IN/asns.txt"
BLACKLIST_IPS="$IN/blacklist_ips.txt"
BLACKLIST_CIDRS="$IN/blacklist_cidrs.txt"
WORDLIST="${WORDLIST:-/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt}"

# Wildcard-hantering
WILDCARD_EXCLUDE="${WILDCARD_EXCLUDE:-1}"

# Säkra Go-bin i PATH
export PATH="$HOME/go/bin:$PATH"

# ---------- Flaggor & defaults ----------
SKIP_BRUTE="${SKIP_BRUTE:-0}"
SKIP_PORTSCAN="${SKIP_PORTSCAN:-0}"
SKIP_KATANA="${SKIP_KATANA:-0}"
SKIP_NUCLEI="${SKIP_NUCLEI:-0}"
DRY_RUN="${DRY_RUN:-0}"
INCREMENTAL="${INCREMENTAL:-0}"
PROFILE="${PROFILE:-home}"
FROM="${FROM:-1}"
TO="${TO:-999}"
YES="${YES:-0}"
REPORT_ONLY="${REPORT_ONLY:-0}"

# Valfria toggles
NO_TIMEOUT="${NO_TIMEOUT:-0}"   # 1 = inaktivera coreutils 'timeout'
MOUNT_WARN="${MOUNT_WARN:-0}"   # 1 = varna om noexec mount (om findmnt finns)

# Screenshots
GW_LIMIT="${GW_LIMIT:-200}"

# ---------- Färg/logg ----------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  CLR_INFO="\033[1;34m"; CLR_OK="\033[1;32m"; CLR_WARN="\033[1;33m"; CLR_ERR="\033[1;31m"; CLR_RST="\033[0m"
else
  CLR_INFO=""; CLR_OK=""; CLR_WARN=""; CLR_ERR=""; CLR_RST=""
fi
log_info() { printf "${CLR_INFO}[i] %s${CLR_RST}\n" "$*"; }
log_ok()   { printf "${CLR_OK}[+] %s${CLR_RST}\n" "$*"; }
log_warn() { printf "${CLR_WARN}[!] %s${CLR_RST}\n" "$*"; }
log_err()  { printf "${CLR_ERR}[x] %s${CLR_RST}\n" "$*"; }

usage() {
  cat <<'USAGE'
recon.sh – robust rek-pipeline

Användning:
  recon.sh [alternativ]

Alternativ:
  -p, --profile <mobile|home|office|vps>
  -w, --wordlist <fil>
      --skip-brute | --skip-portscan | --skip-katana | --skip-nuclei
      --dry-run
      --from <N> --to <M>
      --yes
      --report-only
  -h, --help

Miljö:
  PROFILE=mobile|home|office|vps  WORDLIST=...  INCREMENTAL=1  GW_LIMIT=200
  SKIP_BRUTE=1  SKIP_PORTSCAN=1  SKIP_KATANA=1  SKIP_NUCLEI=1  DRY_RUN=1
  REPORT_ONLY=1  WILDCARD_EXCLUDE=1
  NO_TIMEOUT=1   # stäng av GNU timeout helt
  MOUNT_WARN=1   # varna om binärer ligger på noexec-mount
USAGE
}

# ---------- Argparse ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--profile) PROFILE="$2"; shift 2;;
    -w|--wordlist) WORDLIST="$2"; shift 2;;
    --skip-brute) SKIP_BRUTE=1; shift;;
    --skip-portscan) SKIP_PORTSCAN=1; shift;;
    --skip-katana) SKIP_KATANA=1; shift;;
    --skip-nuclei) SKIP_NUCLEI=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    --from) FROM="$2"; shift 2;;
    --to) TO="$2"; shift 2;;
    --yes) YES=1; shift;;
    --report-only) REPORT_ONLY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "[!] Okänd flagga: $1"; usage; exit 2;;
  esac
done

# ---------- Loggning ----------
LOG="$OUT/run.log"
if command -v ts >/dev/null 2>&1; then
  exec > >(ts '[%Y-%m-%d %H:%M:%S]' | tee -a "$LOG") 2> >(ts '[%Y-%m-%d %H:%M:%S]' | tee -a "$LOG" >&2)
else
  log_warn "moreutils 'ts' saknas – logg utan tidsstämplar (sudo apt install moreutils)"
  exec > >(tee -a "$LOG") 2> >(tee -a "$LOG" >&2)
fi

# ---------- Profiler + timeouts ----------
case "$PROFILE" in
  mobile) SUBF_RL=2;   DNSX_T=50;  PUREDNS_RATE=80;  PUREDNS_TRUSTED_RATE=20;  NAABU_TOP=100;  NAABU_RATE=25;  KATANA_C=2;  HTTPX_RL=25;;
  home)   SUBF_RL=5;   DNSX_T=120; PUREDNS_RATE=200; PUREDNS_TRUSTED_RATE=50;  NAABU_TOP=100;  NAABU_RATE=50;  KATANA_C=4;  HTTPX_RL=50;;
  office) SUBF_RL=15;  DNSX_T=250; PUREDNS_RATE=600; PUREDNS_TRUSTED_RATE=150; NAABU_TOP=500;  NAABU_RATE=400; KATANA_C=8;  HTTPX_RL=150;;
  vps)    SUBF_RL=50;  DNSX_T=500; PUREDNS_RATE=1500;PUREDNS_TRUSTED_RATE=400; NAABU_TOP=1000; NAABU_RATE=1000;KATANA_C=12; HTTPX_RL=400;;
  *) log_err "Okänd PROFILE: $PROFILE"; exit 1;;
esac

# Verktygs-timeouts (GNU timeout duration, t.ex. 20m)
T_SUBF=20m; T_AMASS=25m; T_DNSX=20m; T_NAABU=30m; T_HTTPX=25m; T_KATANA=20m; T_NUCLEI=25m; T_TLSX=10m

log_info "RUN_ID  : $RUN_ID"
log_info "OUT_DIR : $OUT"
log_info "PROFILE : $PROFILE"
log_info "DOMAINS : $DOMAINS"
log_info "RESOLVERS: $RESOLVERS"
[[ "$DRY_RUN" -eq 1 ]] && log_warn "DRY-RUN: inget exekveras – bara plan & framsteg visas."
echo

# ---------- Hjälpfunktioner ----------
need(){ command -v "$1" >/dev/null || { log_err "Missing: $1"; exit 1; }; }
opt(){ command -v "$1" >/dev/null || log_info "(valfritt) $1 saknas – hoppar över relaterat steg."; }

mustbin() {
  local p; p="$(command -v "$1" 2>/dev/null || true)"
  [[ -n "$p" ]] || { log_err "Hittar inte binär: $1 i PATH"; exit 1; }
  printf '%s\n' "$p"
}

warn_noexec_mount() {
  local path="$1"
  [[ "${MOUNT_WARN:-0}" -eq 1 ]] || return 0
  command -v findmnt >/dev/null 2>&1 || return 0
  local mnt_opts
  mnt_opts="$(findmnt -T "$path" -no OPTIONS 2>/dev/null || true)"
  [[ "$mnt_opts" == *noexec* ]] && log_warn "Binärens mount har noexec: $mnt_opts ($path)"
}

first_nonempty_line(){ awk 'NF{print; exit}' "$1" 2>/dev/null || true; }

check_net() {
  local target; target="$(first_nonempty_line "$RESOLVERS")"; [[ -z "$target" ]] && target="1.1.1.1"
  for i in 1 2 3 4 5; do
    if ping -c 1 -W 2 "$target" >/dev/null 2>&1; then return 0; fi
    local sleep_s=$((2**i)); log_warn "Nät misslyckades mot $target (försök $i) – väntar ${sleep_s}s…"; sleep "$sleep_s"
  done
  log_err "Nät verkar nere mot $target – avbryter."; exit 1
}

run_to() {
  local dur="$1"; shift
  if [[ "${NO_TIMEOUT:-0}" -eq 1 ]]; then
    "$@"
  else
    "$TIMEOUT_BIN" -k 5s "$dur" "$@"
  fi
}

# ---------- UI / steg ----------
STEPS=(
  "Passiv subdomäninsamling"           #1
  "Bruteforce + permutationer"         #2
  "Wildcard-DNS detektion"             #3
  "Resolve → IP"                       #4
  "ASN/CIDR-allow + blacklist"         #5
  "Portscan (inkrementell) + rapport"  #6
  "TLS cert scraping (tlsx) → subdomäner" #7
  "HTTP probe/fingerprint"             #8
  "Historiska endpoints (gau/wayback)" #9
  "Katana-crawl"                       #10
  "Screenshots (gowitness)"            #11
  "Nuclei (selektivt)"                 #12
  "Report (md + html)"                 #13
)
WEIGHTS=(11 16 4 9 9 17 5 10 4 4 4 4 3)
CURRENT=0
TOTAL_STEPS=${#STEPS[@]}

spinner() {
  local msg="$1" i=0 spin='-\|/'
  [[ -t 1 && -w /dev/tty ]] || return 0
  while :; do i=$(( (i+1) %4 )); printf "\r[%3d%%] %s %s" "$CURRENT" "$msg" "${spin:$i:1}" > /dev/tty; sleep 0.1; done
}

run_step() {  # run_step <idx> "<label>" <weight> <function_name>
  local idx="$1"; local label="$2"; local weight="$3"; local fn="$4"
  if (( idx < FROM || idx > TO )); then
    log_info "Hoppar över steg $idx/$TOTAL_STEPS: $label (from=$FROM to=$TO)"
    return 0
  fi
  log_info "Steg $idx/$TOTAL_STEPS: $label"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf "[dry-run] %s\n" "$label"
    CURRENT=$((CURRENT + weight))
    printf "\r${CLR_OK}[%3d%%] %s ✓ (0.0s)${CLR_RST}\n" "$CURRENT" "$label"
    return 0
  fi
  check_net
  spinner "$label" & local spid=$!
  local start end rc; start=$(date +%s)
  "$fn"; rc=$?
  kill "$spid" 2>/dev/null || true; wait "$spid" 2>/dev/null || true
  end=$(date +%s)
  CURRENT=$((CURRENT + weight))
  if (( rc==0 )); then
    printf "\r${CLR_OK}[%3d%%] %s ✓ (%.1fs)${CLR_RST}\n" "$CURRENT" "$label" "$((end-start))"
  else
    printf "\r${CLR_ERR}[%3d%%] %s ✗ (%.1fs, rc=%d)${CLR_RST}\n" "$CURRENT" "$label" "$((end-start))" "$rc"
    exit "$rc"
  fi
}

# ---------- Rapport-funktion ----------
generate_report() {
  {
    echo '# Recon Sammanfattning'
    echo
    echo "* Datum: $(date -Iseconds)"
    echo "* Profil: $PROFILE"
    echo "* Run-ID: $RUN_ID"
    echo
    echo '## Nyckeltal'
    echo "- Subdomäner: $(wc -l < "$OUT/subdomains.txt" 2>/dev/null || echo 0)"
    echo "- Subdomäner från cert (tlsx): $(wc -l < "$OUT/subs_from_certs.in_scope.txt" 2>/dev/null || echo 0)"
    echo "- Wildcard IPs (detekterade): $(wc -l < "$OUT/wild_ips.txt" 2>/dev/null || echo 0)"
    echo "- IP (in scope): $(wc -l < "$OUT/ips_in_scope.txt" 2>/dev/null || echo 0)"
    echo "- Öppna portar (rader): $(wc -l < "$OUT/open_ports.txt" 2>/dev/null || echo 0)"
    echo "- HTTP endpoints (httpx URLs): $(wc -l < "$OUT/urls_httpx.txt" 2>/dev/null || echo 0)"
    echo "- Historiska endpoints: $(wc -l < "$OUT/historical_endpoints.txt" 2>/dev/null || echo 0)"
    echo "- Katana endpoints: $(wc -l < "$OUT/katana_endpoints.txt" 2>/dev/null || echo 0)"
    echo "- Nuclei findings: $(wc -l < "$OUT/nuclei_findings.txt" 2>/dev/null || echo 0)"
    echo
    echo '## Topp 10 IP med flest portar'
    (awk -F: '{c[$1]++} END{for (ip in c) printf "%s,%d\n", ip, c[ip]}' "$OUT/open_ports.txt" 2>/dev/null \
      | sort -t, -k2,2nr | head -10 \
      | awk -F, '{printf "- %s (%s portar)\n", $1, $2}') || true
    echo
    echo '## Toppteknologier (httpx -tech-detect)'
    (command -v jq >/dev/null 2>&1 && jq -r '.tech[]?' "$OUT/services_httpx.json" 2>/dev/null \
      | sort | uniq -c | sort -nr | head -20 \
      | awk '{cnt=$1; $1=""; sub(/^ /,""); printf "- %s (%s)\n", $0, cnt}') || true
    echo
    echo '## Exempel på tjänster (förhandsgranskning)'; echo ''
    (head -20 "$OUT/services_httpx.txt" 2>/dev/null || true) | sed 's/^/    /'
    echo
    echo '## Noterbara portar per IP'; echo ''
    (head -30 "$OUT/ports_by_ip.txt" 2>/dev/null || true) | sed 's/^/    /'
    echo
    if [[ -s "$OUT/nuclei_findings.txt" ]]; then
      echo '## Nuclei – fynd (urval)'; echo ''
      (grep -E "\[(critical|high)\]" "$OUT/nuclei_findings.txt" | head -50 || true) | sed 's/^/    /'
      echo
    fi
    if [[ -s "$OUT/screenshots/index.txt" ]]; then
      echo '## Skärmdumpar (exempel)'; echo ''
      (head -20 "$OUT/screenshots/index.txt" | sed 's/^/    - /') || true
      echo
    fi
    echo '---'
    echo '_Artefakter:_'
    echo "- $OUT/subdomains.txt (+ subs_from_certs.in_scope.txt)"
    echo "- $OUT/resolved.txt"
    echo "- $OUT/ips_in_scope.txt"
    echo "- $OUT/open_ports.txt, open_ports.json, ip_port_hosts.csv"
    echo "- $OUT/services_httpx.json, services_httpx.txt"
    echo "- $OUT/urls_httpx.txt, historical_endpoints.txt, katana_endpoints.txt"
    echo "- $OUT/nuclei_findings.txt"
    echo "- $OUT/screenshots/"
  } > "$OUT/report.md"

  if command -v pandoc >/dev/null 2>&1; then
    pandoc "$OUT/report.md" -s -o "$OUT/report.html" || true
  else
    {
      echo '<!doctype html><html><head><meta charset="utf-8"><title>Recon Report</title>'
      echo '<style>body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;line-height:1.5}'
      echo 'pre,code{background:#f6f8fa;padding:8px;border-radius:6px;display:block;white-space:pre-wrap}'
      echo '.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}'
      echo 'img{max-width:100%;height:auto;border:1px solid #ddd;border-radius:6px}</style></head><body>'
      echo "<h1>Recon Report</h1>"
      echo "<p>Genererad: $(date -Iseconds) · Profil: $PROFILE · Run: $RUN_ID</p>"
      echo '<h2>Sammanfattning (markdown)</h2><pre>'
      sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' "$OUT/report.md"
      echo '</pre>'
      if [[ -s "$OUT/screenshots/index.txt" ]]; then
        echo '<h2>Skärmdumpar (urval)</h2><div class="grid">'
        n=0
        while read -r f; do
          echo '<div><img src="screenshots/'"$f"'" alt="shot"><div><code>'"$f"'</code></div></div>'
          n=$((n+1)); [[ $n -ge 24 ]] && break
        done < "$OUT/screenshots/index.txt"
        echo '</div>'
      fi
      echo '</body></html>'
    } > "$OUT/report.html"
  fi
}

# ---------- REPORT-ONLY ----------
if [[ "$REPORT_ONLY" -eq 1 ]]; then
  log_info "REPORT-ONLY: bygger rapport av befintliga artefakter i $OUT/"
  generate_report
  echo
  log_ok "Rapport klar: $OUT/report.md (och report.html)"
  exit 0
fi

# ---------- Normalisera & expandera domäner ----------
normalize_domains() {
  [[ -f "$DOMAINS" ]] || { log_err "Saknar fil: $DOMAINS"; exit 1; }
  local TMP="$OUT/domains.requested.txt"
  awk '{g=$0; sub(/^[[:space:]]+/,"",g); sub(/[[:space:]]+$/,"",g);
        if(g==""||g~/^#/)next; g=tolower(g); sub(/^\*\.[[:space:]]*/,"",g); sub(/^www\./,"",g); print g}' \
      "$DOMAINS" | sort -u > "$TMP"
  if grep -qE '\.\*$' "$TMP"; then
    [[ -s "$TLDS_FILE" ]] || { log_err "Du använder '\''exempel.*'\'' men saknar $TLDS_FILE"; exit 1; }
  fi
  : > "$DOMAINS_NORM"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ \.\*$ ]]; then
      base="${line%.*}"
      while IFS= read -r sfx; do
        [[ -z "$sfx" || "$sfx" =~ ^# ]] && continue
        echo "${base}.${sfx}"
      done < "$TLDS_FILE" >> "$DOMAINS_NORM"
    elif [[ "$line" == *"*"* ]]; then
      log_warn "Ignorerar rad med wildcard: $line"
    else
      echo "$line" >> "$DOMAINS_NORM"
    fi
  done < "$TMP"
  sort -u -o "$DOMAINS_NORM" "$DOMAINS_NORM"
  [[ -s "$DOMAINS_NORM" ]] || { log_err "Inga giltiga domäner efter normalisering"; exit 1; }
  log_info "Normaliserade domäner → $DOMAINS_NORM"
}
normalize_domains

# ---- Preflight + bindningar ----
# Obligatoriska (timeout bara om NO_TIMEOUT=0)
for b in subfinder dnsx naabu httpx; do need "$b"; done
if [[ "${NO_TIMEOUT:-0}" -eq 0 ]]; then need timeout; fi

# Valfria
opt puredns; opt shuffledns; opt dnsgen; opt katana; opt nuclei; opt asnmap
opt mapcidr; opt pv; opt gau; opt waybackurls; opt jq; opt pandoc; opt gowitness
opt tlsx; opt openssl; opt amass; opt assetfinder; opt findmnt

# Absoluta sökvägar
if [[ "${NO_TIMEOUT:-0}" -eq 0 ]]; then
  TIMEOUT_BIN="$(mustbin timeout)"; warn_noexec_mount "$TIMEOUT_BIN"
else
  TIMEOUT_BIN="$(command -v timeout || true)"
fi
SUBF_BIN="$(mustbin subfinder)";            warn_noexec_mount "$SUBF_BIN"
DNSX_BIN="$(mustbin dnsx)";                 warn_noexec_mount "$DNSX_BIN"
NAABU_BIN="$(mustbin naabu)";               warn_noexec_mount "$NAABU_BIN"
HTTPX_BIN="$(mustbin httpx)";               warn_noexec_mount "$HTTPX_BIN"

# Valfria absoluta
AMASS_BIN="$(command -v amass || true)";         [[ -n "$AMASS_BIN" ]]    && warn_noexec_mount "$AMASS_BIN"
ASSETF_BIN="$(command -v assetfinder || true)";  [[ -n "$ASSETF_BIN" ]]   && warn_noexec_mount "$ASSETF_BIN"
KATANA_BIN="$(command -v katana || true)"
NUCLEI_BIN="$(command -v nuclei || true)"
PUREDNS_BIN="$(command -v puredns || true)"
DNSGEN_BIN="$(command -v dnsgen || true)"
SHUFFLE_BIN="$(command -v shuffledns || true)"
ASNMAP_BIN="$(command -v asnmap || true)"
MAPCIDR_BIN="$(command -v mapcidr || true)"
GAU_BIN="$(command -v gau || true)"
WBU_BIN="$(command -v waybackurls || true)"
GOW_BIN="$(command -v gowitness || true)"
TLSX_BIN="$(command -v tlsx || true)"
JQ_BIN="$(command -v jq || true)"
OPENSSL_BIN="$(command -v openssl || true)"
PANDOC_BIN="$(command -v pandoc || true)"

[[ -s "$RESOLVERS" ]] || { log_err "Saknar resolvers: $RESOLVERS"; exit 1; }
[[ -r "$WORDLIST"  ]] || { log_err "Wordlist hittas inte: $WORDLIST"; exit 1; }
sed -i 's/\r$//' "$BLACKLIST_IPS" 2>/dev/null || true
sed -i 's/\r$//' "$BLACKLIST_CIDRS" 2>/dev/null || true

# Bekräfta stor target-yta
if [[ "$YES" -ne 1 && -t 0 && "$DRY_RUN" -ne 1 ]]; then
  COUNT_APEX=$(wc -l < "$DOMAINS_NORM")
  (( COUNT_APEX > 50 )) && { read -r -p "[?] $COUNT_APEX apex-domäner hittade – fortsätta? (y/N) " ans; [[ "${ans,,}" == "y" ]] || { log_err "Avbrutet av användaren."; exit 1; }; }
fi

# ---------- Självtest (kort) ----------
log_info "timeout: $([[ "${NO_TIMEOUT:-0}" -eq 1 ]] && echo 'AV' || echo 'PÅ')"
log_info "subfinder bin: $SUBF_BIN"
if [[ "${NO_TIMEOUT:-0}" -eq 1 ]]; then
  "$SUBF_BIN" -version >/dev/null 2>&1 || log_warn "Subfinder -version misslyckades."
else
  run_to 2s "$SUBF_BIN" -version >/dev/null 2>&1 || log_warn "Subfinder -version med timeout misslyckades."
fi

# ---------- STEG (funktionsbaserade) ----------
step1_passive() {
  run_to "$T_SUBF" "$SUBF_BIN" -dL "$DOMAINS_NORM" -all -recursive -rl "$SUBF_RL" ${SUBF_PC:-} -silent \
    | sort -u > "$RAW/subs_subfinder.txt" || true

  if [[ -n "$AMASS_BIN" ]]; then
    run_to "$T_AMASS" "$AMASS_BIN" enum -passive -df "$DOMAINS_NORM" -o "$RAW/subs_amass.txt" || true
  else
    : > "$RAW/subs_amass.txt"
  fi

  if [[ -n "$ASSETF_BIN" ]]; then
    while read -r d; do "$ASSETF_BIN" --subs-only "$d"; done < "$DOMAINS_NORM" \
      | sort -u > "$RAW/subs_assetfinder.txt" || true
  else
    : > "$RAW/subs_assetfinder.txt"
  fi

  cat "$RAW"/subs_* 2>/dev/null | sort -u > "$RAW/subs_passive.txt"
  : > "$OUT/subdomains_unfiltered.txt"
  cat "$RAW/subs_passive.txt" 2>/dev/null | sort -u >> "$OUT/subdomains_unfiltered.txt"
}
# SUBF provider-config (om den finns)
SUBF_CFG="${SUBF_CFG:-$HOME/.config/subfinder/provider-config.yaml}"
if [[ -s "$SUBF_CFG" ]]; then SUBF_PC=(-pc "$SUBF_CFG"); else SUBF_PC=(); fi

step2_bruteforce() {
  : > "$RAW/brute.txt"; : > "$RAW/perms.txt"
  if [[ "$SKIP_BRUTE" -ne 1 ]]; then
    if [[ -n "$PUREDNS_BIN" ]]; then
      while read -r d; do
        "$PUREDNS_BIN" bruteforce "$WORDLIST" "$d" -r "$RESOLVERS" \
          --rate-limit "$PUREDNS_RATE" --rate-limit-trusted "$PUREDNS_TRUSTED_RATE" -q || true
      done < "$DOMAINS_NORM" | sort -u >> "$RAW/brute.txt"
    fi
    if [[ -n "$DNSGEN_BIN" && -n "$SHUFFLE_BIN" ]]; then
      "$DNSGEN_BIN" "$RAW/subs_passive.txt" | "$SHUFFLE_BIN" -r "$RESOLVERS" -silent > "$RAW/perms.txt" || true
    fi
  else
    echo '[i] --skip-brute aktivt.'
  fi
  cat "$RAW/subs_passive.txt" "$RAW/brute.txt" "$RAW/perms.txt" 2>/dev/null | sort -u > "$OUT/subdomains_unfiltered.txt"
  awk '{g=$0; gsub(/[[.\\]{}()^$|?+*]/,"\\&",g); print "(^|\\.)" g "$"}' "$DOMAINS_NORM" > "$OUT/apex_regex.txt"
  grep -Ei -f "$OUT/apex_regex.txt" "$OUT/subdomains_unfiltered.txt" | sort -u > "$OUT/subdomains.txt"
  cat "$DOMAINS_NORM" >> "$OUT/subdomains.txt"; sort -u -o "$OUT/subdomains.txt" "$OUT/subdomains.txt"
  echo "[i] subdomäner=$(wc -l < "$OUT/subdomains.txt")"
}

step3_wildcard() {
  : > "$OUT/wild_ips.txt"
  if [[ -s "$DOMAINS_NORM" && -n "$OPENSSL_BIN" ]]; then
    {
      while read -r apex; do
        for _ in {1..5}; do echo "$("$OPENSSL_BIN" rand -hex 6).$apex"; done
      done < "$DOMAINS_NORM"
    } | "$DNSX_BIN" -r "$RESOLVERS" -a -aaaa -resp -silent \
      | awk '{for(i=1;i<=NF;i++) if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || $i ~ /:/) print $i}' \
      | sort -u >> "$OUT/wild_ips.txt" || true
  fi
  sort -u -o "$OUT/wild_ips.txt" "$OUT/wild_ips.txt"
  echo "[i] wildcard_ips=$(wc -l < "$OUT/wild_ips.txt")"
}

step4_resolve() {
  run_to "$T_DNSX" "$DNSX_BIN" -l "$OUT/subdomains.txt" -r "$RESOLVERS" -a -aaaa -resp -retries 2 -t "$DNSX_T" -silent > "$OUT/resolved.txt" || true
  awk '{for(i=1;i<=NF;i++) if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || $i ~ /:/) print $i}' "$OUT/resolved.txt" \
    | sort -u > "$OUT/ips_all.txt"

  [[ -s "$IPS_EXTRA"  ]] && awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}$|:/' "$IPS_EXTRA" >> "$OUT/ips_all.txt"
  [[ -s "$CIDRS_EXTRA" && -n "$MAPCIDR_BIN" ]] && "$MAPCIDR_BIN" -i -f "$CIDRS_EXTRA" >> "$OUT/ips_all.txt"
  sort -u -o "$OUT/ips_all.txt" "$OUT/ips_all.txt"

  if [[ "$WILDCARD_EXCLUDE" -eq 1 && -s "$OUT/wild_ips.txt" ]]; then
    cp "$OUT/ips_all.txt" "$OUT/ips_all.pre_nowild.txt"
    grep -vFf "$OUT/wild_ips.txt" "$OUT/ips_all.pre_nowild.txt" | sort -u > "$OUT/ips_all.txt" || true
    local pre cur; pre=$(wc -l < "$OUT/ips_all.pre_nowild.txt" 2>/dev/null || echo 0)
    cur=$(wc -l < "$OUT/ips_all.txt" 2>/dev/null || echo 0)
    echo "[i] wildcard-filter: borttagna=$(( pre - cur ))"
  fi
  echo "[i] resolved_IPs=$(wc -l < "$OUT/ips_all.txt")"
}

step5_scope() {
  : > "$OUT/cidrs_allow.txt"
  if [[ -s "$ASNS" && -n "$ASNMAP_BIN" ]]; then
    "$ASNMAP_BIN" -a $(tr '\n' ' ' < "$ASNS") -silent | sort -u > "$OUT/cidrs_allow.txt" || true
  fi
  cp "$OUT/ips_all.txt" "$OUT/ips_scoped.tmp" 2>/dev/null || :
  if [[ -s "$OUT/cidrs_allow.txt" && -n "$MAPCIDR_BIN" ]]; then
    "$MAPCIDR_BIN" -f "$OUT/ips_scoped.tmp" -r "$OUT/cidrs_allow.txt" -o "$OUT/ips_scoped.tmp"
  fi
  if [[ -s "$BLACKLIST_IPS" ]]; then
    grep -vFf "$BLACKLIST_IPS" "$OUT/ips_scoped.tmp" > "$OUT/ips_scoped.f" || true
    mv "$OUT/ips_scoped.f" "$OUT/ips_scoped.tmp"
  fi
  if [[ -s "$BLACKLIST_CIDRS" && -n "$MAPCIDR_BIN" ]]; then
    "$MAPCIDR_BIN" -i -f "$BLACKLIST_CIDRS" > "$OUT/_deny_ips.tmp"
    grep -vFf "$OUT/_deny_ips.tmp" "$OUT/ips_scoped.tmp" > "$OUT/ips_scoped.f" || true
    mv "$OUT/ips_scoped.f" "$OUT/ips_scoped.tmp"; rm -f "$OUT/_deny_ips.tmp"
  fi
  mv "$OUT/ips_scoped.tmp" "$OUT/ips_in_scope.txt"
  sort -u -o "$OUT/ips_in_scope.txt" "$OUT/ips_in_scope.txt"
  echo "[i] in_scope_IPs=$(wc -l < "$OUT/ips_in_scope.txt")"
}

step6_portscan() {
  : > "$OUT/open_ports.txt"; : > "$OUT/open_ports.json"
  local STATE_DIR="$OUT_BASE/state"; mkdir -p "$STATE_DIR"
  local SCANNED_IPS="$STATE_DIR/scanned_ips.txt"; touch "$SCANNED_IPS"

  if [[ "$SKIP_PORTSCAN" -ne 1 ]]; then
    local TARGET_LIST="$OUT/ips_in_scope.txt"
    if [[ "$INCREMENTAL" -eq 1 && -s "$OUT/ips_in_scope.txt" ]]; then
      comm -23 <(sort -u "$OUT/ips_in_scope.txt") <(sort -u "$SCANNED_IPS") > "$OUT/ips_to_scan.txt"
      TARGET_LIST="$OUT/ips_to_scan.txt"
      echo "[i] Inkrementellt: $(wc -l < "$OUT/ips_to_scan.txt") nya IP"
    fi
    if [[ -s "$TARGET_LIST" ]]; then
      awk '!/:/' "$TARGET_LIST" > "$OUT/ips4_in_scope.txt" || true
      awk '/:/'  "$TARGET_LIST" > "$OUT/ips6_in_scope.txt" || true
      if [[ -s "$OUT/ips4_in_scope.txt" ]]; then
        run_to "$T_NAABU" "$NAABU_BIN" -list "$OUT/ips4_in_scope.txt" -top-ports "$NAABU_TOP" -rate "$NAABU_RATE" -json -o "$OUT/open_ports.json" || true
      fi
      if [[ -s "$OUT/ips6_in_scope.txt" ]]; then
        run_to "$T_NAABU" "$NAABU_BIN" -list "$OUT/ips6_in_scope.txt" -top-ports "$NAABU_TOP" -rate "$NAABU_RATE" -json -o- \
          | tee -a "$OUT/open_ports.json" >/dev/null
      fi
      if [[ -n "$JQ_BIN" ]]; then
        "$JQ_BIN" -r 'select(.ip!=null and .port!=null) | "\(.ip):\(.port)"' "$OUT/open_ports.json" | sort -u > "$OUT/open_ports.txt"
        "$JQ_BIN" -r 'select(.ip!=null and .port!=null) | [ .ip, (.port|tostring) ] | @csv' \
          "$OUT/open_ports.json" | sort -u > "$OUT/ip_port_pairs.csv"
      else
        awk -F: '{print $1":"$2}' "$OUT/open_ports.txt" | sort -u -o "$OUT/open_ports.txt"
        awk -F: '{print $1","$2}' "$OUT/open_ports.txt" | sort -u > "$OUT/ip_port_pairs.csv"
      fi
      if [[ "$INCREMENTAL" -eq 1 && -s "$TARGET_LIST" ]]; then
        cat "$TARGET_LIST" >> "$SCANNED_IPS"; sort -u -o "$SCANNED_IPS" "$SCANNED_IPS"
      fi
    else
      echo "[!] Inga IP att skanna – fallback: subdomains"
      run_to "$T_NAABU" "$NAABU_BIN" -list "$OUT/subdomains.txt" -top-ports "$NAABU_TOP" -rate "$NAABU_RATE" -json -o "$OUT/open_ports.json" || true
      if [[ -n "$JQ_BIN" ]]; then
        "$JQ_BIN" -r 'select(.ip!=null and .port!=null) | "\(.ip):\(.port)"' "$OUT/open_ports.json" | sort -u > "$OUT/open_ports.txt"
        "$JQ_BIN" -r 'select(.ip!=null and .port!=null) | [ .ip, (.port|tostring) ] | @csv' \
          "$OUT/open_ports.json" | sort -u > "$OUT/ip_port_pairs.csv"
      fi
    fi
  else
    echo '[i] --skip-portscan aktivt.'
  fi

  echo "[i] öppna_portar_rader=$(wc -l < "$OUT/open_ports.txt")"
  if [[ -s "$OUT/open_ports.txt" ]]; then
    if [[ -s "$OUT/resolved.txt" ]]; then
      awk '{h=$1; for(i=1;i<=NF;i++){if($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || $i ~ /:/) print $i","h}}' \
        "$OUT/resolved.txt" | sort -u > "$OUT/_ip_host_pairs.csv"
      awk -F, '{a[$1]=a[$1]","$2} END{for(ip in a){sub(/^,/, "", a[ip]); print ip","a[ip]}}' \
        "$OUT/_ip_host_pairs.csv" | sort -t , -k1,1 -u > "$OUT/ip_hosts.csv"
      join -t , -1 1 -2 1 "$OUT/ip_port_pairs.csv" "$OUT/ip_hosts.csv" > "$OUT/ip_port_hosts.csv" || true
    else
      cp "$OUT/ip_port_pairs.csv" "$OUT/ip_port_hosts.csv"
    fi
    awk -F: '{p[$1]=p[$1]","$2} END{for (ip in p){sub(/^,/, "", p[ip]); print ip " -> " p[ip]}}' \
      "$OUT/open_ports.txt" | sort > "$OUT/ports_by_ip.txt"
  fi
}

step7_tlsx() {
  : > "$OUT/subs_from_certs.txt"; : > "$OUT/subs_from_certs.in_scope.txt"
  if [[ -n "$TLSX_BIN" && -s "$OUT/open_ports.json" && -n "$JQ_BIN" ]]; then
    "$JQ_BIN" -r 'select(.port==443 or .port==8443) | .ip' "$OUT/open_ports.json" 2>/dev/null \
      | sort -u \
      | run_to "$T_TLSX" "$TLSX_BIN" -san -cn -resp-only -silent \
      | tr ' ' '\n' | tr -d '"*,' \
      | sed 's/^www\.//' \
      | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
      | sort -u > "$OUT/subs_from_certs.txt" || true

    awk '{g=$0; gsub(/[[.\\]{}()^$|?+*]/,"\\&",g); print "(^|\\.)" g "$"}' "$DOMAINS_NORM" > "$OUT/apex_regex.txt"
    grep -Ei -f "$OUT/apex_regex.txt" "$OUT/subs_from_certs.txt" | sort -u > "$OUT/subs_from_certs.in_scope.txt" || true

    if [[ -s "$OUT/subs_from_certs.in_scope.txt" ]]; then
      cat "$OUT/subs_from_certs.in_scope.txt" >> "$OUT/subdomains.txt"
      sort -u -o "$OUT/subdomains.txt" "$OUT/subdomains.txt"
      echo "[i] TLSX nya subdomäner=$(wc -l < "$OUT/subs_from_certs.in_scope.txt")"
    fi
  else
    echo '[i] tlsx saknas / inga 443/8443 / saknar jq – hoppar över.'
  fi
}

step8_http() {
  run_to "$T_HTTPX" "$HTTPX_BIN" -l "$OUT/subdomains.txt" -ip -status-code -title -tech-detect -web-server -rl "$HTTPX_RL" -json -o "$OUT/services_httpx.json" || true
  if [[ -n "$JQ_BIN" ]]; then
    "$JQ_BIN" -r '[.input,.host,.status_code,(.title//""),(.tech//[]|join("+")),(.webserver//"")] | @tsv' \
      "$OUT/services_httpx.json" 2>/dev/null | sed 's/\t/  /g' > "$OUT/services_httpx.txt" || true
  fi
  "$HTTPX_BIN" -l "$OUT/subdomains.txt" -rl "$HTTPX_RL" -silent -o "$OUT/urls_httpx.txt" || true
}

step9_history() {
  : > "$OUT/historical_endpoints.txt"
  [[ -n "$GAU_BIN" ]] && "$GAU_BIN" -l "$OUT/subdomains.txt" | sort -u >> "$OUT/historical_endpoints.txt" || true
  [[ -n "$WBU_BIN" ]] && "$WBU_BIN" < "$OUT/subdomains.txt" | sort -u >> "$OUT/historical_endpoints.txt" || true
  sort -u -o "$OUT/historical_endpoints.txt" "$OUT/historical_endpoints.txt"
  echo "[i] historical_endpoints=$(wc -l < "$OUT/historical_endpoints.txt")"
}

step10_katana() {
  if [[ "$SKIP_KATANA" -eq 1 || -z "$KATANA_BIN" ]]; then
    : > "$OUT/katana_endpoints.txt"
  else
    run_to "$T_KATANA" "$KATANA_BIN" -list "$OUT/urls_httpx.txt" -depth 3 -concurrency "$KATANA_C" -jc -silent -o "$OUT/katana_endpoints.txt" || true
  fi
}

step11_shots() {
  : > "$OUT/screenshots/index.txt"
  if [[ -n "$GOW_BIN" ]]; then
    mkdir -p "$OUT/screenshots"
    head -n "$GW_LIMIT" "$OUT/urls_httpx.txt" > "$OUT/urls_for_shots.txt"
    "$GOW_BIN" file -f "$OUT/urls_for_shots.txt" -P "$OUT/screenshots" --threads 4 --timeout 15 --log-level warn || true
    find "$OUT/screenshots" -type f -name '*.png' -printf '%f\n' | sort > "$OUT/screenshots/index.txt" || true
  else
    echo '[i] gowitness saknas – hoppar över skärmdumpar.'
  fi
}

step12_nuclei() {
  if [[ "$SKIP_NUCLEI" -eq 1 || -z "$NUCLEI_BIN" ]]; then
    : > "$OUT/nuclei_findings.txt"
  else
    run_to "$T_NUCLEI" "$NUCLEI_BIN" -l "$OUT/urls_httpx.txt" -tags cve,exposures,misconfig,takeover -severity medium,high,critical -rl 50 -o "$OUT/nuclei_findings.txt" || true
  fi
}

step13_report() { generate_report; }

# ---------- Kör pipeline ----------
run_step 1  "${STEPS[0]}"  "${WEIGHTS[0]}"  step1_passive
run_step 2  "${STEPS[1]}"  "${WEIGHTS[1]}"  step2_bruteforce
run_step 3  "${STEPS[2]}"  "${WEIGHTS[2]}"  step3_wildcard
run_step 4  "${STEPS[3]}"  "${WEIGHTS[3]}"  step4_resolve
run_step 5  "${STEPS[4]}"  "${WEIGHTS[4]}"  step5_scope
run_step 6  "${STEPS[5]}"  "${WEIGHTS[5]}"  step6_portscan
run_step 7  "${STEPS[6]}"  "${WEIGHTS[6]}"  step7_tlsx
run_step 8  "${STEPS[7]}"  "${WEIGHTS[7]}"  step8_http
run_step 9  "${STEPS[8]}"  "${WEIGHTS[8]}"  step9_history
run_step 10 "${STEPS[9]}"  "${WEIGHTS[9]}"  step10_katana
run_step 11 "${STEPS[10]}" "${WEIGHTS[10]}" step11_shots
run_step 12 "${STEPS[11]}" "${WEIGHTS[11]}" step12_nuclei
run_step 13 "${STEPS[12]}" "${WEIGHTS[12]}" step13_report

echo
log_ok "KLART. Se $OUT/  (logg: $LOG, rapport: $OUT/report.md, $OUT/report.html)"
