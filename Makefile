SHELL := /bin/bash

# --- Bas ---
PROG     ?= $(shell basename $$(pwd))
BASE     := $(HOME)/recon/$(PROG)
IN       := $(BASE)/input

# --- Miljö (Go-binaries hamnar i $(GOPATH)/bin), pipx i ~/.local/bin ---
export GOPATH := $(HOME)/go
export PATH   := $(GOPATH)/bin:$(HOME)/.local/bin:$(PATH)

# --- Standardvärden ---
WORDLIST ?= /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt
PROFILE  ?= home   # mobile | home | office | vps

# gör help till default
default: help

install:
	# Systempaket
	sudo apt update
	sudo apt install -y golang-go jq ripgrep git dnsutils massdns python3-pip build-essential seclists pv parallel whiptail moreutils \
	                    libpcap-dev pkg-config chromium fonts-liberation pandoc


	# ProjectDiscovery
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
	go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
	go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
	go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
	go install github.com/projectdiscovery/katana/cmd/katana@latest
	go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

	# OWASP Amass (Go) – valfritt
	-go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest || true
	-sudo apt install -y amass || true

	# Historik / screenshots
	go install github.com/lc/gau@latest
	go install github.com/tomnomnom/waybackurls@latest
	go install github.com/sensepost/gowitness@latest

	# Övrigt
	go install github.com/tomnomnom/assetfinder@latest

	# dnsgen – Python
	sudo apt install -y dnsgen

	# Tillåt naabu att köra raw sockets utan sudo (om setcap finns)
	@command -v naabu >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1 && sudo setcap cap_net_raw,cap_net_admin+eip "$$(command -v naabu)" || true

prepare:
	mkdir -p $(BASE)/{input,raw,out}
	@[ -f $(IN)/domains.txt ]   || (echo "exempel.com" > $(IN)/domains.txt)
	@[ -f $(IN)/resolvers.txt ] || (printf "1.1.1.1\n8.8.8.8\n9.9.9.9\n" > $(IN)/resolvers.txt)
	@[ -f $(IN)/tlds.txt ]      || (printf "com\nse\nfi\nno\ndk\nnet\norg\nio\napp\nco.uk\n" > $(IN)/tlds.txt)

envcheck:
	@echo "GOPATH=$(GOPATH)"
	@echo "PATH=$(PATH)"
	@command -v subfinder   >/dev/null && echo "subfinder OK"       || echo "subfinder MISSING"
	@command -v amass       >/dev/null && echo "amass OK"           || echo "amass MISSING"
	@command -v assetfinder >/dev/null && echo "assetfinder OK"     || echo "assetfinder MISSING"
	@command -v dnsx        >/dev/null && echo "dnsx OK"            || echo "dnsx MISSING"
	@command -v naabu       >/dev/null && echo "naabu OK"           || echo "naabu MISSING"
	@command -v httpx       >/dev/null && echo "httpx OK"           || echo "httpx MISSING"
	@command -v puredns     >/dev/null && echo "puredns OK"         || echo "puredns MISSING"
	@command -v shuffledns  >/dev/null && echo "shuffledns OK"      || echo "shuffledns MISSING"
	@command -v gau         >/dev/null && echo "gau OK"             || echo "gau MISSING"
	@command -v waybackurls >/dev/null && echo "waybackurls OK"     || echo "waybackurls MISSING"
	@command -v gowitness   >/dev/null && echo "gowitness OK"       || echo "gowitness MISSING"
	@command -v tlsx        >/dev/null && echo "tlsx OK"            || echo "tlsx MISSING"
	@command -v pandoc      >/dev/null && echo "pandoc OK"          || echo "pandoc MISSING"
	@command -v chromium    >/dev/null && echo "chromium OK"        || echo "chromium MISSING"
	@command -v ts          >/dev/null && echo "ts (moreutils) OK"  || echo "ts MISSING"

run:
	@echo "[*] Running recon.sh in $(BASE) (PROFILE=$(PROFILE))"
	@PROFILE="$(PROFILE)" WORDLIST="$(WORDLIST)" bash "$(BASE)/recon.sh" -p $(PROFILE)

run-home:
	@$(MAKE) run PROFILE=home

run-vps:
	@$(MAKE) run PROFILE=vps

light:
	@PROFILE="$(PROFILE)" WORDLIST="$(WORDLIST)" bash -c ' \
	  export SKIP_BRUTE=1 SKIP_PORTSCAN=1; bash "$(BASE)/recon.sh" -p $(PROFILE)'

heavy:
	@$(MAKE) run PROFILE=vps

report:
	@echo "[*] Building report from existing artifacts in $(BASE)"
	@PROFILE="$(PROFILE)" REPORT_ONLY=1 YES=1 bash "$(BASE)/recon.sh" -p $(PROFILE)

report-open: report
	@d="$$(readlink -f "$(BASE)/out.latest" 2>/dev/null || echo "$(BASE)/out")"; \
	  f="$$d/report.html"; \
	  if which xdg-open >/dev/null 2>&1; then xdg-open "$$f"; else echo "Öppna $$f manuellt."; fi

dry-run:
	@echo "[*] Dry-run in $(BASE) (PROFILE=$(PROFILE))"
	@PROFILE="$(PROFILE)" WORDLIST="$(WORDLIST)" DRY_RUN=1 bash "$(BASE)/recon.sh" -p $(PROFILE)

clean:
	rm -rf $(BASE)/raw/* $(BASE)/out/*

help:
	@echo "Targets:"
	@echo "  make install                - Installera verktyg och beroenden (libpcap-dev etc.)"
	@echo "  make prepare                - Skapa input/, raw/, out/ + basfiler (+ default tlds.txt)"
	@echo "  make envcheck               - Visa PATH/GOPATH och verktygsstatus"
	@echo "  make run PROFILE=home       - Kör recon.sh (PROFILE=mobile|home|office|vps)"
	@echo "  make run-home / run-vps     - Snabbkommandon"
	@echo "  make light                  - Hoppa över brute + portscan"
	@echo "  make heavy                  - vps-profil med allt"
	@echo "  make dry-run                - Visa steg/procent utan att köra verktygen"
	@echo "  make report                 - Bygg endast rapport (md + html) av befintliga artefakter"
	@echo "  make report-open            - Öppna report.html (out.latest/)"
	@echo ""
	@echo "Input:"
	@echo "  input/domains.txt  – apex eller wildcard (*.exempel.com / exempel.*)"
	@echo "  input/tlds.txt     – TLD/suffix att expandera 'exempel.*' (stödjer även 'co.uk')"
	@echo "  input/ips.txt      – (valfritt) extra IP"
	@echo "  input/cidrs.txt    – (valfritt) extra CIDR"
	@echo ""

.PHONY: install prepare envcheck run run-home run-vps light heavy report report-open dry-run clean help
