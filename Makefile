\
SHELL := /bin/bash

# --- Base ---
PROG     ?= $(shell basename $$(pwd))
BASE     := $(HOME)/recon/$(PROG)
IN       := $(BASE)/input

# --- Go env ---
export GOPATH := $(HOME)/go
export PATH   := $(GOPATH)/bin:$(HOME)/.local/bin:/usr/local/go/bin:$(PATH)
GOENV   := env GOTOOLCHAIN=auto

# --- Defaults ---
WORDLIST ?= /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt
PROFILE  ?= home  # mobile|home|office|vps

.PHONY: help install prepare envcheck run run-vps clean
help:
\t@echo "Targets: install, prepare, run, run-vps, envcheck, clean"

install:  ## Install core tools + templates + naabu setcap
\tapt-get update -y || true
\tapt-get install -y --no-install-recommends git make jq moreutils chromium fonts-liberation pandoc golang-go massdns seclists pv parallel libpcap-dev pkg-config || true
\t# Go tools
\t$(GOENV) go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
\t$(GOENV) go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
\t$(GOENV) go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
\t$(GOENV) go install github.com/projectdiscovery/httpx/cmd/httpx@latest
\t$(GOENV) go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
\t$(GOENV) go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
\t$(GOENV) go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
\t$(GOENV) go install github.com/projectdiscovery/katana/cmd/katana@latest
\t$(GOENV) go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
\t$(GOENV) go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
\t$(GOENV) go install github.com/owasp-amass/amass/v4/cmd/amass@latest || true
\t$(GOENV) go install github.com/lc/gau@latest
\t$(GOENV) go install github.com/tomnomnom/waybackurls@latest
\t$(GOENV) go install github.com/sensepost/gowitness@latest
\t$(GOENV) go install github.com/tomnomnom/assetfinder@latest
\t$(GOENV) go install github.com/d3mondev/puredns/v2@latest
\t# Python dnsgen (pipx)
\tpython3 -m pip install --user --upgrade pipx || true
\tpython3 -m pipx ensurepath || true
\tpipx install dnsgen || true
\t# naabu setcap (SYN scan utan root)
\tcommand -v setcap >/dev/null 2>&1 && setcap cap_net_raw,cap_net_admin+eip "$$(command -v naabu)" || true
\t# nuclei templates upfront
\tnuclei -update-templates || true

prepare:
\tmkdir -p $(BASE)/{input,raw,out}
\t@[ -f $(IN)/domains.txt ]   || (echo "example.com" > $(IN)/domains.txt)
\t@[ -f $(IN)/resolvers.txt ] || (printf "1.1.1.1\n8.8.8.8\n9.9.9.9\n" > $(IN)/resolvers.txt)
\t@[ -f $(IN)/asn.txt ]       || (echo "AS13335" > $(IN)/asn.txt)     # exempel
\t@[ -f $(IN)/orgs.txt ]      || (echo "GOOGLE"  > $(IN)/orgs.txt)    # exempel

envcheck:
\t@echo "GOPATH=$(GOPATH)"
\t@echo "PATH=$(PATH)"
\t@command -v subfinder   >/dev/null && echo "subfinder OK"       || echo "subfinder MISSING"
\t@command -v assetfinder >/dev/null && echo "assetfinder OK"     || echo "assetfinder MISSING"
\t@command -v amass       >/dev/null && echo "amass OK"           || echo "amass MISSING"
\t@command -v dnsx        >/dev/null && echo "dnsx OK"            || echo "dnsx MISSING"
\t@command -v naabu       >/dev/null && echo "naabu OK"           || echo "naabu MISSING"
\t@command -v httpx       >/dev/null && echo "httpx OK"           || echo "httpx MISSING"
\t@command -v asnmap      >/dev/null && echo "asnmap OK"          || echo "asnmap MISSING"
\t@command -v mapcidr     >/dev/null && echo "mapcidr OK"         || echo "mapcidr MISSING"
\t@command -v puredns     >/dev/null && echo "puredns OK"         || echo "puredns MISSING"
\t@command -v katana      >/dev/null && echo "katana OK"          || echo "katana MISSING"
\t@command -v nuclei      >/dev/null && echo "nuclei OK"          || echo "nuclei MISSING"
\t@command -v chromium    >/dev/null && echo "chromium OK"        || echo "chromium MISSING"
\t@command -v gowitness   >/dev/null && echo "gowitness OK"       || echo "gowitness MISSING"
\t@command -v jq          >/dev/null && echo "jq OK"              || echo "jq MISSING"

run:
\t@echo "[*] Running recon.sh in $(BASE) (PROFILE=$(PROFILE))"
\tBASE=$(BASE) PROFILE=$(PROFILE) IN=$(IN) OUTROOT=$(BASE)/out WORDLIST=$(WORDLIST) ./recon.sh

run-vps:
\t$(MAKE) run PROFILE=vps

clean:
\trm -rf $(BASE)/raw/* $(BASE)/out/* 2>/dev/null || true