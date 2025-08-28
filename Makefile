SHELL := /bin/bash

# ---- Paths / env ----
PROG     ?= $(shell basename $$(pwd))
BASE     := $(HOME)/recon/$(PROG)
IN       := $(BASE)/input

export HOME   ?= $(shell echo $$HOME)
export GOPATH ?= $(HOME)/go
export XDG_CACHE_HOME ?= $(HOME)/.cache
export GOCACHE ?= $(HOME)/.cache/go-build
export PATH   := $(GOPATH)/bin:/usr/local/go/bin:$(HOME)/.local/bin:/usr/sbin:/usr/bin:/bin:$(PATH)
GOENV   := env GOTOOLCHAIN=auto

WORDLIST ?= /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt
PROFILE  ?= vps  # mobile|home|office|vps

.PHONY: help install prepare envcheck run run-vps clean
help:
	@echo "Targets: install, prepare, envcheck, run, run-vps, clean"

install:
	@echo "[*] apt deps"
	apt-get update -y || true
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	  git make tmux jq moreutils chromium fonts-liberation pandoc golang-go \
	  bind9-dnsutils massdns seclists pv parallel libpcap-dev pkg-config \
	  libcap2-bin ca-certificates ripgrep || true

	@echo "[*] go tools (ProjectDiscovery + others)"
	$(GOENV) go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	$(GOENV) go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
	$(GOENV) go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	$(GOENV) go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	$(GOENV) go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
	$(GOENV) go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
	$(GOENV) go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
	$(GOENV) go install github.com/projectdiscovery/katana/cmd/katana@latest
	$(GOENV) go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	$(GOENV) go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
	$(GOENV) go install github.com/lc/gau@latest
	$(GOENV) go install github.com/tomnomnom/waybackurls@latest
	$(GOENV) go install github.com/sensepost/gowitness@latest
	$(GOENV) go install github.com/tomnomnom/assetfinder@latest
	$(GOENV) go install github.com/d3mondev/puredns/v2@latest

	@echo "[*] python dnsgen via pipx"
	python3 -m pip install --user --upgrade pipx || true
	python3 -m pipx ensurepath || true
	~/.local/bin/pipx install dnsgen || true

	@echo "[*] naabu capabilities (for SYN scan)"
	-command -v setcap >/dev/null 2>&1 && setcap cap_net_raw,cap_net_admin+eip "$$(command -v naabu)" || true

	@echo "[*] nuclei templates"
	-nuclei -update-templates || true

prepare:
	mkdir -p $(BASE)/{input,raw,out}
	@[ -f $(IN)/domains.txt ]   || (printf "nmap.org\nvulnweb.com\ntestfire.net\n" > $(IN)/domains.txt)
	@[ -f $(IN)/hosts.txt ]     || (printf "scanme.nmap.org\nexpired.badssl.com\nself-signed.badssl.com\nwrong.host.badssl.com\n" > $(IN)/hosts.txt)
	@[ -f $(IN)/resolvers.txt ] || (printf "1.1.1.1\n8.8.8.8\n9.9.9.9\n208.67.222.222\n" > $(IN)/resolvers.txt)
	@[ -f $(IN)/resolvers6.txt ] || (printf "2606:4700:4700::1111\n2001:4860:4860::8888\n2620:fe::fe\n2620:119:35::35\n" > $(IN)/resolvers6.txt)
	@[ -f $(IN)/resolvers-trusted.txt ] || (printf "1.1.1.1\n8.8.8.8\n9.9.9.9\n208.67.222.222\n2606:4700:4700::1111\n2001:4860:4860::8888\n2620:fe::fe\n2620:119:35::35\n" > $(IN)/resolvers-trusted.txt)
	@[ -f $(IN)/asn.txt ]       || (echo "AS13335" > $(IN)/asn.txt)
	@[ -f $(IN)/orgs.txt ]      || (echo "GOOGLE"  > $(IN)/orgs.txt)
	@echo "[*] subfinder warmup (creates ~/.config/subfinder/)"
	-subfinder -silent -d nmap.org -o /tmp/sf.warmup || true

envcheck:
	@echo "GOPATH=$(GOPATH)"
	@echo "PATH=$(PATH)"
	@echo "XDG_CACHE_HOME=$(XDG_CACHE_HOME)  GOCACHE=$(GOCACHE)"
	@command -v subfinder   >/dev/null && echo "subfinder OK ($$(subfinder -version 2>/dev/null | head -n1))"       || echo "subfinder MISSING"
	@command -v httpx       >/dev/null && echo "httpx CLI in PATH: $$(command -v httpx)"                           || echo "httpx MISSING"
	@command -v httpx-toolkit >/dev/null && echo "httpx-toolkit available: $$(command -v httpx-toolkit)"           || true
	@command -v gowitness   >/dev/null && echo "gowitness OK"                                                      || echo "gowitness MISSING"
	@command -v naabu       >/dev/null && echo "naabu OK ($$(naabu -version 2>/dev/null | head -n1))"              || echo "naabu MISSING"
	@command -v nuclei      >/dev/null && echo "nuclei OK ($$(nuclei -version 2>/dev/null | head -n1))"            || echo "nuclei MISSING"
	@command -v dnsx        >/dev/null && echo "dnsx OK"                                                           || echo "dnsx MISSING"
	@command -v katana      >/dev/null && echo "katana OK"                                                         || echo "katana MISSING"
	@command -v puredns     >/dev/null && echo "puredns OK"                                                        || echo "puredns MISSING"
	@command -v amass       >/dev/null && echo "amass OK ($$(amass -version 2>/dev/null | head -n1))"              || echo "amass MISSING"

run:
	@echo "[*] Running recon.sh in $(BASE) (PROFILE=$(PROFILE))"
	BASE=$(BASE) PROFILE=$(PROFILE) IN=$(IN) OUTROOT=$(BASE)/out WORDLIST=$(WORDLIST) ./recon.sh

run-vps:
	$(MAKE) run PROFILE=vps

clean:
	rm -rf $(BASE)/raw/* $(BASE)/out/* 2>/dev/null || true
