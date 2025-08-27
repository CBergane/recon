SHELL := /bin/bash

PROG     ?= $(shell basename $$(pwd))
BASE     := $(HOME)/recon/$(PROG)
IN       := $(BASE)/input

export GOPATH := $(HOME)/go
export PATH   := $(GOPATH)/bin:$(HOME)/.local/bin:/usr/local/go/bin:$(PATH)
GOENV   := env GOTOOLCHAIN=auto

WORDLIST ?= /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt
PROFILE  ?= home  # mobile|home|office|vps

.PHONY: help install prepare envcheck run run-vps clean
help:
	@echo "Targets: install, prepare, run, run-vps, envcheck, clean"

install:
	apt-get update -y || true
	apt-get install -y --no-install-recommends git make jq moreutils chromium fonts-liberation pandoc golang-go massdns seclists pv parallel libpcap-dev pkg-config || true
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
	$(GOENV) go install github.com/owasp-amass/amass/v4/cmd/amass@latest || true
	$(GOENV) go install github.com/lc/gau@latest
	$(GOENV) go install github.com/tomnomnom/waybackurls@latest
	$(GOENV) go install github.com/sensepost/gowitness@latest
	$(GOENV) go install github.com/tomnomnom/assetfinder@latest
	$(GOENV) go install github.com/d3mondev/puredns/v2@latest
	python3 -m pip install --user --upgrade pipx || true
	python3 -m pipx ensurepath || true
	pipx install dnsgen || true
	command -v setcap >/dev/null 2>&1 && setcap cap_net_raw,cap_net_admin+eip "$$(command -v naabu)" || true
	nuclei -update-templates || true

prepare:
	mkdir -p $(BASE)/{input,raw,out}
	@[ -f $(IN)/domains.txt ]   || (echo "example.com" > $(IN)/domains.txt)
	@[ -f $(IN)/resolvers.txt ] || (printf "1.1.1.1\n8.8.8.8\n9.9.9.9\n208.67.222.222\n" > $(IN)/resolvers.txt)
	@[ -f $(IN)/resolvers6.txt ] || (printf "2606:4700:4700::1111\n2001:4860:4860::8888\n2620:fe::fe\n2620:119:35::35\n" > $(IN)/resolvers6.txt)
	@[ -f $(IN)/resolvers-trusted.txt ] || (printf "1.1.1.1\n8.8.8.8\n9.9.9.9\n208.67.222.222\n2606:4700:4700::1111\n2001:4860:4860::8888\n2620:fe::fe\n2620:119:35::35\n" > $(IN)/resolvers-trusted.txt)
	@[ -f $(IN)/asn.txt ]       || (echo "AS13335" > $(IN)/asn.txt)
	@[ -f $(IN)/orgs.txt ]      || (echo "GOOGLE"  > $(IN)/orgs.txt)

envcheck:
	@echo "GOPATH=$(GOPATH)"
	@echo "PATH=$(PATH)"
	@command -v subfinder   >/dev/null && echo "subfinder OK"       || echo "subfinder MISSING"
	@command -v assetfinder >/dev/null && echo "assetfinder OK"     || echo "assetfinder MISSING"
	@command -v amass       >/dev/null && echo "amass OK"           || echo "amass MISSING"
	@command -v dnsx        >/dev/null && echo "dnsx OK"            || echo "dnsx MISSING"
	@command -v naabu       >/dev/null && echo "naabu OK"           || echo "naabu MISSING"
	@command -v httpx       >/dev/null && echo "httpx OK"           || echo "httpx MISSING"
	@command -v asnmap      >/dev/null && echo "asnmap OK"          || echo "asnmap MISSING"
	@command -v mapcidr     >/dev/null && echo "mapcidr OK"         || echo "mapcidr MISSING"
	@command -v puredns     >/dev/null && echo "puredns OK"         || echo "puredns MISSING"
	@command -v katana      >/dev/null && echo "katana OK"          || echo "katana MISSING"
	@command -v nuclei      >/dev/null && echo "nuclei OK"          || echo "nuclei MISSING"
	@command -v chromium    >/dev/null && echo "chromium OK"        || echo "chromium MISSING"
	@command -v gowitness   >/dev/null && echo "gowitness OK"       || echo "gowitness MISSING"
	@command -v jq          >/dev/null && echo "jq OK"              || echo "jq MISSING"

run:
	@echo "[*] Running recon.sh in $(BASE) (PROFILE=$(PROFILE))"
	BASE=$(BASE) PROFILE=$(PROFILE) IN=$(IN) OUTROOT=$(BASE)/out WORDLIST=$(WORDLIST) ./recon.sh

run-vps:
	$(MAKE) run PROFILE=vps

clean:
	rm -rf $(BASE)/raw/* $(BASE)/out/* 2>/dev/null || true
