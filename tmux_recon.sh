#!/bin/bash
# tmux layout: 1 fönster, 3 rutor (RUN | LOGS | WATCH)
set -Eeuo pipefail

SESSION="recon"
BASE="/root/recon/live"

mkdir -p "$BASE"
cd "$BASE"

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  # Vänster (RUN, 70%)
  tmux new-session -d -s "$SESSION" -n main \
    "cd $BASE; source /etc/profile.d/go.sh 2>/dev/null || true; clear; echo '[run] make run PROFILE=${PROFILE:-vps}'; bash"
  # Höger (kolumn, 30%)
  tmux split-window -t "$SESSION:0" -h -p 30 \
    "cd $BASE; source /etc/profile.d/go.sh 2>/dev/null || true; bash"
  # Höger-nere (rad, 50% av höger)
  tmux split-window -t "$SESSION:0.1" -v -p 50 \
    "cd $BASE; source /etc/profile.d/go.sh 2>/dev/null || true; bash"

  tmux select-pane -t "$SESSION:0.0"; tmux select-pane -T "RUN"
  tmux select-pane -t "$SESSION:0.1"; tmux select-pane -T "LOGS"
  tmux select-pane -t "$SESSION:0.2"; tmux select-pane -T "WATCH"

  # LOGS: följ senaste run.log
  tmux send-keys -t "$SESSION:0.1" \
    "source /etc/profile.d/go.sh 2>/dev/null || true; mkdir -p out; while true; do D=\$(ls -1td out/* 2>/dev/null | head -1); if [ -n \"\$D\" ]; then ln -sfn \"\$D\" out.latest; echo \"[logs] Tailing \$D/run.log\"; tail -F \"\$D/run.log\"; fi; sleep 2; done" C-m

  # WATCH: enkel dashboard
  tmux send-keys -t "$SESSION:0.2" \
    "source /etc/profile.d/go.sh 2>/dev/null || true; mkdir -p out; while true; do D=\$(ls -1td out/* 2>/dev/null | head -1); clear; date; if [ -n \"\$D\" ]; then ln -sfn \"\$D\" out.latest; echo; ls -lh \"\$D\" | sed -n '1,40p'; echo; echo '[nuclei]'; tail -n 40 \"\$D/nuclei_findings.txt\" 2>/dev/null || true; fi; sleep 5; done" C-m
fi

# Autorun om markeringsfil finns
if [ -f /root/recon/.autorun ]; then
  tmux send-keys -t "$SESSION:0.0" 'make run PROFILE=vps' C-m
fi

# Attach bara om terminal finns (inte i cloud-init)
if [ -t 1 ]; then
  tmux attach -t "$SESSION"
fi
