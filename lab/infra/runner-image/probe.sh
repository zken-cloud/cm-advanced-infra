#!/bin/bash
echo "=== ENV ==="; uname -a; echo "ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
dmesg 2>/dev/null | head -1
cm --version
export HOME=/home/cm; mkdir -p $HOME/.codemender
cp /etc/codemender/config.yaml $HOME/.codemender/config.yaml
cp /etc/codemender/command_policy.yaml $HOME/.codemender/command_policy.yaml
echo "=== config parse ==="; cm init --verify 2>&1 | grep -E 'Config parsing|Server |Results' 
echo "=== identity (WIF) ==="
curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email; echo

cd /work && git init -q . 2>/dev/null; git add -A 2>/dev/null; git -c user.email=a@b -c user.name=c commit -qm init 2>/dev/null

echo "=== R1a: find (no --sandbox) ==="
S=$(date +%s); cm find app -y --bypass-warning > /tmp/f1 2>&1; RC=$?; E=$(date +%s)
echo "rc=$RC seconds=$((E-S))"; tail -6 /tmp/f1

echo "=== R1b: verify under gVisor (exercises run_command + exploit exec) ==="
FID=$(python3 -c "
import sqlite3,os
c=sqlite3.connect('file:'+os.environ['HOME']+'/.codemender/state.db?mode=ro',uri=True)
r=c.execute(\"select finding_id from findings where vuln_id like 'CWE-89%' limit 1\").fetchone()
print(r[0] if r else '')" 2>/dev/null)
echo "finding=$FID"
if [ -n "$FID" ]; then
  S=$(date +%s); cm verify $FID -y --bypass-warning > /tmp/v1 2>&1; RC=$?; E=$(date +%s)
  echo "rc=$RC seconds=$((E-S))"; tail -8 /tmp/v1
fi

echo "=== R1c: find WITH --sandbox (the gVisor nesting test) ==="
S=$(date +%s); cm find app -y --bypass-warning --sandbox > /tmp/f2 2>&1; RC=$?; E=$(date +%s)
echo "rc=$RC seconds=$((E-S))"; tail -12 /tmp/f2
grep -iE 'sandbox|SIGSYS|ptrace|seccomp|denied|exebox' /tmp/f2 | head -10
