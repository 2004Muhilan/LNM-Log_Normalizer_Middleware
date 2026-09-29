#!/bin/sh
# Runs inside fgt-client (busybox): real connections through the FortiGate. Policy 1 (allow-web) accepts HTTP and ping to
# the lab server; policy 2 (deny-rest) denies and logs everything else — SSH, Telnet, SMB, RDP, HTTP on 8080, DNS.
S=172.20.20.10
while true; do
  wget -q -T 3 -O /dev/null "http://$S/" 2>/dev/null           # allowed
  ping -c 1 -W 1 "$S" > /dev/null 2>&1                          # allowed
  for p in 22 23 445 3389 8080; do nc -z -w 2 "$S" "$p" 2>/dev/null; done   # denied
  nslookup example.com 8.8.8.8 > /dev/null 2>&1                 # denied (DNS is not in allow-web)
  sleep 2
done
