#!/bin/sh
# Runs inside fgt-client (busybox): real connections through the FortiGate. Policy 1 (allow-web) accepts HTTP and ping to
# the lab server; policy 2 (deny-rest) denies and logs everything else — SSH, Telnet, SMB, RDP, HTTP on 8080, DNS.
# Suricata (demo/devices/suricata) sniffs this container's eth1, the same wire: Telnet, SMB and RDP attempts and the
# web attack below are deliberate triggers of its local rules, so one attack is logged by both devices.
S=172.20.20.10
while true; do
  wget -q -T 3 -O /dev/null "http://$S/" 2>/dev/null           # allowed
  wget -q -T 3 -U "sqlmap/1.7.2#stable" -O /dev/null "http://$S/cgi-bin/view?file=../../../../etc/passwd" 2>/dev/null   # allowed by the FortiGate; Suricata sid 9000004 + 9000005
  ping -c 1 -W 1 "$S" > /dev/null 2>&1                          # allowed
  for p in 22 23 445 3389 8080; do nc -z -w 2 "$S" "$p" 2>/dev/null; done   # denied; Suricata sid 9000001-9000003 (23, 445, 3389)
  nslookup example.com 8.8.8.8 > /dev/null 2>&1                 # denied (DNS is not in allow-web)
  sleep 2
done
