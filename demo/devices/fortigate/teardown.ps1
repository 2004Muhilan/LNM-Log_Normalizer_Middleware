<#
Removes EVERYTHING the FortiGate lab and the Suricata sensor added, in one command. Written for the operator; NOT run by the build or the gate.

    powershell -ExecutionPolicy Bypass -File demo\devices\fortigate\teardown.ps1            # asks you to type DELETE
    powershell -ExecutionPolicy Bypass -File demo\devices\fortigate\teardown.ps1 -Force     # no question
    ... -KeepBackup C:\fgt-backup                                                             # copy the licensed VM disk out first

Run it in an ELEVATED PowerShell ("Run as administrator"): removing the portproxy rule needs it.

IRREVERSIBLE. The FortiGate's evaluation licence is one per account and lives in this VM's disk (inside the container's
writable layer, and in the backups under /home/clab/fgt-backup in the Containerlab distro). Unregistering the distro
deletes all of it. -KeepBackup copies /home/clab/fgt-backup (the licensed overlay disk and the original vrnetlab files)
to a Windows folder first.

What it removes, in order:
  1. in the Containerlab distro (its own Docker engine): the Suricata sensor (containers fgt-ids and fgt-ids-syslog,
     volume ulpf-ids-log, image ulpf/suricata:alpine3.20 — demo/devices/suricata), the traffic containers fgt-client and
     fgt-server, the FortiGate container clab-fortigate-fgt, the images vrnetlab/vr-fortios:7.4.12 and alpine:3.20, the
     keep-alive processes (in the distro, and the hidden Windows-side session ulpf-clab-keepalive that keeps it up);
  2. the Containerlab WSL distro itself (`wsl --unregister Containerlab`): the distro, its virtual disk, containerlab,
     vrnetlab, the lab directory and the backups;
  3. the Windows portproxy rule 127.0.0.1:8443 -> the distro (the FortiGate web UI);
  4. on the ULPF side (the Ubuntu distro): the raw captures and the analysis, ~/ulpf-fortigate.
What it does NOT touch, on purpose:
  * %USERPROFILE%\.wslconfig `nestedVirtualization=true` — revert by hand (docs/real-device-fortigate.md, "Reverting
    nested virtualization"): other WSL work may rely on it;
  * the repository: demo/devices/fortigate/, demo/devices/suricata/, the inventory entries for 172.20.20.2 and
    172.20.20.11 and ULPF_REAL_DEVICES (off unless set) stay; they do nothing without the lab;
  * Docker Desktop, the Ubuntu distro and the ULPF demo.
#>
param([switch]$Force, [string]$KeepBackup = "")
$ErrorActionPreference = "Continue"
$distro = "Containerlab"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "Run this in an elevated PowerShell (Run as administrator): the portproxy rule cannot be removed otherwise."; exit 1 }

$present = (wsl -l -q) -replace "`0", "" | Where-Object { $_.Trim() -eq $distro }
Write-Host "This removes the FortiGate lab and the Suricata sensor: containers, images, the '$distro' WSL distro (and with it the licensed VM and its backups), and the portproxy rule on 127.0.0.1:8443."
Write-Host "The FortiGate evaluation licence (one per account) cannot be recovered afterwards unless you keep the backup (-KeepBackup <folder>)."
if (-not $Force) {
  $a = Read-Host "Type DELETE to continue"
  if ($a -ne "DELETE") { Write-Host "Nothing removed."; exit 1 }
}

if ($present) {
  if ($KeepBackup) {
    New-Item -ItemType Directory -Force $KeepBackup | Out-Null
    $win = (wsl -d $distro -- wslpath -u "$KeepBackup").Trim()
    Write-Host "copying /home/clab/fgt-backup to $KeepBackup ..."
    wsl -d $distro -- bash -c "cp -a /home/clab/fgt-backup/. '$win/' && ls -la '$win'"
    if ($LASTEXITCODE -ne 0) { Write-Host "backup copy FAILED — stopping, nothing removed"; exit 1 }
  }
  Write-Host "1. containers and images in the $distro engine"
  wsl -d $distro -- bash -c "pkill -f ulpf-fortigate-keepalive; pkill -f ulpf-clab-keepalive; docker rm -f fgt-ids fgt-ids-syslog fgt-client fgt-server clab-fortigate-fgt 2>&1; docker volume rm ulpf-ids-log 2>&1; docker rmi -f ulpf/suricata:alpine3.20 vrnetlab/vr-fortios:7.4.12 alpine:3.20 2>&1; sudo -n ip link del ulpf-cli1 2>/dev/null; true"
  Write-Host "2. the $distro WSL distro"
  wsl --terminate $distro
  wsl --unregister $distro
} else {
  Write-Host "the $distro distro is not registered: skipping 1-2"
}

Write-Host "3. the portproxy rule 127.0.0.1:8443"
netsh interface portproxy delete v4tov4 listenport=8443 listenaddress=127.0.0.1
netsh interface portproxy show all

Write-Host "4. the ULPF side: ~/ulpf-fortigate and ~/ulpf-suricata (captures and analysis)"
wsl -d Ubuntu -- bash -c "rm -rf ~/ulpf-fortigate ~/ulpf-suricata"

Write-Host ""
Write-Host "Done. Left on purpose: .wslconfig nestedVirtualization=true (see docs/real-device-fortigate.md to revert it), and"
Write-Host "the repository files. WSL distros now:"
wsl -l -v
