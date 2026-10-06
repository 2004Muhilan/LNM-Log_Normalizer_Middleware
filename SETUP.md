# ULPF setup, step by step

This guide installs everything on a **Windows 11 PC with an NVIDIA GPU**, the way we run it. Each step says where to run
the commands:
- **PowerShell (admin):** Windows PowerShell started with "Run as administrator".
- **Ubuntu:** the Ubuntu WSL terminal (ULPF runs here).
- **Lab:** the `Containerlab` WSL terminal (the FortiGate and Suricata run here).

| Part | What you get |
|---|---|
| 1. Windows | WSL2, NVIDIA driver, Docker Desktop |
| 2. ULPF | the code, tools, model, test data |
| 3. First demo | the generator demo in your browser |
| 4. FortiGate lab | a licensed FortiGate VM sending real logs |
| 5. Suricata | an IDS watching the same traffic |
| 6. Final demo | everything in containers with the real devices |

Parts 1–3 are enough to see ULPF work. Parts 4–6 add the real devices.
You need internet during setup; after that everything runs offline.

---

## Part 1 — Windows

### Step 1. Turn on virtualization
Restart into your BIOS/UEFI and enable **Intel VT-x** or **AMD-V (SVM)**. In Windows, Task Manager → Performance → CPU
should then show "Virtualization: Enabled".

### Step 2. Install WSL2 and Ubuntu
PowerShell (admin):
```powershell
wsl --install -d Ubuntu
```
Restart when asked. Ubuntu opens and asks for a user name and password; choose any.

### Step 3. Give WSL enough memory, and allow nested virtualization
Create the file `C:\Users\<you>\.wslconfig` with:
```ini
[wsl2]
memory=24GB
nestedVirtualization=true
```
Use about two thirds of your RAM for `memory` (10GB on a 16 GB PC). `nestedVirtualization` is only needed for the
FortiGate VM (part 4). Then, PowerShell:
```powershell
wsl --shutdown
```

### Step 4. Update the NVIDIA driver
Install the latest **GeForce/Studio driver for Windows** from nvidia.com (version **570 or newer**). Do **not** install a
Linux driver inside WSL. Check in PowerShell:
```powershell
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv
```

### Step 5. Install Docker Desktop
1. Download Docker Desktop for Windows from docker.com and install it with the **WSL 2 backend**.
2. Settings → Resources → WSL integration → turn on **Ubuntu**. Apply and restart.
3. Check in Ubuntu:
   ```bash
   docker run --rm --gpus all nvidia/cuda:12.1.1-base-ubuntu22.04 nvidia-smi -L
   ```
   It should print your GPU. (If it doesn't, the model still runs on the CPU, much slower.)

---

## Part 2 — ULPF

### Step 6. Basic tools
Ubuntu:
```bash
sudo apt update && sudo apt install -y git curl python3-venv make
git config --global core.autocrlf false
```
(`autocrlf false` matters: Windows line endings break the scripts.)

### Step 7. Get the code
Ubuntu (we keep it on the C: drive at `C:\ulpf`, so both WSL distros can reach it as `/mnt/c/ulpf`):
```bash
git clone https://github.com/2004Muhilan/LNM-Log_Normalizer_Middleware.git /mnt/c/ulpf
cd /mnt/c/ulpf
```
All Ubuntu commands below run in `/mnt/c/ulpf`.

### Step 8. Install Go and the Python environment
```bash
bash scripts/wsl-bootstrap.sh
echo 'source ~/.ulpf-env' >> ~/.bashrc && source ~/.ulpf-env
```
This puts Go in `~/sdk` and a Python venv in `~/.venvs/ulpf`. No root needed.

### Step 9. Download the test data and the model
```bash
python corpus/tools/fetch_corpus.py                          # public test logs (stay on your disk, never committed)
python learning/tools/models.py fetch --id qwen3.5-4b-q4_k_m # the 2.7 GB model, digest-checked
mkdir -p ~/ulpf-models && cp models/cache/Qwen3.5-4B-Q4_K_M.gguf ~/ulpf-models/
```
Keep the model in `~/ulpf-models` (Linux disk): loading it from `/mnt/c` is very slow.

### Step 10. Build, create keys and vendor parsers
```bash
bash demo/reset.sh
```
This builds the Go binaries, creates your own development keys (never committed), signs the starting parser and builds
the FortiGate, PAN-OS and Cisco ASA parsers from the test data. About 1–2 minutes.

### Step 11. Download the SIEM and model images (internet, once)
```bash
docker pull opensearchproject/opensearch:2.19.2
docker pull opensearchproject/opensearch-dashboards:2.19.2
bash demo/llama-server.sh start      # first time downloads the llama.cpp CUDA image (~7 GB)
```
This puts 20 of the model's 33 layers on the GPU, which fits a 4 GB card and is what the checks in step 12 expect.
With 8 GB or more you can later run it with every layer on the GPU (faster):
`ULPF_LLAMA_NGL=99 bash demo/llama-server.sh start` (then run the step 12 check with `ULPF_DEMO_NGL_UNPINNED=1` in front).

### Step 12. Check everything
```bash
bash demo/preflight.sh
```
It must end with `PRE-FLIGHT: all clear`. If a line fails, it says what to fix.

---

## Part 3 — First demo

### Step 13. Start it
```bash
bash demo/start-demo.sh
```
Open in your browser:
- **Generator** http://127.0.0.1:8780 — choose a connector and a format, press Start
- **System** http://127.0.0.1:8765 — sources, onboarding, drift, Prove it
- **Data lake** http://127.0.0.1:8765/lake
- **SIEM** http://127.0.0.1:5601 (OpenSearch Dashboards)

### Step 14. Stop it
```bash
bash demo/start-demo.sh stop
bash demo/llama-server.sh stop
```
No GPU? Run `ULPF_DEMO_PROVIDER=fixture bash demo/start-demo.sh` instead; team-written proposals replace the model.

---

## Part 4 — FortiGate lab (real firewall)

The FortiGate runs as a VM inside a container, in a second WSL distro called `Containerlab`.

> **Read before you start: the licence.** Fortinet gives **one free evaluation licence per account**, bound to the VM
> you activate it on. After activation (step 22), **never run `containerlab deploy` or `containerlab destroy`** again:
> they create a new VM and the licence is lost. Use only `start.sh` (step 25) and `docker start/stop`. Keep 1 vCPU and
> 2 GB RAM; the evaluation allows at most 3 interfaces and 3 policies (the lab uses 2 of each).

### Step 15. Create a Fortinet account
1. Go to **https://support.fortinet.com** and choose **Register** (a free FortiCloud account).
2. Confirm your e-mail and log in.

### Step 16. Download the FortiGate VM image
1. In the support portal, open **Support → Downloads → VM Images**.
2. Select **Product: FortiGate**, **Platform: KVM**, version **7.4.x** (we use 7.4.12).
3. Download the file named like `FGT_VM64_KVM-v7.4.12.F-build2902-FORTINET.out.kvm.zip`.
4. Unzip it. Inside is `fortios.qcow2`. Note where it is (for example `C:\Downloads\fortios.qcow2`).

(Menu names can change slightly; look for "VM Images" and the KVM platform.)

### Step 17. Create the lab distro
PowerShell (admin):
```powershell
wsl --install Debian --name Containerlab
```
Choose user name `clab` and a password. (If your WSL is older and `--name` is unknown, run `wsl --update` first.)

### Step 18. Let the lab distro use KVM and sudo without a password
Lab:
```bash
sudo tee /etc/wsl.conf > /dev/null <<'EOF'
[boot]
systemd=true
command = /bin/bash -c 'chown -v root:kvm /dev/kvm && chmod 660 /dev/kvm'
EOF
echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/$USER
```
(The lab scripts run from PowerShell and call `sudo`; without the second line they would stop at a password prompt.)
PowerShell: `wsl --terminate Containerlab`, then open the Lab terminal again and check `ls -l /dev/kvm` (group `kvm`).

### Step 19. Install Docker Engine and Containerlab
Lab:
```bash
sudo apt update && sudo apt install -y curl git make
curl -sL https://containerlab.dev/setup | sudo -E bash -s "all"
sudo usermod -aG docker,clab_admins $USER
```
Close and reopen the Lab terminal, then check: `docker ps` and `containerlab version` (we use 0.79).

### Step 20. Build the FortiGate container image
Lab (replace the Windows path with yours):
```bash
git clone https://github.com/srl-labs/vrnetlab.git ~/vrnetlab
cp /mnt/c/Downloads/fortios.qcow2 ~/vrnetlab/fortinet/fortigate/fortios-v7.4.12.qcow2
cd ~/vrnetlab/fortinet/fortigate && make
docker images | grep fortios        # expect vrnetlab/vr-fortios:7.4.12
```

### Step 21. Create the lab — ONCE
1. Lab: create `~/fortigate.clab.yml`:
   ```yaml
   name: fortigate
   topology:
     nodes:
       fgt:
         kind: fortinet_fortigate
         image: vrnetlab/vr-fortios:7.4.12
         env:
           QEMU_SMP: "1"
           QEMU_MEMORY: "2048"
         ports:
           - 8443:443
   ```
2. Lab, **the only time you ever run deploy**:
   ```bash
   cd ~ && containerlab deploy -t fortigate.clab.yml
   ```
   Wait 5–10 minutes until `docker ps` shows `clab-fortigate-fgt` as healthy.
3. **Save the VM's UUID now.** The licence will be bound to it, and the container picks a new random one on every
   restart unless the lab scripts pin it. Lab:
   ```bash
   docker logs clab-fortigate-fgt 2>&1 | grep -o -- "-uuid [0-9a-f-]*" | head -1 | cut -d" " -f2 > ~/.fgt-uuid
   cat ~/.fgt-uuid
   ```
   It must print one UUID. `start.sh` reads this file from now on.

### Step 22. Activate the evaluation licence
1. Make the web page reachable from Windows. Lab: `hostname -I` (note the first address, e.g. 172.23.220.11).
   PowerShell (admin):
   ```powershell
   netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=8443 connectaddress=172.23.220.11 connectport=8443
   ```
   (The address can change after WSL restarts; re-run with the new one if the page stops loading.)
2. Open **https://localhost:8443** (accept the certificate warning). Log in as `admin` / `admin` and keep this password
   (the container logs in with it when it starts).
3. When the licence dialog appears, choose the **evaluation licence**, sign in with your **FortiCloud account** and
   accept. The VM reboots by itself. Log in again: *Dashboard → Status* shows the licence as **Valid**.
   (Fortinet's wording can differ slightly between versions.)

### Step 23. Let scripts log in with a key (never the password)
Lab:
```bash
ssh-keygen -t ecdsa -N "" -f ~/.ssh/id_ecdsa && cat ~/.ssh/id_ecdsa.pub
```
In the web page, open the **CLI console** (top right, `>_`) and enter, with your key between the quotes:
```
config system admin
edit admin
set ssh-public-key1 "ecdsa-sha2-nistp256 AAAA... clab@..."
end
```
Check from Lab: `ssh admin@172.20.20.2 "get system status"` (answer `yes` the first time). It prints the status and
`License Status: Valid` without asking for a password.

### Step 24. Back up the licensed VM
Lab:
```bash
docker stop clab-fortigate-fgt
mkdir -p ~/fgt-backup && docker cp clab-fortigate-fgt:/fortios-v7.4.12-overlay.qcow2 ~/fgt-backup/
```
Leave it stopped: do **not** use a plain `docker start` here. Step 25 starts it with the UUID pinned.

### Step 25. Start the lab (this is how you start it every time from now on)
PowerShell:
```powershell
wsl -d Containerlab -- bash /mnt/c/ulpf/demo/devices/fortigate/start.sh
```
It pins your UUID and adds the lab network port (port2), starts the FortiGate, adds a client and a server around it,
checks the licence (stops if it is not Valid) and starts a traffic loop. It must end with `FortiGate lab up`.

### Step 26. Apply the lab configuration (once)
Lab:
```bash
ssh -T admin@172.20.20.2 < /mnt/c/ulpf/demo/devices/fortigate/fortigate-base.conf
```
This sets the time zone, port2 for the lab clients, two policies (allow web, deny the rest), and syslog to ULPF at
`172.20.20.1:6515` over TCP.

---

## Part 5 — Suricata (real IDS)

### Step 27. Start Suricata on the FortiGate's wire
PowerShell (the first run builds a small image and needs internet):
```powershell
wsl -d Containerlab -- bash /mnt/c/ulpf/demo/devices/suricata/start.sh
```
No licence needed. Suricata watches the same connections the FortiGate filters and forwards its alerts to ULPF.

---

## Part 6 — Final demo, in containers

### Step 28. Prepare the shipped parsers
The container images include signed parser packs. On a fresh clone you are not the team's release authority, so create
your own (Ubuntu):
```bash
rm keys/trust/ulpf-pack-release.pub.json      # local only; do not commit this deletion
bash scripts/release-packs.sh                 # creates your release key in keys/release/ (keep it private)
```
(Alternatively, ask the team for the offline bundle and run `bash deploy/ulpf.sh import ulpf-latest.tar.gz` in the Lab
terminal, then skip step 29.)

### Step 29. Build the images
Lab (internet, once; the lab has its own Docker, so it needs its own copy of the SIEM images):
```bash
cd /mnt/c/ulpf && bash deploy/ulpf.sh build
docker pull opensearchproject/opensearch:2.19.2
docker pull opensearchproject/opensearch-dashboards:2.19.2
```

### Step 30. Settings for this machine
Lab:
```bash
mkdir -p ~/ulpf-models && cp /mnt/c/ulpf/models/cache/Qwen3.5-4B-Q4_K_M.gguf ~/ulpf-models/
cd /mnt/c/ulpf && cp deploy/env.example deploy/.env
echo "ULPF_MODELS_DIR=$HOME/ulpf-models" >> deploy/.env
echo "ULPF_LAB_AGENT=http://127.0.0.1:8799" >> deploy/.env
```

### Step 31. Run the final demo
Follow **[Running the demo](README.md#running-the-demo)** in the README: start the lab, start the model, stop any old
stack, run the device pre-flight, start the lab agent, start ULPF with `bash deploy/ulpf.sh up devices`, and open the
three pages. The same seven steps every time. What to press and say: [docs/demo-runbook.md](docs/demo-runbook.md).

### Step 32. Stop
```powershell
wsl -d Containerlab --cd /mnt/c/ulpf -- bash deploy/ulpf.sh down
wsl -d Ubuntu --cd /mnt/c/ulpf -- bash demo/llama-server.sh stop
```
The FortiGate keeps running until you stop it (`docker stop clab-fortigate-fgt` in Lab) or shut WSL down.

---

## Checking your installation

```bash
bash scripts/gate.sh        # Ubuntu; ~15–20 minutes; must end "GATE: PASS" (4 GB GPU: bash scripts/gate.sh --laptop)
```

## Common problems

| Problem | Fix |
|---|---|
| `nvidia-smi` fails in Docker | update the Windows driver (570+), restart Docker Desktop |
| Model very slow | model file under `/mnt/c`: keep it in `~/ulpf-models` |
| `port 6515 is busy` | stop the other demo: `bash demo/start-demo.sh stop` or `bash deploy/ulpf.sh down` |
| Pre-flight complains about CRLF | re-clone with `git config --global core.autocrlf false` |
| FortiGate page doesn't load | the WSL address changed: re-run the `netsh` command of step 22 with the new address |
| FortiGate not sending | the System page reconnects it; or re-run step 25 |
| Licence not Valid | stop; do not redeploy; restore the backup from step 24 |
| Everything stopped after closing windows | the lab distro shuts down when idle; `preflight.py` starts a hidden keep-alive |

## Removing everything

PowerShell (admin), removes the lab and its distro (**this deletes the licensed VM**; `-KeepBackup` copies it out first):
```powershell
powershell -ExecutionPolicy Bypass -File C:\ulpf\demo\devices\fortigate\teardown.ps1 -KeepBackup C:\fgt-backup
```
Then `wsl --unregister Ubuntu` if you want to remove ULPF's distro too, and delete `C:\ulpf`.
