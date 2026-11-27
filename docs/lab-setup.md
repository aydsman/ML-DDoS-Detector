# Isolated VM lab: setup and capture

Three Ubuntu Server VMs on a VirtualBox internal network. Written for Windows hosts (PowerShell). All attack traffic stays inside the lab network.

| VM | Role | Lab IP (`enp0s8`) | SSH from host |
|----|------|-------------------|---------------|
| `ddos-server` | Protected web server, capture point, later the detector | 10.10.10.10 | `ssh -p 2222 lab@127.0.0.1` |
| `ddos-client` | Legitimate client | 10.10.10.20 | `ssh -p 2223 lab@127.0.0.1` |
| `ddos-attacker` | Traffic simulator (hping3) | 10.10.10.30 | `ssh -p 2224 lab@127.0.0.1` |

Every VM has two NICs:
- **NIC1 (`enp0s3`), NAT.** Static `10.0.2.15/24`, gateway `10.0.2.2`, DNS `10.0.2.3`. Used for SSH from the host (port forwards) and for `apt`.
- **NIC2 (`enp0s8`), internal network `ddoslab`.** `10.10.10.0/24`. This network has no adapter on the host, so nothing on it can reach your PC or the internet. Capture happens here.

Host requirements: virtualization enabled in BIOS, VirtualBox 7.x, about 6 GB free RAM and 40 GB free disk. Tested with VirtualBox 7.2.22 and Ubuntu Server 26.04.1.

In every new PowerShell window define the shortcut first:

```
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
```

## 1. Install

```
winget install -e --id Oracle.VirtualBox
```

Download the Ubuntu Server amd64 ISO from https://ubuntu.com/download/server.

## 2. Create the server VM

```
& $vb createvm --name ddos-server --ostype Ubuntu_64 --register
& $vb modifyvm ddos-server --memory 2048 --cpus 2 --nic1 nat --natpf1 "ssh,tcp,127.0.0.1,2222,,22" --nic2 intnet --intnet2 ddoslab --nicpromisc2 allow-all
& $vb createmedium disk --filename "$env:USERPROFILE\VirtualBox VMs\ddos-server\ddos-server.vdi" --size 15360
& $vb storagectl ddos-server --name SATA --add sata --controller IntelAhci
& $vb storageattach ddos-server --storagectl SATA --port 0 --device 0 --type hdd --medium "$env:USERPROFILE\VirtualBox VMs\ddos-server\ddos-server.vdi"
& $vb storageattach ddos-server --storagectl SATA --port 1 --device 0 --type dvddrive --medium "C:\path\to\ubuntu-server.iso"
& $vb startvm ddos-server
```

Installer choices: whole disk with defaults, DHCP on both adapters, server name `ddos-server`, user `lab`, install OpenSSH server, no snaps. Reboot, then detach the ISO:

```
& $vb storageattach ddos-server --storagectl SATA --port 1 --device 0 --type dvddrive --medium emptydrive
```

## 3. Configure the server

SSH in (`ssh -p 2222 lab@127.0.0.1`, answer `yes` to the host key) and run:

```
sudo apt update && sudo apt install -y nginx tcpdump net-tools curl

printf 'network:\n  version: 2\n  ethernets:\n    enp0s8:\n      dhcp4: false\n      addresses: [10.10.10.10/24]\n' | sudo tee /etc/netplan/60-lab.yaml

printf 'network:\n  version: 2\n  ethernets:\n    enp0s3:\n      dhcp4: false\n      dhcp6: false\n      accept-ra: false\n      addresses: [10.0.2.15/24]\n      routes:\n        - to: default\n          via: 10.0.2.2\n      nameservers:\n        addresses: [10.0.2.3]\n' | sudo tee /etc/netplan/70-nat-routes.yaml

sudo chmod 600 /etc/netplan/*.yaml && sudo netplan apply
ip -br a
curl -sI http://10.10.10.10 | head -1
```

Expected: `enp0s8` shows `10.10.10.10/24` and curl prints `HTTP/1.1 200 OK`.

### Why the NAT NIC is static (do not switch it back to DHCP)

On our setup the NAT adapter's DHCP also handed out extra host routes (`10.10.10.10` and `10.10.10.12` via `10.0.2.2`). Those are more specific than the lab `/24`, so traffic to the server left through NAT instead of the lab network. The symptom was `ping` replies with `ttl=61` (instead of 64) and `curl` timing out. The fixed address and route above avoid it.

## 4. Clone the client and the attacker

Power the server off (`sudo poweroff`) and clone it. Cloning copies the server's identity, so each clone must be fixed before it joins the network.

```
& $vb clonevm ddos-server --name ddos-client --register
& $vb clonevm ddos-server --name ddos-attacker --register
& $vb modifyvm ddos-client --natpf1 delete ssh
& $vb modifyvm ddos-client --natpf1 "ssh,tcp,127.0.0.1,2223,,22"
& $vb modifyvm ddos-attacker --natpf1 delete ssh
& $vb modifyvm ddos-attacker --natpf1 "ssh,tcp,127.0.0.1,2224,,22"
```

**Client.** Start it alone (`& $vb startvm ddos-client --type headless`, wait about 90 s), SSH to port 2223 and run:

```
sudo hostnamectl set-hostname ddos-client
sudo sed -i 's#10.10.10.10/24#10.10.10.20/24#' /etc/netplan/60-lab.yaml
MAC=$(cat /sys/class/net/enp0s3/address); sudo sed -i "s/08:00:27:4c:9c:52/$MAC/" /etc/netplan/*.yaml
sudo rm /etc/machine-id && sudo systemd-machine-id-setup
sudo rm /etc/ssh/ssh_host_* && sudo dpkg-reconfigure openssh-server
sudo systemctl disable --now nginx
sudo reboot
```

(`4c:9c:52` is the first server's NAT MAC from our build. The installer's netplan file pins the NAT NIC to that MAC, and a clone has a different one. If your server's MAC differs, use the value in `/etc/netplan/00-installer-config.yaml`.)

**Attacker.** Its lab IP would clash with the server, so unplug its lab cable before the first boot and plug it in after fixing the address:

```
& $vb modifyvm ddos-attacker --cableconnected2 off
& $vb startvm ddos-attacker --type headless
```

SSH to port 2224 and run the same block as for the client with `ddos-attacker` and `10.10.10.30/24`, reboot, then:

```
& $vb controlvm ddos-attacker setlinkstate2 on
```

On the attacker install the traffic tool: `sudo apt install -y hping3`.

If SSH warns about a changed host key after a reboot, run `ssh-keygen -R "[127.0.0.1]:PORT"` on the host and reconnect.

Leave the attacker's lab cable set to `on` for later boots: `& $vb modifyvm ddos-attacker --cableconnected2 on` (VM powered off).

## 5. Verify

From the client:

```
ping -c 3 10.10.10.10
curl -sI http://10.10.10.10 | head -1
```

Expected: `ttl=64`, `HTTP/1.1 200 OK`.

### Capture test

On the server, start the capture first:

```
sudo tcpdump -i enp0s8 -nn -c 12 'tcp port 80 or icmp'
```

On the attacker send 10 SYN packets (about 10 per second, one second in total):

```
sudo hping3 -I enp0s8 -S -p 80 -c 10 -i u100000 10.10.10.10
```

The server shows `10.10.10.30.xxxx > 10.10.10.10.80: Flags [S]`, the server's `[S.]` reply and the attacker's `[R]`, for 12 captured packets and 0 dropped.

## Before any real flood

Turn off every NAT adapter so nothing can leave the lab:

```
& $vb controlvm ddos-server setlinkstate1 off
& $vb controlvm ddos-client setlinkstate1 off
& $vb controlvm ddos-attacker setlinkstate1 off
```

Use SSH over NAT only before that point. Afterwards use the VM consoles. Turn NAT back on with `setlinkstate1 on` when you need `apt`. Do not run `hping3 --flood` against anything but 10.10.10.10 on the lab network.

## Moving the lab to another PC

```
& $vb export ddos-server ddos-client ddos-attacker -o "$env:USERPROFILE\Desktop\ddos-lab.ova"
```

Copy the file (several GB), then on the other PC:

```
& $vb import "C:\path\to\ddos-lab.ova" --options keepallmacs
```

`keepallmacs` matters, because the VMs' network config is tied to their MAC addresses. The NAT SSH forwards survive the import. Start the server first and give it about 90 seconds before testing from the client.

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| `$vb` error "expression after '&' ... not valid" | New PowerShell window; define `$vb` again. |
| SSH "System is booting up" or "Connection reset" | VM still booting. Wait 1-2 minutes. |
| `ping` works but `curl` fails, `ttl=61` | Stray DHCP routes on the NAT NIC. Use the static NAT config in section 3. |
| `Destination Host Unreachable` from the client | Server not up yet or its `enp0s8` has no address. Check `ip -br a` on the server. |
| `Cannot find unique matching interface for enp0s3` | Netplan MAC pin from the clone. Edit the MAC (section 4). |
| Attacker `enp0s8` is DOWN | Lab cable off. `& $vb controlvm ddos-attacker setlinkstate2 on`. |
| VM shows "Aborted" | VirtualBox/host problem. Start it again; check `VBox.log` if it repeats. |
| SSH to a fresh clone says "host key has changed" | Expected after the clone fix: `known_hosts` still holds the server's copied key. Confirm the new fingerprint differs from the server's, then `ssh-keygen -R "[127.0.0.1]:PORT"`. |

## Detector runtime on the server

Ubuntu 26.04 ships a newer Python than the project's 3.12, so the server uses [uv](https://docs.astral.sh/uv/): clone the repository into `~/ML-DDoS-Detector`, create `.venv` with Python 3.12 through uv and install `requirements.txt`. A uv-created venv has no `pip`, so check dependencies with `uv pip check --python .venv/bin/python`. Then `./.venv/bin/python -m pytest -q` (root-only capture tests skip as a normal user).

## Snapshots

After the rebuild was verified on November 26, 2026, each VM got a powered-off snapshot named `baseline-2026-11-26` (development `a2ea466`, before any flood). Take a new one after each verified change, and restore with the VM powered off:

```
& $vb snapshot ddos-server restore baseline-2026-11-26
```

Snapshots live in the VM folders on the same disk. They protect against a broken guest, not against losing the host, so also keep an OVA export ([Moving the lab to another PC](#moving-the-lab-to-another-pc)) off the PC for that.

## Still to do

The policy-to-firewall runner and its lab acceptance on the server (draft PR #47, issue #51).
