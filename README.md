# 🐝 BuzzTrap

**A Containerized Low-Interaction Honeypot System**

BuzzTrap is a modular honeypot system designed for deployment within private networks to detect lateral movement, log activity and trigger alerts. Currently, it supports detecting **SSH** and **RDP** connections. This project isolates its "Conductor" (logging/alerting) from the "Sensors" (listeners) using Unix Domain Sockets, ensuring secure, non-blocking inter-process communication. By default, the resulting BuzzTrap containers run as a **non-root user** with a **read-only filesystem** and **zero Linux capabilities**, minimizing the risk of container breakout.

---

## Designed for Simplicity

BuzzTrap is built on the philosophy that a sensor should be lightweight, invisible, and require zero maintenance. It avoids the complexity of web GUIs, heavy databases, and management dashboards in favor of a purely headless approach.

* **No Web Interface:** There is no GUI to configure, secure, or patch. All settings are managed via standard `.ini` files or Environment Variables, treating configuration as code.
* **Automation Ready:** The containerized, stateless architecture makes it trivial to mass-deploy across hundreds of endpoints using tools like Ansible, Terraform, or SaltStack.
* **Low Overhead:** Designed to run silently in the background of production servers or low-power edge devices without impacting legitimate workloads.

---

## Architecture

The system consists of three distinct services running in Docker:

1.  **BuzzTrap Conductor:** The backend system listening on a Unix Domain Socket for messages from sensors. It handles:
    * Writing to a dedicated security event log.
    * Sending real-time Webhook alerts.
    * Sanitizing inputs to prevent log injection attacks.

2.  **BuzzTrap RDP:** A lightweight RDP listener.
    * Accepts the initial TCP handshake and captures the source IP/MAC.
    * Responds with a valid RDP Negotiation Failure (`0x00000004`) to suggest that it is a genuine RDP server before disconnecting.

3.  **BuzzTrap SSH:** A low-interaction SSH listener built on `Paramiko`.
    * Rejects all authentication attempts (recording the username tried).
    * Auto-generates its own RSA host key on first run.
    * Multi-threaded to handle concurrent scanners.

---

## Security Hardening

This project has hardened the resulting containers in the following ways:

* **Non-Root Execution:** By default all processes run as user `buzztrap` (UID 1000), not root.
* **Read-Only Filesystem:** In the Docker Compose, containers run with `read_only: true`. This greatly reduces the surface area for attackers to write malware or persistence tools to the disk.
* **Capability Drop:** In the Docker Compose, containers all Linux capabilities (`cap_drop: [ALL]`) are removed. Even if a process is compromised, it cannot manipulate network interfaces or mount drives.
* **Log Sanitization:** All incoming data is sanitized to strip newlines and quotes, neutralizing simple Log Injection vulnerabilities.
* **Safe ARP Lookup:** Uses a custom, non-privileged method to read `/proc/net/arp` for Layer 2 MAC address fingerprinting without requiring root access.

---

## Deployment Guide

The following is a basic deployment guide

### Prerequisites
* A Linux host machine
* Docker & Docker Compose

### 1. Host Preparation
Because the containers run as a restricted user (UID 1000), you must create the data directories on your host and set the correct ownership **before** starting Docker.

From inside the folder containing the Docker Compose:

```bash
# Create directories for persistent data and logs
sudo mkdir -p ./data
sudo mkdir -p ./logs

# Set ownership to UID 1000 (The 'buzztrap' user inside the container)
sudo chown -R 1000:1000 ./data
sudo chown -R 1000:1000 ./logs

```

### 2. Build and Run

Clone the repository and start the stack.

From inside the folder containing the Docker Compose:

```bash
# Build and start in detached mode
docker compose up -d --build

```

### 3. Networking Note (Important!)

Since by default the SSH container runs as a non-root user, it cannot bind to the privileged port `22`. It defaults to port **2222**.

If you wish to bind BuzzTrap SSH to port 22 you will need to rebuild the container using the `dockerfile_ssh_root` dockerfile.

From inside the folder containing the Docker Compose:

```bash
# Must be done after the initial compose build and any subsequent compose rebuilds
docker build -t buzztrap-ssh --file dockerfile_ssh_root .

```

---

## Configuration

Configuration is handled in the following descending priority:
- Environmental Variables
- `.ini` files
- Default values

### BuzzTrap Conductor

| Setting | Description | Required | Default |
| --- | --- | --- | --- |
| `CONDUCTOR_ID` | ID of conductor used in alerts and logs | _True_ | _(Empty)_ |
| `SECURITY_WEBHOOKURL` | URL to POST JSON alerts to (must start with "https://") | _False_ | _(Empty)_ |
| `SECURITY_WEBHOOKCOOLDOWN` | Seconds to wait between webhook alerts to prevent spam | _False_ | `30` |
| `SECURITY_EVENTLOG` | Path to the security event-only log file | _False_ | _(Empty)_ |
| `SECURITY_APPROVED_BLINDSPOTS` | IPs and MAC addresses to exclude from security webhook and log | _False_ | _(Empty)_ |
| `SOCKET_PATH` | Path to the Unix socket file | _False_ | `./data/buzztrap.sock` |
| `LOG_FILE` | Path to the application log file | _False_ | `./logs/buzztrap_conductor.log` |
| `LOG_FILEMODE` | Use w (write) or a (append) file mode for application log | _False_ | `a` |
| `LOG_DEBUG` | Include debug entries in application log | _False_ | `false` |

### BuzzTrap RDP

| Setting | Description | Required | Default |
| --- | --- | --- | --- |
| `RDP_IP` | IP used for network socket bind | _False_ | `0.0.0.0` |
| `RDP_PORT` | Port used for network socket bind | _False_ | `3389` |
| `SOCKET_PATH` | Path to the Unix socket file | _False_ | `./data/buzztrap.sock` |
| `LOG_FILE` | Path to the application log file | _False_ | `./logs/buzztrap_rdp.log` |
| `LOG_FILEMODE` | Use w (write) or a (append) file mode for application log | _False_ | `a` |
| `LOG_DEBUG` | Include debug entries in application log | _False_ | `false` |

### BuzzTrap SSH

| Setting | Description | Required | Default |
| --- | --- | --- | --- |
| `SSH_IP` | IP used for network socket bind | _False_ | `0.0.0.0` |
| `SSH_PORT` | Port used for network socket bind | _False_ | `2222` |
| `SSH_KEYFILE` | Server key file for SSH connection | _False_ | `./data/server.key` |
| `SSH_BANNER` | SSH banner provided to client | _False_ | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.13` |
| `SOCKET_PATH` | Path to the Unix socket file | _False_ | `./data/buzztrap.sock` |
| `LOG_FILE` | Path to the application log file | _False_ | `./logs/buzztrap_rdp.log` |
| `LOG_FILEMODE` | Use w (write) or a (append) file mode for application log | _False_ | `a` |
| `LOG_DEBUG` | Include debug entries in application log | _False_ | `false` |

### `.ini` Example

Please see the following example for how the environmental variables map to an `.ini` configuration file

```ini
[conductor]
id=buzztrap-prod

[security]
eventlog=./logs/record-of-buzzes.log
webhookurl=https://example.com/api/ingest-webhook?token=SGVsbG8gZnJpZW5kIDop
approved_blindspots= ip=8.8.8.8, mac=11:22:33:44:55:66
```

### Example Compose Files

This repo includes two example Docker Compose configurations.

#### Layer 2 (compose.layer2.yaml)

- Network Mode: Host networking.
- Key Benefit: Captures the Source MAC address of the attacker if available, providing deeper visibility into local network threats.

#### Layer 3 (compose.layer3.yaml)

- Network Mode: Bridge networking.
- Key Benefit: Provides stronger container isolation to prevent outbound connections, though it cannot capture MAC addresses.

---

## Logs & Fail2Ban

Security logs are written to path specified in the `SECURITY_EVENTLOG` setting.

**Format:**

```text
timestamp="2025-12-10 11:30:13" host="buzztrap-prod" service="BuzzTrap" honeypot="RDP" proto="TCP" src_ip="192.168.1.50" src_mac="00:11:22:33:44:55" src_port="58079" dst_ip="0.0.0.0" dst_port="3389"

```

### Fail2Ban Integration

To use these logs with Fail2Ban, use a filter that strictly matches the `proto="TCP"` field to prevent UDP spoofing attacks.

**jail.local example:**

Please update `/data/docker/buzztrap/logs/record-of-buzzes.log` to be path specified in the `SECURITY_EVENTLOG` setting.

```ini
[buzztrap]
enabled = true
backend = polling
logpath = /data/docker/buzztrap/logs/record-of-buzzes.log
filter = buzztrap
action = iptables-allports[name=buzztrap]

```

**filter.d/buzztrap.conf:**

```ini
[Definition]
failregex = ^.*proto="TCP".*src_ip="<HOST>".*$
ignoregex =

```

Using the above logpath for this example, if you would like to test custom Fail2Ban regex against the events in your log run:  
`fail2ban-regex /data/docker/buzztrap/logs/record-of-buzzes.log /etc/fail2ban/filter.d/buzztrap.conf`

---

## License

This project is licensed under the MIT License (see LICENSE file) and includes code derived from:

* *SSH-Honeypot* (MIT License)
* *CommunityHoneyNetwork/rdphoney* (CC0 1.0)

See individual scripts for full attribution.
