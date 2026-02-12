"""
Reads the systems "Neighbor Table" (ARP cache) to resolve an IP to a MAC address.
This should only be used for getting the MAC of IPs who just connected to you.
The kernel will flush entries after a few minutes of inactivity
Works for non-root users in Docker containers.
"""
def get_mac_address(ip):
    try:
        # /proc/net/arp is a standard Linux kernel file
        with open('/proc/net/arp', 'r') as f:
            # Skip the header line
            next(f)
            for line in f:
                parts = line.split()
                # column 0 is IP, column 3 is MAC (HW address)
                if parts[0] == ip:
                    return parts[3]
    except Exception:
        # Fail silently if we can't read the file or find the IP
        pass
    return ''