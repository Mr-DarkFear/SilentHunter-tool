# SilentHunter_scanner.py (IMPROVED VERSION)
# Network scanning module with enhanced detection and debugging

from scapy.all import ARP, Ether, srp, get_if_list, conf
import socket
import platform
import subprocess
import ctypes
import os
import SilentHunter_GUI as GUI

# Configure Scapy for Windows
conf.use_pcap = True
if platform.system() == "Windows":
    try:
        conf.use_winpcapy = True
    except:
        pass

def c_print(text):
    """Centralized printing through GUI"""
    GUI.c_print(text)

# ============================================================================
# PRIVILEGE AND FIREWALL CHECK
# ============================================================================

def is_admin():
    """Check if running with admin/root privileges"""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def check_firewall_status():
    """Check if firewall might interfere with ARP scanning"""
    c_print("[*] Checking firewall status...")
    
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'currentprofile', 'state'],
                capture_output=True, 
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            if 'ON' in result.stdout.upper() or 'BẬT' in result.stdout.upper():
                c_print("[!] WARNING: Windows Firewall is ON")
                c_print("[!] This may block ARP responses from other devices")
                c_print("[!] Consider temporarily disabling firewall for scanning")
                return True
            else:
                c_print("[+] Windows Firewall appears to be OFF")
                return False
        except Exception as e:
            c_print(f"[!] Could not check firewall status: {e}")
    
    return False

# ============================================================================
# IMPROVED INTERFACE DETECTION
# ============================================================================

def get_active_interfaces():
    """Get all active network interfaces with their IP addresses"""
    interfaces_info = []
    
    try:
        import psutil
        
        # Get interface statistics
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        
        for iface_name, iface_stats in stats.items():
            # Only consider UP interfaces
            if iface_stats.isup and iface_name in addrs:
                for addr in addrs[iface_name]:
                    # Look for IPv4 addresses
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        # Skip loopback and APIPA addresses
                        if not ip.startswith(('127.', '169.254.')):
                            interfaces_info.append({
                                'name': iface_name,
                                'ip': ip,
                                'netmask': addr.netmask
                            })
        
        return interfaces_info
        
    except ImportError:
        c_print("[!] psutil not installed, using fallback method")
        return get_active_interfaces_fallback()
    except Exception as e:
        c_print(f"[!] Error detecting interfaces: {e}")
        return get_active_interfaces_fallback()

def get_active_interfaces_fallback():
    """Fallback method for interface detection"""
    interfaces_info = []
    
    try:
        # Get local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        
        # Get all Scapy interfaces
        scapy_ifaces = get_if_list()
        
        for iface in scapy_ifaces:
            if 'loopback' not in iface.lower():
                interfaces_info.append({
                    'name': iface,
                    'ip': local_ip,
                    'netmask': '255.255.255.0'
                })
                break
        
        return interfaces_info
        
    except Exception as e:
        c_print(f"[!] Fallback interface detection failed: {e}")
        return []

def show_interfaces_detailed():
    """Display detailed information about network interfaces"""
    interfaces = get_active_interfaces()
    
    if not interfaces:
        c_print("[!] No active interfaces found")
        return None
    
    c_print("\n[*] Available Network Interfaces:")
    c_print("─" * 60)
    
    for i, iface in enumerate(interfaces):
        c_print(f"  [{i}] {iface['name']}")
        c_print(f"      IP:      {iface['ip']}")
        c_print(f"      Netmask: {iface['netmask']}")
        c_print("")
    
    return interfaces

# ============================================================================
# IMPROVED ARP SCANNING
# ============================================================================

def scan_network_arp_improved(ip_range, interface=None, timeout=10, retry=2):
    """
    Enhanced ARP scan with multiple attempts and better error handling
    """
    c_print(f"[*] ARP Scanning: {ip_range}")
    c_print(f"[*] Interface: {interface if interface else 'Auto-detect'}")
    c_print(f"[*] Timeout: {timeout}s, Retries: {retry}")
    c_print("[*] This may take 15-30 seconds...")
    
    all_devices = {}
    
    for attempt in range(retry):
        c_print(f"\n[*] Scan attempt {attempt + 1}/{retry}...")
        
        # Create ARP request
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        try:
            # Send packet with specified parameters
            if interface:
                answered, unanswered = srp(
                    packet, 
                    timeout=timeout, 
                    iface=interface,
                    verbose=False,
                    retry=2
                )
            else:
                answered, unanswered = srp(
                    packet,
                    timeout=timeout,
                    verbose=False,
                    retry=2
                )
            
            # Process responses
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                
                # Store unique devices
                if ip not in all_devices:
                    all_devices[ip] = mac
                    c_print(f"  [+] Found: {ip} -> {mac}")
            
            c_print(f"  [*] Attempt {attempt + 1}: Found {len(answered)} devices")
            c_print(f"  [*] No response from {len(unanswered)} addresses")
            
        except PermissionError:
            c_print(f"[!] Permission denied! Run as Administrator/root")
            return []
        except Exception as e:
            c_print(f"[!] Scan error on attempt {attempt + 1}: {e}")
            continue
    
    # Convert to list format
    devices = [{"ip": ip, "mac": mac} for ip, mac in all_devices.items()]
    
    c_print(f"\n[+] Total unique devices found: {len(devices)}")
    return devices

def debug_single_arp(target_ip, interface=None):
    """
    Debug function to test ARP request to a single IP
    Useful for troubleshooting connectivity issues
    """
    c_print(f"\n[DEBUG] Testing ARP request to {target_ip}")
    c_print(f"[DEBUG] Interface: {interface if interface else 'Auto'}")
    
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    c_print(f"[DEBUG] Packet details:")
    c_print(f"        Source MAC: {ether.src}")
    c_print(f"        Dest MAC: {ether.dst}")
    c_print(f"        Target IP: {arp.pdst}")
    
    try:
        if interface:
            answered, unanswered = srp(packet, timeout=5, iface=interface, verbose=False)
        else:
            answered, unanswered = srp(packet, timeout=5, verbose=False)
        
        if answered:
            for sent, received in answered:
                c_print(f"[DEBUG] ✓ Response received!")
                c_print(f"        IP: {received.psrc}")
                c_print(f"        MAC: {received.hwsrc}")
                return True
        else:
            c_print(f"[DEBUG] ✗ No response received")
            c_print(f"[DEBUG] Possible causes:")
            c_print(f"        - Target device is offline")
            c_print(f"        - Firewall blocking ARP")
            c_print(f"        - Wrong network interface")
            c_print(f"        - Target IP not in local network")
            return False
            
    except Exception as e:
        c_print(f"[DEBUG] ✗ Error: {e}")
        return False

def ping_sweep_improved(network_base, interface=None):
    """
    Enhanced ping sweep with progress indication
    """
    c_print(f"[*] Starting ping sweep on {network_base}.0/24")
    c_print("[*] Scanning 254 addresses...")
    
    devices = []
    checked = 0
    
    for i in range(1, 255):
        ip = f"{network_base}.{i}"
        checked += 1
        
        # Progress indicator every 50 IPs
        if checked % 50 == 0:
            c_print(f"[*] Progress: {checked}/254 addresses checked...")
        
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            if interface:
                answered, _ = srp(packet, timeout=0.5, iface=interface, verbose=False, retry=1)
            else:
                answered, _ = srp(packet, timeout=0.5, verbose=False, retry=1)
            
            if answered:
                for sent, received in answered:
                    device_info = {"ip": received.psrc, "mac": received.hwsrc}
                    devices.append(device_info)
                    c_print(f"  [+] Found: {ip} -> {received.hwsrc}")
                    
        except Exception:
            continue
    
    c_print(f"[+] Ping sweep completed: {len(devices)} devices found")
    return devices

# ============================================================================
# MAIN SCANNING FUNCTION
# ============================================================================

def get_local_ip():
    """Get local machine's IP address"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        c_print(f"[!] Could not determine local IP: {e}")
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if not ip.startswith("127."):
                return ip
        except:
            pass
        return None

def scan_devices():
    """
    Main scanning function with all improvements
    """
    # Check privileges
    if not is_admin():
        c_print("[!] WARNING: Not running as Administrator/root")
        c_print("[!] ARP scanning may fail without elevated privileges")
        c_print("[!] Please run as Administrator (Windows) or sudo (Linux)")
        
        proceed = input("\n[?] Continue anyway? (y/n): ").lower()
        if proceed not in ('y', 'yes'):
            return None, None, []
    
    # Check firewall
    check_firewall_status()
    
    # Get local IP
    my_ip = get_local_ip()
    if not my_ip:
        c_print("[-] Could not determine local IP address")
        return None, None, []
    
    network_base = ".".join(my_ip.split('.')[:-1])
    network_range = f"{network_base}.0/24"
    
    c_print(f"\n[+] Your IP address: {my_ip}")
    c_print(f"[+] Network range: {network_range}")
    
    # Show available interfaces
    interfaces = show_interfaces_detailed()
    
    if not interfaces:
        c_print("[-] No suitable network interfaces found")
        return my_ip, network_range, []
    
    # Let user choose interface
    c_print("[?] Select interface to use:")
    c_print("    Enter number [0-{}] or press Enter for auto-select".format(len(interfaces)-1))
    
    choice = input("Selection: ").strip()
    
    selected_interface = None
    if choice.isdigit() and 0 <= int(choice) < len(interfaces):
        selected_interface = interfaces[int(choice)]['name']
        c_print(f"[+] Selected: {selected_interface}")
    else:
        selected_interface = interfaces[0]['name']
        c_print(f"[+] Auto-selected: {selected_interface}")
    
    # Optional: Debug mode
    c_print("\n[?] Enable debug mode? (Test single IP first)")
    debug_choice = input("    Enter target IP or press Enter to skip: ").strip()
    
    if debug_choice:
        debug_single_arp(debug_choice, selected_interface)
        proceed = input("\n[?] Continue with full scan? (y/n): ").lower()
        if proceed not in ('y', 'yes'):
            return my_ip, network_range, []
    
    # Perform main scan
    c_print("\n" + "="*60)
    c_print("STARTING MAIN NETWORK SCAN")
    c_print("="*60)
    
    devices = scan_network_arp_improved(
        network_range, 
        interface=selected_interface,
        timeout=10,
        retry=2
    )
    
    # If no devices found, try ping sweep
    if len(devices) <= 1:  # Only found ourselves
        c_print("\n[!] Few devices found with ARP scan")
        c_print("[*] Trying alternative ping sweep method...")
        
        additional_devices = ping_sweep_improved(network_base, selected_interface)
        
        # Merge results
        existing_ips = {d['ip'] for d in devices}
        for device in additional_devices:
            if device['ip'] not in existing_ips:
                devices.append(device)
    
    # Display results
    c_print("\n" + "="*60)
    c_print("SCAN RESULTS")
    c_print("="*60)
    
    if devices:
        c_print(f"[+] Total devices found: {len(devices)}")
        c_print("\nDevice List:")
        for i, device in enumerate(devices, 1):
            indicator = " (YOU)" if device['ip'] == my_ip else ""
            c_print(f"  [{i}] {device['ip']:<15} -> {device['mac']}{indicator}")
    else:
        c_print("[-] No devices found on network")
        c_print("\nTroubleshooting suggestions:")
        c_print("  1. Check if other devices are actually connected")
        c_print("  2. Temporarily disable Windows Firewall")
        c_print("  3. Verify you're on the same network segment")
        c_print("  4. Try running as Administrator")
        c_print("  5. Check antivirus/security software")
    
    return my_ip, network_range, devices

def show_interfaces():
    """Legacy function for compatibility"""
    show_interfaces_detailed()