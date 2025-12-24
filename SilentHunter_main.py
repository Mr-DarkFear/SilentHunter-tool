# SilentHunter_main.py (IMPROVED VERSION)
# Enhanced command line interface with better error handling

import SilentHunter_funcs as func
import SilentHunter_scanner as scan_engine
import SilentHunter_GUI as GUI
import sys
import time

def c_print(text):
    """Centralized printing through GUI"""
    GUI.c_print(text)

def show_banner():
    """Display enhanced tool banner"""
    c_print(GUI.title)
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║              SILENT HUNTER - MITM TOOL v2.0              ║
    ║                  Educational Use Only                     ║
    ║                                                           ║
    ║  ⚠️  WARNING: Unauthorized use is illegal!               ║
    ║  ✓  Only use on networks you own or have permission     ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    c_print(banner)

def show_help():
    """Display comprehensive command help"""
    help_text = """
    ╔════════════════════════════════════════════════════════════╗
    ║                    AVAILABLE COMMANDS                      ║
    ╠════════════════════════════════════════════════════════════╣
    ║ SCANNING                                                   ║
    ║  scan              - Scan network for active devices       ║
    ║  my_ip             - Display your IP address               ║
    ║  get_gateway       - Display gateway IP                    ║
    ║  get_mac <ip>      - Get MAC address of specific IP        ║
    ╠════════════════════════════════════════════════════════════╣
    ║ ATTACK SETUP                                               ║
    ║  set_target <ip>   - Set target IP for MITM attack         ║
    ║  check_connect     - Test connectivity to target & gateway ║
    ║  show_target       - Display current target information    ║
    ╠════════════════════════════════════════════════════════════╣
    ║ ATTACK CONTROL                                             ║
    ║  attack            - Start MITM ARP spoofing attack        ║
    ║  stop_attack       - Stop ongoing attack                   ║
    ║  restore           - Restore ARP tables                    ║
    ╠════════════════════════════════════════════════════════════╣
    ║ UTILITY                                                    ║
    ║  status            - Show current attack status            ║
    ║  clear             - Clear screen                          ║
    ║  help / ?          - Show this help message                ║
    ║  exit / quit       - Exit the tool                         ║
    ╚════════════════════════════════════════════════════════════╝
    
    TIP: Use 'scan' first to discover devices on your network
    """
    c_print(help_text)

def show_status():
    """Display current tool status"""
    status = f"""
    ╔═══════════════════════════════════════╗
    ║          CURRENT STATUS               ║
    ╠═══════════════════════════════════════╣
    ║ Gateway:  {func.gateway_ip or 'Not detected':<25} ║
    ║ Target:   {func.target_ip or 'Not set':<25} ║
    ║ Attack:   {'RUNNING' if func.attack_running else 'STOPPED':<25} ║
    ╚═══════════════════════════════════════╝
    """
    c_print(status)

def better_input(prompt, lower=False):
    """Enhanced input with interrupt handling"""
    try:
        data = input(prompt).strip()
        return data.lower() if lower and data else data
    except (KeyboardInterrupt, EOFError):
        c_print("\n[*] Input interrupted")
        return ""
    except Exception as e:
        c_print(f"[!] Input error: {e}")
        return ""

def parse_command(command_line):
    """Parse command line into command and arguments"""
    parts = command_line.strip().split()
    if not parts:
        return "", []
    return parts[0].lower(), parts[1:]

def clear_screen():
    """Clear terminal screen"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')
    show_banner()

def main():
    """Enhanced main program loop"""
    show_banner()
    c_print("[*] SilentHunter MITM Tool v2.0 Started")
    c_print("[*] Type 'help' for available commands\n")
    
    # Variables
    my_ip = None
    network_range = None
    devices = []
    
    # Main command loop
    while True:
        try:
            command_line = better_input("\n┌[SilentHunter]─[~]\n└──> ", lower=True)
            
            if not command_line:
                continue
            
            command, args = parse_command(command_line)
            
            # ============================================================
            # SCANNING COMMANDS
            # ============================================================
            
            if command == "scan":
                c_print("[*] Initiating network scan...")
                try:
                    my_ip, network_range, devices = scan_engine.scan_devices()
                    if devices:
                        c_print(f"\n[+] Scan complete: {len(devices)} devices found")
                    else:
                        c_print("\n[!] No devices found - check troubleshooting tips above")
                except Exception as e:
                    c_print(f"[!] Scan failed: {e}")
            
            elif command == "my_ip":
                my_ip = scan_engine.get_local_ip()
                if my_ip:
                    c_print(f"[+] Your IP address: {my_ip}")
                else:
                    c_print("[-] Could not determine your IP")
            
            elif command == "get_gateway":
                gateway = func.get_gateway_ip()
                if gateway:
                    c_print(f"[+] Gateway IP: {gateway}")
                else:
                    c_print("[-] Could not detect gateway")
            
            elif command == "get_mac":
                if args:
                    ip = args[0]
                    mac = func.get_mac(ip)
                    if mac:
                        c_print(f"[+] {ip} -> {mac}")
                    else:
                        c_print(f"[-] Could not resolve MAC for {ip}")
                else:
                    ip = better_input("Enter IP address: ")
                    if ip:
                        mac = func.get_mac(ip)
                        if mac:
                            c_print(f"[+] {ip} -> {mac}")
            
            # ============================================================
            # ATTACK SETUP COMMANDS
            # ============================================================
            
            elif command == "set_target":
                if args:
                    target_ip = args[0]
                else:
                    # Show available devices if we have them
                    if devices:
                        c_print("\n[*] Available devices from last scan:")
                        for i, device in enumerate(devices, 1):
                            c_print(f"  [{i}] {device['ip']} - {device['mac']}")
                        c_print("")
                    
                    target_ip = better_input("Enter target IP address: ")
                
                if target_ip:
                    func.set_target_ip(target_ip)
                else:
                    c_print("[-] No target IP provided")
            
            elif command == "show_target":
                if func.target_ip:
                    c_print(f"[+] Current target: {func.target_ip}")
                    mac = func.get_mac(func.target_ip)
                    if mac:
                        c_print(f"    MAC address: {mac}")
                else:
                    c_print("[-] No target set. Use 'set_target' first")
            
            elif command == "check_connect":
                c_print("[*] Testing connectivity...")
                if func.test_connectivity():
                    c_print("[+] All connectivity tests passed!")
                    c_print("[+] Ready for MITM attack")
                else:
                    c_print("[-] Connectivity test failed")
                    c_print("[!] Cannot proceed with attack")
            
            # ============================================================
            # ATTACK CONTROL COMMANDS
            # ============================================================
            
            elif command == "attack":
                if func.attack_running:
                    c_print("[!] Attack is already running")
                    c_print("[*] Use 'stop_attack' to stop it first")
                    continue
                
                if not func.target_ip:
                    c_print("[-] No target set. Use 'set_target' first")
                    continue
                
                # Final confirmation
                c_print("\n" + "!"*60)
                c_print("⚠️  WARNING: You are about to start a MITM attack")
                c_print("⚠️  Ensure you have proper authorization!")
                c_print("⚠️  Unauthorized use may be illegal")
                c_print("!"*60)
                
                confirm = better_input("\nType 'YES' to confirm and start attack: ")
                
                if confirm == "yes":
                    if func.start_MiTM_attack():
                        c_print("[+] Attack started successfully")
                        c_print("[*] Use 'stop_attack' to stop")
                    else:
                        c_print("[-] Failed to start attack")
                else:
                    c_print("[*] Attack cancelled")
            
            elif command == "stop_attack":
                if not func.attack_running:
                    c_print("[*] No active attack to stop")
                else:
                    func.stop_MiTM_attack()
            
            elif command == "restore":
                c_print("[*] Manually restoring ARP tables...")
                if func.target_ip and func.gateway_ip:
                    func.restore_arp(func.target_ip, func.gateway_ip, count=5)
                    func.restore_arp(func.gateway_ip, func.target_ip, count=5)
                    c_print("[+] ARP restoration complete")
                else:
                    c_print("[-] Need both target and gateway to restore")
            
            # ============================================================
            # UTILITY COMMANDS
            # ============================================================
            
            elif command == "status":
                show_status()
            
            elif command == "clear":
                clear_screen()
            
            elif command in ("help", "?"):
                show_help()
            
            elif command in ("exit", "quit", "q"):
                c_print("\n[*] Shutting down SilentHunter...")
                
                # Stop any running attack
                if func.attack_running:
                    c_print("[*] Stopping active attack...")
                    func.stop_MiTM_attack()
                
                c_print("[*] Cleaning up...")
                time.sleep(1)
                
                c_print("[+] Goodbye! Stay safe and ethical!")
                break
            
            else:
                c_print(f"[-] Unknown command: '{command}'")
                c_print("[*] Type 'help' to see available commands")
        
        except KeyboardInterrupt:
            c_print("\n\n[!] Interrupted by user (Ctrl+C)")
            c_print("[*] Stopping any active attacks...")
            func.stop_MiTM_attack()
            
            confirm_exit = better_input("\n[?] Do you want to exit? (y/n): ", lower=True)
            if confirm_exit in ('y', 'yes'):
                c_print("[+] Exiting...")
                break
            else:
                c_print("[*] Continuing...")
        
        except Exception as e:
            c_print(f"[!] Unexpected error: {e}")
            c_print("[*] Type 'help' for available commands")

if __name__ == "__main__":
    try:
        # Initial safety check
        c_print("\n" + "="*70)
        c_print("⚠️  LEGAL WARNING")
        c_print("="*70)
        c_print("This tool is for EDUCATIONAL and AUTHORIZED TESTING purposes only.")
        c_print("Unauthorized interception of network traffic is ILLEGAL.")
        c_print("The authors assume NO responsibility for misuse of this tool.")
        c_print("="*70)
        
        confirm = better_input("\n[?] Do you understand and accept responsibility? (YES/no): ")
        
        if confirm.lower() in ('yes', 'y'):
            # Check for admin privileges
            if not scan_engine.is_admin():
                c_print("\n[!] WARNING: Not running with Administrator/root privileges")
                c_print("[!] Some features may not work correctly")
                c_print("[!] Consider running as Administrator (Windows) or with sudo (Linux)")
                
                proceed = better_input("\n[?] Continue anyway? (y/n): ", lower=True)
                if proceed not in ('y', 'yes'):
                    c_print("[*] Exiting...")
                    sys.exit(0)
            
            # Start main program
            main()
        else:
            c_print("\n[*] You must accept the terms to use this tool")
            c_print("[*] Exiting...")
            sys.exit(0)
    
    except Exception as e:
        c_print(f"\n[!] Fatal error: {e}")
        sys.exit(1)