#!/usr/bin/python3
from tqdm import tqdm
from threading import Thread
import time
modules_for_progress_bar = [ "colored", "randint", "sample", "randrange", "Dot11Elt", "Dot11Beacon", "RadioTap", "Dot11", "Dot11Deauth", "Dot11Disas", "sniff", "Thread", "Lock", "tabulate", "subprocess", "sqlite3", "pandas", "signal", "textwrap", "time", "os", "sys", "interfaces", "cmd", "string" ]

def progress_bar_module_import():
    pbmi = tqdm(total=len(modules_for_progress_bar), desc="[*] Loading modules...", unit="modules")
    for mod in modules_for_progress_bar:
        pbmi.update(1)
        pbmi.refresh()
        time.sleep(0.33)
    pbmi.close()

thread_for_pbmi = Thread(target=progress_bar_module_import)
thread_for_pbmi.start()

# import modules
from termcolor import colored
from random import randint
from random import sample
from random import randrange
from scapy.layers.dot11 import Dot11Elt, Dot11Beacon, RadioTap, Dot11, Dot11Deauth, Dot11Disas
from scapy.all import sniff
from threading import Lock
from tabulate import tabulate
import subprocess
import sqlite3
import pandas
import signal
import textwrap
import os
import string
import sys
from netifaces import interfaces
import cmd

from wapa_scanner import WAPANetworkScanner
from wapa_db import WapaDatabase
from wapa_gp import GeneralPurpose
from wapa_pe import PreExecution
from wapa_fuzzer import WapaFuzzer
from wapa_et import WAPAEvilTwin

# end import + finish progress bar
thread_for_pbmi.join()
print("[*] Starting WAPA shell...")
time.sleep(1)

# END OF IMPORTS -- DEFINE TITLE
random_title=randint(1,2)
colores = ["red", "green", "yellow", "blue", "cyan", "magenta", "yellow", "white"]
random_color_title=randint(0,7)
titulo1="""
 __     __     ______     ______   ______
/\ \  _ \ \   /\  __ \   /\  == \ /\  __ \ 
\ \ \/ ".\ \  \ \  __ \  \ \  _-/ \ \  __ \ 
 \ \__/".~\_\  \ \_\ \_\  \ \_\    \ \_\ \_\ 
  \/_/   \/_/   \/_/\/_/   \/_/     \/_/\/_/

                            ┌──────────────────────────────────────
                            │
  WAPA version 2.1-stable   │  Wireless Access Point Auditor
                            │
       Made by: D0t         │  https://github.com/D-0x0-t/wapa_v2
                            │
────────────────────────────┘
"""
titulo2="""
███       ███╗  █████████╗  ████████╗  █████████╗
███  ▄▄▄  ███║  ███   ███║  ███  ███║  ███   ███║
███  ███  ███║  █████████║  ████████║  █████████║
███▄▄███▄▄███║  ███╔══███║  ███╔════╝  ███╔══███║
█████████████║  ███║  ███║  ███║       ███║  ███║
╚════════════╝  ╚══╝  ╚══╝  ╚══╝       ╚══╝  ╚══╝

                            ┌──────────────────────────────────────
                            │
  WAPA version 2.1-stable   │  Wireless Access Point Auditor
                            │
       Made by: D0t         │  https://github.com/D-0x0-t/wapa_v2
                            │
────────────────────────────┘
"""

class WapaShell(cmd.Cmd):
    prompt = "wapa> "
    completekey = "tab"
    scanner = WAPANetworkScanner()
    fuzzer = WapaFuzzer()
    evil_twin = WAPAEvilTwin()


    def __init___(self):
        super().__init__()

    def cmdloop(self, intro=None):
        try:
            super().cmdloop()
        except KeyboardInterrupt:
            self.do_exit()

    # Basic shell commands
    def default(self, line):
        """
        Handle unknown commands
        """
        print(f'Unknown command: {line}')

    def emptyline(self):
        """
        Emptyline 
        """
        pass

    def do_exit(self, args):
        """
        Exit wapa shell
        """
        print('\n[!] Exitting shell...\n')
        return True

    def do_EOF(self, args):
        """
        Handle Ctrl+D
        """
        print('\n[!] Exitting shell...\n')
        return True

    def do_man(self, args):
        """
        Usage manuals
        """

    def do_shell(self, args):
        """
        Execute system commands (also available with the following syntax !<cmd>)
        """
        os.system(args)

    #def do_help(self, args):
    #   args = args.split()
    #   if args == "x":[...]
    
    # WAPA Scanner
    def do_scan(self, args):
        """
        Sniff wireless packets with WAPA
        """
        try:
            args = args.split()
            if args[0].lower() == "start":
                try:
                    iface = str(args[1])
                    print("[*] Starting scanner on interface", iface)
                    self.scanner.start_scan_thread(iface)
                except:
                    print("[!] Interface?")
            elif args[0].lower() == "stop":
                try:
                    print("[*] Stopping network scanner")
                    self.scanner.stop_scan_thread()
                except:
                    print("[!] Command couldn't be executed\nIs there any undergoing scan?")
            elif args[0].lower() == "list" or args[0].lower() == "show":
                show_both_scans = True
                wapadb = WapaDatabase()
                try:
                    if args[1].lower() == "networks" or args[1].lower() == "ap" or args[1].lower() == "aps":
                        show_both_scans = False
                        wapadb.get_scan()
                    elif args[1].lower() == "probes":
                        show_both_scans = False
                        wapadb.get_probe_scan()
                    elif args[1].lower() == "both":
                        pass
                    else:
                        show_both_scans = False
                        print("[!] What would you like to list?\n-->networks\n-->probes")
                except:
                    pass
                if show_both_scans is True:
                    print("[*] Scanned APs:\n")
                    wapadb.get_scan()
                    print("\n[*] Scanned probes:\n")
                    wapadbf = WapaDatabase()
                    wapadbf.get_probe_scan()
            elif args[0].lower() == "status":
                wapadb = WapaDatabase()
                wapadb.scan_status()
        except:
            print("[!] Check the syntax: scan <action> <interface_name>")
            

    # WAPA fuzzer
    def do_fuzz(self, args):
        """
        Fuzz packets over the air
        """
        try:
            args = args.split()
            mode = str(args[0])
            if mode.lower() == "start":
                print("[*] Select the frame to fuzz:\n(1) --> Dot11Beacon\n(2) --> Dot11Deauth\n(3) --> Dot11Disas")
                packet_to_fuzz = input("[>] ")
                if packet_to_fuzz == "1":
                    wordlist_style_check = input("[>] Would you like to use a wordlist? (y/n) ")
                    if wordlist_style_check.lower() == "n":
                        essid_mode = input("[>] Generate random ESSIDs? (y/n) ")
                        if essid_mode.lower() == "y":
                            essid_method = "random"
                            print("[*] Select the charset to use:\n--> default (uppercase + lowercase + numbers + punctuation characters)\n--> uppercase (ABCDEFGHIJKLMNOPQRSTUVWXYZ)\n--> lowercase (abcdefghijklmnopqrstuvwxyz)\n--> numbers (0123456789)\n--> custom (type the characters you would like to use)\n[>] ", end="")
                            string_query = input()
                            security_type = input("[>] Which security method would you like to use (OPN/WEP/WPA/WPA2/ALL)> ")
                            if security_type.lower() == "opn" or security_type.lower() == "wep" or security_type.lower() == "wpa" or security_type.lower() == "wpa2":
                                pass
                            else:
                                security_type = "random"
                            print("[*] Please, select one interface from the database to execute the attack:\n")
                            wapa_database = WapaDatabase()
                            wapa_database.list_ifaces()
                            iface = input("[>] ")
                            print("[*] Executing fuzzer, press Ctrl+C to stop it, and execute 'fuzz kill' to kill the access points.")
                            self.fuzzer.beacon_fuzzer(wordlist=essid_method, string=string_query, count=None, sectype=security_type, intf=iface)
                        else:
                            essid_method = "generate"
                            charstring = input("[>] String to fuzz ESSIDs: ")
                            count_maxwl_str = input("[>] How many ESSIDs should WAPA create? ")
                            count_maxwl = int(count_maxwl_str)
                            security_type = input("[>] Which security method would you like to use (OPN/WEP/WPA/WPA2/ALL)> ")
                            if security_type.lower() == "opn" or security_type.lower() == "wep" or security_type.lower() == "wpa" or security_type.lower() == "wpa2":
                                pass
                            else:
                                security_type = "random"
                            print("[*] Please, select one interface from the database to execute the attack:\n")
                            wapa_database = WapaDatabase()
                            wapa_database.list_ifaces()
                            iface = input("[>] ")
                            print("[*] Executing fuzzer, press Ctrl+C to stop it, and execute 'fuzz kill' to kill the access points.")
                            self.fuzzer.beacon_fuzzer(wordlist=essid_method, string=charstring, count=count_maxwl, sectype=security_type, intf=iface)
                    elif wordlist_style_check.lower() == "y":
                        essid_method = "obtain"
                        wordlist_path = input("[>] Path to the wordlist: ")
                        security_type = input("[>] Which security method would you like to use (OPN/WEP/WPA/WPA2/ALL)> ")
                        if security_type.lower() == "opn" or security_type.lower() == "wep" or security_type.lower() == "wpa" or security_type.lower() == "wpa2":
                            pass
                        else:
                            security_type = "random"
                        print("[*] Please, select one interface from the database to execute the attack:\n")
                        wapa_database = WapaDatabase()
                        wapa_database.list_ifaces()
                        iface = input("[>] ")
                        print("[*] Executing fuzzer, press Ctrl+C to stop it, and execute 'fuzz kill' to kill the access points.")
                        self.fuzzer.beacon_fuzzer(wordlist=essid_method, string=wordlist_path, sectype=security_type, intf=iface)
                    else:
                        print("[!] Unrecognized command")
                elif packet_to_fuzz == "2" or packet_to_fuzz == "3":
                    src = input("[>] Please provide the source MAC address of the frames: ")
                    dst = input("[>] Now, provide the destination MAC address or type B for broadcast: ")
                    print("[*] Available reasons are:\n1 - Unspecified\n2 - Previous authentication no longer valid\n3 - Deauthenticated because sending station (STA) is leaving or has left Independent Basic Service Set (IBSS) or ESS\n4 - Disassociated due to inactivity\n6 - Class 2 frame received from nonauthenticated STA\n7 - Class 3 frame received from nonassociated STA (default)\n8 - Disassociated because sending STA is leaving or has left Basic Service Set (BSS)\n24 - Cipher suite rejected because of the security policy")
                    reason = input("[>] Choose any reason or leave blank for default: ")
                    if reason == "" or reason == " ":
                        reason = 7
                    else:
                        reason = int(reason)
                    print("[*] Please, select one interface from the database to execute the attack:\n")
                    wapa_database = WapaDatabase()
                    wapa_database.list_ifaces()
                    iface = input("[>] ")
                    print("[*] Executing fuzzer, press Ctrl+C to stop it.")
                    if packet_to_fuzz == "2":
                        mode = "deauth"
                    elif packet_to_fuzz == "3":
                        mode = "disas"
                    self.fuzzer.send_deauth_disas(mode=mode, src=src, dst=dst, reason=reason, intf=iface)
            elif mode.lower() == "stop" or mode.lower() == "kill":
                self.fuzzer.stop_fuzzer()
            elif mode.lower() == "list" or mode.lower() == "query":
                wapadb = WapaDatabase()
                wapadb.list_beacons()
        except KeyboardInterrupt:
            print("")
            pass
        except:
            print("[!] Couldn't execute the command successfully")
            print("[*] Check the syntax: fuzz [start|stop|list]")
 

    # WAPA - EvilTwin generator (ETG)
    def do_evil_twin(self, args):
        """
        Execute an EvilTwin attack
        """
        try:
            args = args.split()
            if args[0] == "start" or args[0] == "s":
                print("[*] Please, select one interface from the database to execute the attack:\n")
                wapa_database = WapaDatabase()
                wapa_database.list_ifaces()
                iface = input("[>] ")
                exit_intf = input("[>] Now select an output interface: ")
                channel = input("[>] In which channel do you want to work?: ")
                essid = input("[>] Which ESSID should be used: ")
                ap_password = input("[>] Type your desired password for the access point or leave blank to create an OPN network: ")
                if ap_password == "" or ap_password == " ":
                    ap_password = None
                webserver_path = input("[>] Path to the webserver: ")
                if webserver_path == "" or webserver_path == " ":
                    webserver_path = None
                self.evil_twin.start_eviltwin(interface=iface, exit_interface=exit_intf, channel=channel, essid=essid, ap_password=ap_password, webserver_path=webserver_path)
            else:
                intf = input("[>] In which interface is the AP running: ")
                self.evil_twin.stop_eviltwin(interface=intf)
        except:
            print("[!] Couldn't execute the command successfully")
            print("[*] Check the syntax: evil_twin [start|stop|list]")

    # WAPA Database Management System (DMS)

    # WAPA DMS Aliases
    def do_db(self, args):
        self.do_database(args)

    # WAPA DMS Main
    def do_database(self, args):
        """
        Database interaction
        """
        try:
            args = args.split()
            wapa_database = WapaDatabase()
            if args[0].lower() == "generate":
                wapa_database.generate_tables()
                print("[*] Tables generated successfully")
            
            if args[0].lower() == "add":
                interface_to_add = args[1]
                if interface_to_add in interfaces():
                    wapa_database.add_iface(interface_to_add)
                    print(f"[+] Interface {interface_to_add} has been added to the database")
                else:
                    print(f"[!] Interface {interface_to_add} not detected")
            
            if args[0].lower() == "remove" or args[0].lower() == "delete":
                interface_to_remove = args[1]
                if interface_to_remove in interfaces():
                    wapa_database.rem_iface(interface_to_remove)
                    print(f"[+] Interface {interface_to_remove} has been deleted from the database")
                else:
                    print(f"[!] Interface {interface_to_remove} not detected")
                
            if args[0].lower() == "list" or args[0].lower() == "query":
                try:
                    if args[1] == "interfaces" or args[1] == "ifaces":
                        wapa_database.list_ifaces()
                    elif args[1] == "automon":
                        wapa_database.query_automon()
                except:
                    print("[!] What would you like to list?\n--> interfaces\n--> automon")
        except:
            print("[!] Check the syntax: database\nadd --> add an interface to the database\nremove --> remove an interface from the database\nquery/list --> check the status of automon or list interfaces")

    # WAPA Inner config

    def do_set(self, args):
        """
        Set WAPA configuration
        """
        args = args.split()
        wapa_database = WapaDatabase()
        if args[0].lower() == "automon":
            try:
                if args[1].lower() == "true" or args[1].lower() == "1" or args[1].lower() == "t" or args[1].lower() == "yes" or args[1].lower() == "y":
                    wapa_database.set_auto_monitor_mode(True)
                elif args[1].lower() == "false" or args[1].lower() == "0" or args[1].lower() == "f" or args[1].lower() == "no" or args[1].lower() == "n":
                    wapa_database.set_auto_monitor_mode(False)
            except:
                print("[!] Statement left (true/false)")

    def do_clear(self, args):
        """
        Delete all entries from a table
        """
        try:
            args = args.split()
            if args[0].lower() == "beacons" or args[0].lower() == "networks" or args[0].lower() == "ap" or args[0].lower() == "aps":
                wapadb = WapaDatabase()
                wapadb.clear_networks()
                print("[*] Removed all entries from scan table.")
            elif args[0].lower() == "probe" or args[0].lower() == "probes" or args[0].lower() == "clients":
                wapadb = WapaDatabase()
                wapadb.clear_probes()
                print("[*] Removed all entries from probe_scan table.")
            elif args[0].lower() == "scan" or args[0].lower() == "scanner" or args[0].lower() == "both" or args[0].lower() == "all":
                wapadb = WapaDatabase()
                wapadb.clear_scan()
                print("[*] Removed all entries from tables:\n--> scan\n--> probe_scan")
        except:
            print("[!] Check the syntax: clear [beacons|probes|scan]")

    # INTERFACE MANAGEMENT SYSTEM (IMS)

    # WAPA IMS Aliases
    def do_interfaces(self, args):
        self.do_interface(args)

    def do_ifaces(self, args):
        self.do_interface(args)

    def do_iface(self, args):
        self.do_interface(args)

    # WAPA IMS Main
    def do_interface(self, args):
        """
        Enable or disable monitor mode on interfaces
        """
        args = args.split()
        gp = GeneralPurpose()
        if len(args) > 1:
            interface_interaction = args[1]
        else:
            interface_interaction = None
        try:
            if args[0] == "start" or args[0] == "enable" or args[0] == "monitor":
                gp.start_monitor_mode(interface_interaction)
            elif args[0] == "stop" or args[0] == "disable" or args[0] == "managed":
                gp.stop_monitor_mode(interface_interaction)
        except:
            print("[!] Check the syntax: interface <action> <interface_name>")


if __name__ == '__main__':
    if os.path.exists("/var/lib/wapa"):
        pass
    else:
        os.mkdir("/var/lib/wapa")
        os.mkdir("/var/lib/wapa/eviltwin")
        os.mkdir("/var/lib/wapa/evil_twin_webserver")
        print("[!] Generating database")
        wapadb = WapaDatabase()
        wapadb.generate_tables()
        time.sleep(2.5)
    if os.path.exists("/var/lib/wapa/eviltwin"):
        pass
    else:
        os.mkdir("/var/lib/wapa/eviltwin")
    if os.path.exists("/var/lib/wapa/evil_twin_webserver"):
        pass
    else:
        os.mkdir("/var/lib/wapa/evil_twin_webserver")
    execution = True
    pe = PreExecution()
    pe.automon_setup()

    interface_daemon = Thread(target=pe.wapa_interface_daemon)
    interface_daemon.daemon = True
    interface_daemon.start()
    time.sleep(1)
    
    # WAPA SHELL STARTUP
    os.system("clear")
    if random_title == 1:
        print(colored(titulo1,colores[random_color_title]))
    else:
        print(colored(titulo2,colores[random_color_title]))

    # Shell
    shell = WapaShell()
    shell.cmdloop()
