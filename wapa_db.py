import sqlite3
import sys, os, re
import pandas as pd
import subprocess
from threading import Thread
from threading import Lock
from tabulate import tabulate
from time import sleep

from wapa_gp import GeneralPurpose

class WapaDatabase:
    def __init__(self, db_path=None):
        if db_path is None:
            self.db_path = "/var/lib/wapa/wapa.db"
        else:
            self.db_path = db_path # to be implemented...

        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

    def generate_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS interfaces (
                iname TEXT,
                mode TEXT,
                status INTEGER
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evil_twin_results (
                email TEXT,
                password TEXT,
                hostname TEXT,
                mac TEXT,
                ip TEXT,
                target TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS set_monitor_mode_auto (
                automon INTEGER
            )
        """)
        cursor.execute("INSERT INTO set_monitor_mode_auto (automon) VALUES (0)")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan (               
                BSSID TEXT,
                ESSID TEXT,
                SIGNAL TEXT,
                CHANNEL TEXT,
                CRYPTO TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS probe_scan (
                TYPE TEXT,
                SRC TEXT,
                DST TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fuzzed_beacons (
                ESSID TXT,
                BSSID TXT,
                SECURITY TXT
            )               
        """)
        self.conn.commit()
        cursor.close()
        self.conn.close()
    
    def set_auto_monitor_mode(self, tf=None):
        if tf is None:
            pass
        else:
            cursor = self.conn.cursor()
            if tf is False:
                cursor.execute("UPDATE set_monitor_mode_auto SET automon = 0")
            else:
                cursor.execute("UPDATE set_monitor_mode_auto SET automon = 1")
            self.conn.commit()
            cursor.close()
            self.conn.close()

    def get_iface_names(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT iname FROM interfaces")
        ifaces_query_result = cursor.fetchall()
        ifaces = [ i[0] for i in ifaces_query_result ]
        fifaces = [ i for index, i in enumerate(ifaces) if i not in ifaces[:index] ]
        cursor.close()
        self.conn.close()
        return fifaces
    
    def query_automon(self, start_query=None): # pregunta por el estado de automon, si se llama de normal(query_automon(), devuelve el estado de automon. )
        cursor = self.conn.cursor() # cuando se ejecute el programa, deberá comprobarlo con query_automon("x") para que start_query no sea None y devuelva true o false dependiendo del estado
        cursor.execute("SELECT * FROM set_monitor_mode_auto")
        automon_list = cursor.fetchall()
        automon_status = automon_list[0][0]
        cursor.close()
        self.conn.close()
        if start_query is None:
            if automon_status == 0:
                print("[*] Automon mode is disabled")
            else:
                print("[*] Automon mode is enabled")
        else:
            if automon_status == 0:
                return False
            else:
                return True

    def add_iface(self, interface=None):
        if interface is None:
            print("[!] No interface specified")
        else:
            wireless_intf_pattern = r"(wl(?:.*)[0-9])"
            match = re.match(wireless_intf_pattern, interface)
            if match:
                interface_mode_cmd = f"iwconfig {interface} | grep Mode"
                interface_mode_cmd = interface_mode_cmd + " | awk '{print $1}' | cut -f2 -d':'"
                interface_mode = subprocess.run(interface_mode_cmd, shell=True, capture_output=True, text=True)
                interface_mode = interface_mode.stdout
                cursor = self.conn.cursor()
                cursor.execute("INSERT INTO interfaces (iname, mode, status) VALUES (?, ?, ?)", (interface, interface_mode.strip(), "0"))
                self.conn.commit()
                cursor.close()
            else:
                print("[!] Interface supplied appears not to be a wireless one")
        self.conn.close()
    
    def rem_iface(self, interface=None):
        if interface is None:
            print("[!] No interface specified")
        else:
            wireless_intf_pattern = r"(wl(?:.*)[0-9])"
            match = re.match(wireless_intf_pattern, interface)
            if match:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM interfaces WHERE iname=?", (interface,))
                self.conn.commit()
                cursor.close()
            else:
                print("[!] Interface supplied appears not to be a wireless one")
        self.conn.close()

    def swap_mode_to_master(self, intf):
        cursor = self.conn.cursor()
        cursor.execute("UPDATE interfaces SET mode='Master' WHERE iname=(?)", (intf,))
        self.conn.commit()
        cursor.close()
        self.conn.close()

    def swap_mode_to_managed(self, intf):
        cursor = self.conn.cursor()
        cursor.execute("UPDATE interfaces SET mode='Managed' WHERE iname=(?)", (intf,))
        self.conn.commit()
        cursor.close()
        self.conn.close()

    def list_ifaces(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM interfaces")
        list_ifs = cursor.fetchall()
        print(tabulate(list_ifs, headers=["Interface", "Mode", "Status"], tablefmt="pretty"))
        cursor.close()
        self.conn.close()
    
    def daemon_query(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT iname, mode FROM interfaces")
        interfaces = cursor.fetchall()
        interface_daemon_if_status = {}
        for if_row in interfaces:
            ifname = if_row[0]
            ifmode = if_row[1]
            sys_ifmode_cmd = f"iwconfig {ifname} | grep Mode"
            sys_ifmode_cmd = sys_ifmode_cmd + " | awk '{print $1}' | cut -f2 -d':'"
            sys_ifmode = subprocess.run(sys_ifmode_cmd, shell=True, capture_output=True, text=True)
            sys_ifmode = sys_ifmode.stdout.strip()
            if ifmode.lower() == sys_ifmode.lower():
                interface_daemon_if_status[ifname] = 0 # interface status is OK
            else:
                if ifmode.lower() == "monitor" and sys_ifmode.lower() != "monitor":
                    interface_daemon_if_status[ifname] = 1 # iface must be set on mode monitor
                elif ifmode.lower() == "master" or sys_ifmode.lower() == "master":
                    interface_daemon_if_status[ifname] = 0 # don't trigger if working with access points
                else:
                    interface_daemon_if_status[ifname] = 2 # iface must be set on mode managed
        cursor.close()
        self.conn.close()
        return interface_daemon_if_status
    
    def change_status(self, iface, status): # change interface status to 1 (being used by scanner)
        cursor = self.conn.cursor()
        if iface is not None:
            cursor.execute("UPDATE interfaces SET status = (?) WHERE iname = (?)", (status, iface))
        else:
            cursor.execute("UPDATE interfaces SET status = 0")    
        cursor.close()
        self.conn.commit()
        self.conn.close()

    def check_scanner(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT status FROM interfaces")
        status_query_result = cursor.fetchall()
        for i in status_query_result:
            if i[0] == 1:
                return False
        cursor.close()
        self.conn.close()
        return True

    def scan_to_database(self, data):
        cursor = self.conn.cursor()
        bssid = data[0]
        essid = data[1]
        signal = data[2]
        channel = data[3]
        crypto = data[4]
        cursor.execute("INSERT INTO scan (BSSID, ESSID, SIGNAL, CHANNEL, CRYPTO) VALUES (?, ?, ?, ?, ?)", (bssid, essid, signal, channel, crypto))
        self.conn.commit()
        cursor.close()
        self.conn.close()

    def get_scan(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT BSSID, ESSID, MIN(SIGNAL) AS SIGNAL, CHANNEL, CRYPTO FROM scan GROUP BY BSSID, ESSID, CHANNEL, CRYPTO ORDER BY ESSID, BSSID")
        scan_data = cursor.fetchall()
        print(tabulate(scan_data, headers=["BSSID", "ESSID", "Signal", "Channel", "Crypto"], tablefmt="pretty"))
        cursor.close()
        self.conn.close()

    def probes_to_database(self, data):
        cursor = self.conn.cursor()
        type = data[0]
        src = data[1]
        dst = data[2]
        cursor.execute("INSERT INTO probe_scan (TYPE, SRC, DST) VALUES (?, ?, ?)", (type, src, dst))
        self.conn.commit()
        cursor.close()
        self.conn.close()

    def get_probe_scan(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT TYPE, SRC, DST FROM probe_scan ORDER BY TYPE, SRC")
        scan_data = cursor.fetchall()
        print(tabulate(scan_data, headers=["TYPE", "SRC", "DST"], tablefmt="pretty"))
        cursor.close()
        self.conn.close()
    
    def scan_status(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM interfaces WHERE status = 1")
        query_result = cursor.fetchall()
        if len(query_result) == 0:
            print("[*] There is no scanning in progress")
        elif len(query_result) == 1:
            print("[*] There is a scan running on interface", query_result[0][0])
        cursor.close()
        self.conn.close()

    def beacons_to_table(self, essid, bssid, security):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO fuzzed_beacons (ESSID, BSSID, SECURITY) VALUES (?, ?, ?)", (essid, bssid, security))
        self.conn.commit()
        cursor.close()
        self.conn.close()
    
    def list_beacons(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM fuzzed_beacons")
        query_result = cursor.fetchall()
        print(tabulate(query_result, headers=["ESSID", "BSSID", "SECURITY"], tablefmt="pretty"))
        cursor.close()
        self.conn.close()

    def clear_beacons(self):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM fuzzed_beacons")
        self.conn.commit()
        cursor.close()
        self.conn.close()
    
    def clear_probes(self):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM probe_scan")
        self.conn.commit()
        cursor.close()
        self.conn.close()
        
    def clear_networks(self):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM scan")
        self.conn.commit()
        cursor.close()
        self.conn.close()

    def clear_scan(self):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM scan")
        self.conn.commit()
        cursor.execute("DELETE FROM probe_scan")
        self.conn.commit()
        cursor.close()
        self.conn.close()