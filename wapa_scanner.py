from scapy.layers.dot11 import Dot11Elt, Dot11Beacon, Dot11, Dot11ProbeReq, Dot11ProbeResp
from scapy.all import sniff
from threading import Thread
from threading import Lock
import pandas
import time
import os
import sqlite3
import sys

from wapa_db import WapaDatabase


class WAPANetworkScanner:
    #scanner_networks = pandas.DataFrame(columns=["BSSID", "ESSID", "Signal", "Channel", "Crypto"])
    #scanner_networks.set_index("BSSID", inplace=True)
    ap_list = []
    probe_request_list = []
    probe_response_list = []
    empty_bytes = bytes()
    lock = Lock()

    # esto se inicializa como un hilo que corre en el background para no interferir con la shell
    # otra que se puede hacer es show scanner (tiempo) y que muestre actualizaciones de la base de datos cada x tiempo
    # no se como meter eso de momento pero habría que mirarlo, podría quedar MUY interesante
    # implementar función en wapa_db.py que cargue los datos en la base de datos, así no es necesario crear un método similar aquí
    def Packet_Handler_for_database(self, pkt):
        if pkt.haslayer(Dot11Beacon): # handle beacon frames
            bssid = pkt[Dot11].addr2
            if bssid not in self.ap_list:
                self.ap_list.append(bssid)
                essid = pkt[Dot11Elt].info.decode()
                if essid != "" and essid != " ":
                    pass
                else:
                    essid = "<null>"
                try:
                    signal = pkt.dBm_AntSignal
                except:
                    signal = "N/A"
                stats = pkt[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                crypto = stats.get("crypto")
                crypto = str(crypto)
                crypto = crypto[1:-1]
                data = (str(bssid), str(essid), str(signal), str(channel), str(crypto))
                self.lock.acquire(True)
                wapadb = WapaDatabase()
                wapadb.scan_to_database(data)
                self.lock.release()
        elif pkt.haslayer(Dot11ProbeReq):
            if pkt.info != self.empty_bytes:
                wapadb = WapaDatabase()
                src = pkt.addr2
                dst = pkt.info
                data = ("Request", str(src), str(dst.decode()))
                self.lock.acquire(True)
                wapadb.probes_to_database(data)
                self.lock.release()
        elif pkt.haslayer(Dot11ProbeResp):
            wapadb = WapaDatabase()
            src = pkt.info
            dst = pkt.addr1
            data = ("Response", str(src.decode()), str(dst))
            self.lock.acquire(True)
            wapadb.probes_to_database(data)
            self.lock.release()
    
    def network_sniffer(self, intf):
        sniff(prn=self.Packet_Handler_for_database, stop_filter=lambda _: self.should_stop, iface=intf)

    def start_scan_thread(self, intf):
        self.should_stop = False
        check_scan = WapaDatabase()
        can_scan = check_scan.check_scanner()
        if can_scan is False:
            print("[!] There is already an undergoing scan")
        else:
            wapadb = WapaDatabase()
            wapadb.change_status(intf, 1)
            self.scanner_thread = Thread(target=self.network_sniffer, args=(intf,))
            self.scanner_thread.start()
    
    def stop_scan_thread(self):
        print("[*] Stopping scanner")
        wapadb = WapaDatabase()
        wapadb.change_status(None, 1)
        self.should_stop = True
        time.sleep(1)
        self.scanner_thread.join()














































#class WAPANetworkScanner:
#    scanner_networks = pandas.DataFrame(columns=["BSSID", "ESSID", "Signal", "Channel", "Crypto"])
#    scanner_networks.set_index("BSSID", inplace=True)
#    stop_printing = False
#    stop_scan = False
#
#    def __init__(self, interface, chop, bssid_filter, interval):
#        self.intf = interface
#        self.do_channel_hop = chop
#        self.filter_bssid = bssid_filter
#        self.scan_interval = interval
#
#    def wapa_scanner_PacketHandler(self, pkt):
#        if not self.stop_scan:
#            if pkt.haslayer(Dot11Beacon):
#                bssid = pkt[Dot11].addr2
#                essid = pkt[Dot11Elt].info.decode()
#                if essid != "":
#                    essid = essid
#                else:
#                    essid = "<null ESSID>"
#                try:
#                    signal = pkt.dBm_AntSignal
#                except:
#                    signal = " - "
#                stats = pkt[Dot11Beacon].network_stats()
#                channel = stats.get("channel")
#                crpt = stats.get("crypto")
#                if self.filter_bssid == 1:
#                    if bssid == self.filter_bssid or bssid.upper() == self.filter_bssid:
#                        self.scanner_networks.loc[bssid] = (essid, signal, channel, crpt)
#                else:
#                    self.scanner_networks.loc[bssid] = (essid, signal, channel, crpt)
#
#    def wapa_scanner_print_results(self):
#        while not self.stop_printing:
#            os.system("clear")
#            print(self.scanner_networks)
#            time.sleep(self.scan_interval)
#
#    def channel_hop(self):
#        ch = 0
#        while True:
#            os.system(f"iwconfig {self.intf} channel {ch}")
#            ch = ch % 14 + 1
#            time.sleep(self.scan_interval)
#
#    def stop_scan(self):
#        self.stop_printing = True
#        self.stop_scan = True