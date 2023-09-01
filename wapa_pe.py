# wapa pre-execution script
import os, sys
import sqlite3
import time
from wapa_db import WapaDatabase
from wapa_gp import GeneralPurpose

class PreExecution:
    execute_wid = True

    def automon_setup(self):
        try:
            wapadb = WapaDatabase()
            is_automon = wapadb.query_automon("check")
            if is_automon is True:
                wapadb = WapaDatabase()
                ifaces = wapadb.get_iface_names()
                print("[*] Automon is enabled, starting monitor mode on:")
                for i in ifaces:
                    print(f"--> {i}")
                    wapagp = GeneralPurpose()
                    wapagp.start_monitor_mode(i)
            else:
                print("[*] Automon is disabled")
        except:
            print("[!] Table does not exist. If this is the first time you are executing wapa, you might want to set up the database using 'database generate'")

    def wapa_interface_daemon(self): #interface daemon se encarga de comprobar el estado de las interfaces con respecto al sistema
        # si encuentra una discordancia, la base de datos de wapa tiene prioridad ante el sistema, así que en >5s restaura el estado
        # de la interfaz de acuerdo con la BBDD
        while self.execute_wid:
            try:
                time.sleep(5)
                wapadb = WapaDatabase()
                interface_daemon_if_status = wapadb.daemon_query()
                for interface in interface_daemon_if_status:
                    if interface_daemon_if_status[interface] == 0:
                        pass # iface OK
                    elif interface_daemon_if_status[interface] == 1:
                        wapagp = GeneralPurpose()
                        wapagp.start_monitor_mode(interface)
                    elif interface_daemon_if_status[interface] == 2:
                        wapagp = GeneralPurpose()
                        wapagp.stop_monitor_mode(interface)
            except:
                print("[!] DAEMON ERROR!")
    
    def disable_wapa_interface_daemon(self):
        self.execute_wid = False