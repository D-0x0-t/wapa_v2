# wapa general purposes script
import sqlite3
import sys, os, re
import pandas as pd
import subprocess
from threading import Thread
from threading import Lock
from tabulate import tabulate
from time import sleep
from random import randint

class GeneralPurpose:
    #
    #
    # db interaction for general purpose commands
    #
    #
    def start_monitor_mode(self, interface=None):
        db_path = "/var/lib/wapa/wapa.db"
        conn = sqlite3.connect(db_path, check_same_thread=False)
        if interface is None:
            yesorno = input("[>] Do you want to put all database interfaces in monitor mode? (y/n): ")
            if yesorno.lower() == "n" or yesorno.lower() == "no":
                pass
            elif yesorno.lower() == "y" or yesorno.lower() == "yes":
                cursor = conn.cursor()
                cursor.execute("""SELECT iname FROM interfaces""")
                ifaces = cursor.fetchall()
                for iface in ifaces:
                    iface_string = iface[0]
                    os.system(f"ifconfig {iface_string} down 2>/dev/null")
                    os.system(f"macchanger -A {iface_string} 1>/dev/null 2>/dev/null")
                    os.system(f"iwconfig {iface_string} mode monitor 2>/dev/null")
                    os.system(f"ifconfig {iface_string} up 2>/dev/null")
                    cursor = conn.cursor()
                    cursor.execute("UPDATE interfaces SET mode='Monitor' WHERE iname=(?)", (iface_string,))
                conn.commit()
        else:
            os.system(f"ifconfig {interface} down 2>/dev/null")
            os.system(f"macchanger -A {interface} 1>/dev/null 2>/dev/null")
            os.system(f"iwconfig {interface} mode monitor 2>/dev/null")
            os.system(f"ifconfig {interface} up 2>/dev/null")
            cursor = conn.cursor()
            cursor.execute("UPDATE interfaces SET mode='Monitor' WHERE iname=(?)", (interface,))
            conn.commit()
        cursor.close()
        conn.close()


    def stop_monitor_mode(self, interface=None):
        db_path = "/var/lib/wapa/wapa.db"
        conn = sqlite3.connect(db_path, check_same_thread=False)
        if interface is None:
            yesorno = input("[>] Do you want to put all database interfaces in managed mode? (y/n): ")
            if yesorno.lower() == "n" or yesorno.lower() == "no":
                pass
            elif yesorno.lower() == "y" or yesorno.lower() == "yes":
                cursor = conn.cursor()
                cursor.execute("""SELECT iname FROM interfaces""")
                ifaces = cursor.fetchall()
                for iface in ifaces:
                    iface_string = iface[0]
                    os.system(f"ifconfig {iface_string} down 2>/dev/null")
                    os.system(f"macchanger -p {iface_string} 1>/dev/null 2>/dev/null")
                    os.system(f"iwconfig {iface_string} mode managed 2>/dev/null")
                    os.system(f"ifconfig {iface_string} up 2>/dev/null")
                    cursor.execute("UPDATE interfaces SET mode='Managed' WHERE iname=(?)", (iface_string,))
                conn.commit()
        else:
            os.system(f"ifconfig {interface} down 2>/dev/null")
            os.system(f"macchanger -p {interface} 1>/dev/null 2>/dev/null")
            os.system(f"iwconfig {interface} mode managed 2>/dev/null")
            os.system(f"ifconfig {interface} up 2>/dev/null")
        cursor = conn.cursor()
        cursor.execute("UPDATE interfaces SET mode='Managed' WHERE iname=(?)", (interface,))
        conn.commit()
        cursor.close()
        conn.close()

    #channel hopper (interface, fr(rango de frecuencias (banda)))
    def channel_hop(self, interface, band="2.4"):
        if band == "2.4":
            chmax = 1
            ch = 1
            while True:
                os.system(f"iwconfig {interface} channel {ch}")
                ch = randint(1, chmax)
                sleep(0.5)
        else: # support for 5ghz antennas
            band_5gh_channels = [32, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 68, 96, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159, 161, 163, 165, 167, 169, 171, 173, 175, 177]
            list_band_5gh_ch_length = len(band_5gh_channels) - 1
            while True:
                random_channel_from_5gh_channels = randint(0, list_band_5gh_ch_length)
                ch = band_5gh_channels[random_channel_from_5gh_channels]
                os.system(f"iwconfig {interface} channel {ch}")
                sleep(0.5)
    
    def static_channel(self, interface, ch):
        os.system(f"iwconfig {interface} channel {ch}")