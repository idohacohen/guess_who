from scapy.all import *
import requests
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.l2 import Ether


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.pcap = rdpcap(pcap_path)


    @staticmethod
    def get_vendor(mac):
        """returns the vendor of a device given its MAC address"""
        mac = mac.replace(':', '')
        url = f'https://api.macvendors.com/{mac}'
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return 'Unknown'


    @staticmethod
    def get_packet_info(packet):
        """returns a dict with information about a device given a packet"""
        packet_info = {}
        if Ether in packet:
            packet_info['MAC'] = packet[Ether].src
            packet_info['Vendor'] = AnalyzeNetwork.get_vendor(packet[Ether].src)
        else:
            packet_info['MAC'] = 'Unknown'
        if IP in packet:
            packet_info['IP'] = packet[IP].src
        else:
            packet_info['IP'] = 'Unknown'
        return packet_info
    

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        ips = []
        for packet in self.pcap:
            if IP in packet:
                ips.append(packet[IP].src)
                ips.append(packet[IP].dst)
        return list(set(ips))


    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        macs = []
        for packet in self.pcap:
            if Ether in packet:
                macs.append(packet[Ether].src)
                macs.append(packet[Ether].dst)
        return list(set(macs))


    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
            given MAC address"""
        for packet in self.pcap:
            if Ether in packet and packet[Ether].src == mac:
                return self.get_packet_info(packet)


    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        for packet in self.pcap:
            if IP in packet and packet[IP].src == ip:
                return self.get_packet_info(packet)


    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        info = []
        for packet in self.pcap:
            info.append(self.get_packet_info(packet))
        return info
        


    def __repr__(self):
        return str(self)


    def __str__(self):
        return str(self.get_info())
    


if __name__ == '__main__':
    pcap_path = 'pcap-00.pcapng'
    network = AnalyzeNetwork(pcap_path)
    print(network)
