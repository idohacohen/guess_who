from scapy.all import *
import requests
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.l2 import Ether
from typing import List, Dict


class AnalyzeNetwork:
    def __init__(self, pcap_path: str) -> None:
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path: str = pcap_path
        self.pcap: PacketList = rdpcap(pcap_path)


    @staticmethod
    def get_vendor(mac: str) -> str:
        """returns the vendor of a device given its MAC address"""
        mac = mac.replace(':', '')
        url = f'https://api.macvendors.com/{mac}'
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return 'Unknown'


    @staticmethod
    def get_packet_info(packet: Packet) -> Dict[str, str]:
        """returns a dict with information about a device given a packet"""
        packet_info = {}
        if Ether in packet:
            packet_info['MAC'] = packet[Ether].src
            packet_info['Vendor'] = AnalyzeNetwork.get_vendor(packet[Ether].src)
        else:
            packet_info['MAC'] = 'Unknown'
        if IP in packet:
            packet_info['IP'] = packet[IP].src
            packet_info['protocol'] = packet[IP].proto
            packet_info['ttl'] = packet[IP].ttl
        else:
            packet_info['IP'] = 'Unknown'
            packet_info['protocol'] = 'Unknown'
            packet_info['ttl'] = 'Unknown'
        return packet_info
    

    def get_ips(self) -> List[str]:
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        ips = []
        for packet in self.pcap:
            if IP in packet:
                ips.append(packet[IP].src)
                ips.append(packet[IP].dst)
        return list(set(ips))


    def get_macs(self) -> List[str]:
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        macs = []
        for packet in self.pcap:
            if Ether in packet:
                macs.append(packet[Ether].src)
                macs.append(packet[Ether].dst)
        return list(set(macs))


    def get_info_by_mac(self, mac: str) -> Dict[str, str] | None:
        """returns a dict with all information about the device with
            given MAC address"""
        for packet in self.pcap:
            if Ether in packet and packet[Ether].src == mac:
                return self.get_packet_info(packet)


    def get_info_by_ip(self, ip : str) -> Dict[str, str] | None:
        """returns a dict with all information about the device with
        given IP address"""
        for packet in self.pcap:
            if IP in packet and packet[IP].src == ip:
                return self.get_packet_info(packet)


    def get_info(self) -> List[Dict[str, str]]:
        """returns a list of dicts with information about every
        device in the pcap"""
        info = []
        for packet in self.pcap:
            info.append(self.get_packet_info(packet))
        return info
    

    def guess_os(self, device_info: Dict[str, str]) -> str:
        """returns the most likely OS of a device given its info"""
        if device_info['ttl'] == 'Unknown':
            return 'Unknown'
        elif device_info['ttl'] <= 64:
            return 'Linux/MacOS'
        elif device_info['ttl'] <= 128:
            return 'Windows'
        else:
            return 'net device'
        


    def __repr__(self) -> str:
        return str(self)


    def __str__(self) -> str:
        return str(self.get_info())
    


if __name__ == '__main__':
    pcap_path = 'pcap-01.pcapng'
    network = AnalyzeNetwork(pcap_path)
    print(network)
    print(network.guess_os(network.get_info()[0]))
    print(network.guess_os(network.get_info()[1]))
