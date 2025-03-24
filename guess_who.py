from scapy.all import *
import requests
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from typing import List, Dict
from time import sleep


class AnalyzeNetwork:
    counter = 0
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
        sleep(1) # to avoid getting blocked
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return 'Unknown'


    @staticmethod
    def get_packet_info(packet: Packet, check_vendor: bool) -> Dict[str, str]:
        """returns a dict with information about a device given a packet"""
        packet_info = {}
        AnalyzeNetwork.counter += 1
        if check_vendor:
            packet_info['MAC'] = packet[Ether].src
            packet_info['Vendor'] = AnalyzeNetwork.get_vendor(packet[Ether].src)

        if IP in packet:
            packet_info['IP'] = packet[IP].src
            packet_info['protocol'] = packet[IP].proto
            packet_info['ttl'] = packet[IP].ttl
            packet_info['size'] = packet[IP].len
            packet_info['flags'] = packet[IP].flags.value
        else:
            packet_info['IP'] = 'Unknown'
            packet_info['protocol'] = 'Unknown'
            packet_info['ttl'] = 'Unknown'
            packet_info['size'] = 'Unknown'
            packet_info['flags'] = 'Unknown'

        if TCP in packet and packet[TCP].payload:
            if "HTTP" in str(packet[TCP].payload.load):
                data = packet[TCP].payload.load.decode('utf-8').split('\r\n')[1:]
                for line in data:
                    if line.startswith('User-Agent:'):
                        packet_info['program'] = line.split(': ')[1]
                    if line.startswith('Server:'):
                        packet_info['program'] = line.split(': ')[1]
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
                return self.get_packet_info(packet, True)


    def get_info_by_ip(self, ip : str) -> Dict[str, str] | None:
        """returns a dict with all information about the device with
        given IP address"""
        for packet in self.pcap:
            if IP in packet and packet[IP].src == ip:
                return self.get_packet_info(packet, True)


    def get_info(self) -> List[Dict[str, str]]:
        """returns a list of dicts with information about every
        device in the pcap"""
        info = []
        macs = self.get_macs()
        for mac in macs: # finding vendor takes a long time so we only do it once
            info.append(self.get_info_by_mac(mac))
        for packet in self.pcap:
            mac_index = macs.index(packet[Ether].src)
            info[mac_index].update(self.get_packet_info(packet, False))
        return info
    

    def guess_os_by_ttl(self, ttl: int) -> str:
        """returns the most likely OS given a TTL value"""
        if 0 <= ttl <= 64:
            return 'Linux'
        elif 65 <= ttl <= 128:
            return 'Windows'
        elif 129 <= ttl <= 255:
            return 'network device'
        else:
            return 'Unknown'
        
    def guess_os_by_size(self, size: int) -> str:
        """returns the most likely OS given a packet size"""
        if size == 60:
            return 'Windows'
        elif size == 84:
            return 'Linux'
        else:
            return 'Unknown'
        
    
    def guess_os_by_flags(self, flags: str) -> str:
        """returns the most likely OS given a packet's flags"""
        if flags == 0:
            return 'Windows'
        elif flags == 2:
            return 'Linux'
        else:
            return 'Unknown'


    def guess_os(self, device_info: Dict[str, str]) -> str:
        """returns the most likely OS of a device given its info"""
        ret = 'Unknown'
        if device_info['size'] != 'Unknown':
            ret = self.guess_os_by_size(int(device_info['size']))
        if device_info['flags'] != 'Unknown' and ret == 'Unknown':
            ret = self.guess_os_by_flags(int(device_info['flags']))
        if device_info['ttl'] != 'Unknown' and ret == 'Unknown':
            ret = self.guess_os_by_ttl(int(device_info['ttl']))
        return ret
        
        


    def __repr__(self) -> str:
        return str(self).replace('\n', ',')


    def __str__(self) -> str:
        return str(self.get_info())
    


if __name__ == '__main__':
    pcap_path = 'pcap-03.pcapng'
    network = AnalyzeNetwork(pcap_path)
    print(network)
