from scapy.all import *
class Packet:
    def __init__(self):
        self.number=0
    def print_summary(self ,packet):
        print("______________________________")
        self.number += 1
        print(packet.summary())
        print("source mac  = " + str(packet.src))
        print("destination mac  = " + str(packet.dst))
        print("source ip = " + str(packet["IP"].src))
        print("destination ip = " + str(packet["IP"].dst))
        if packet["ICMP"].type == 0:
            print("type = reply")
        elif packet["ICMP"].type == 8:
            print("type = request")
        print("number" , self.number)

packet = Packet()
sniffed=sniff(filter="icmp",prn=packet.print_summary)
