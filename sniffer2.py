from scapy.all import *
class Packet:
    def __init__(self):
        self.number=0
        self.list=[]
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

    def store_and_print(self,packet):
        if packet["ICMP"].type == 0:
            for p in self.list:
                if p.dst == packet.src and p.src == packet.dst :
                    self.print_summary(p)
                    self.list.remove(p)
                    self.print_summary(packet)
        elif packet["ICMP"].type == 8:
            if len(self.list) != 0:
                print("time out")
            self.list.append(packet)

        else:
            print("error")


packet = Packet()
sniffed=sniff(filter="icmp",prn=packet.store_and_print , count = 5)
for i in sniffed:
    print(i.summary())
