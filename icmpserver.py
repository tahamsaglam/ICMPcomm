import struct
import sys
from threading import Thread
from time import sleep
import pcapy
import socket
from pcapy import findalldevs, open_live
from struct import pack,unpack
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
from scapy.all import *


class DecoderThread(Thread):
    def __init__(self, pcapObj):
        # PCAP için datalink tipi sec
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcapObj
        Thread.__init__(self)

    def run(self):
        #Surekli dinleme
        while(1) :
            (header, packet) = self.pcap.next()
            self.packetHandler(packet)
    #Ethernet stringi isleyip mac adreslerini ortaya cikar
    def eth_addr(self,a):
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])
        return b
    def carry_around_add(self,a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)
    def checksum(self,msg):
        # mesaj uzunlugu tek sayiysa 0la doldur padding
        if len(msg)%2 is 1:
            msg += b'\x00'
        # IP checksuma bak
        s = 0
        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i+1] << 8)
            s = self.carry_around_add(s, w)
        answer = ~s & 0xffff
        return answer >> 8 | (answer << 8 & 0xff00)

    def pack_reply(self,identifier, sequence, content):
        header = struct.pack(
            ">bbHHH",
            0, 0,
            0, identifier, sequence)

        header_checksum = self.checksum(header + content)

        header = struct.pack(
            ">bbHHH",
            0, 0,
            header_checksum, identifier, sequence)

        return header + content
    def packetHandler(self,packet):
        #ethernet headeri ayikla
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        

        #IP protokol = 8
        if eth_protocol == 8 :
            #IP header ayikla
            #IP headerin ilk 20 karakter al
            ip_header = packet[eth_length:20+eth_length]
            
            #Ilk 20 karakteri unpackle
            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            #socketin builtin fonksiyonuya hexadecimal adresi IP'ye donustur
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
            

            #ICMP Paketi
            if protocol == 1 :
                print ('Destination MAC : ' + self.eth_addr(packet[0:6]) + ' Source MAC : ' + self.eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                u = iph_length + eth_length
                icmph_length = 8
                icmp_header = packet[u:u+4]
                idseq_header=packet[u+4:u+8]
                print(icmp_header)
                print(idseq_header)
                #ICMP unpackle
                icmph = unpack('!BBH' , icmp_header)
                idseq = unpack('!HH' , idseq_header)
                print(icmph)
                print(idseq[0])
                print(idseq[1])
                
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]
                
                print ('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))
                
                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size
                
                #PAketten datayi ayikla
                data = packet[h_size:]
                #datayi ekrana bas
                print ('Data : ' + str(data))
                #gelen paketin tipi 8se cevap dondur
                if(icmp_type==8):
                    icmp_type=0
                    checksum=0
                    send(IP(dst=s_addr,src=d_addr)/ICMP(type=0,id=idseq[0], seq=idseq[1]))


def getInterface():
    # NICleri ara
    ifs = findalldevs()

    # NIC yok
    if 0 == len(ifs):
        print ("Hata.")
        sys.exit(1)

    # Tek nic varsa secmeden kullan
    elif 1 == len(ifs):
        print ('Tek nic.')
        return ifs[0]

    # Coklu niclerin arasindan sec
    count = 0
    for iface in ifs:
        print ('%i - %s' % (count, iface))
        count += 1
    idx = int(input('Interface sec: '))

    return ifs[idx]

def main(filter):
    dev = getInterface()

    # Paket yakalama icin NIC ac
    p = open_live(dev, 1500, 0, 100)
    # BPF filtresi varsa uygula
    p.setfilter(filter)

    print ("Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink()))

    # Sniff threadini baslat
    DecoderThread(p).start()

#BPF filtreyi CLIdan al
filter = ''
if len(sys.argv) > 1:
    filter = ' '.join(sys.argv[1:])
    print(filter)

main(filter)