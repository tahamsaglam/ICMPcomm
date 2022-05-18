from asyncio.windows_events import NULL
import ctypes
from socket import AF_INET
import sys
from time import sleep
import libpcap
from ctypes import *
import array
import struct
from bitstring import BitArray
import socket
from scapy.all import *
import datetime

libpcap.config(LIBPCAP="npcap")
alldevs = POINTER(libpcap.pcap_if_t)()
d = POINTER(libpcap.pcap_if_t)()
#fp = POINTER(libpcap.pcap_t)()
errbuf = create_string_buffer(libpcap.PCAP_ERRBUF_SIZE)

def ListInterfaces():
    if (libpcap.findalldevs(byref(alldevs), errbuf) == -1):
        print ("Hata: %s\n" % errbuf.value)
        sys.exit(1)

    interfaces = []
    d = alldevs.contents
    while d:
        interfaces.append(d)
        if d.next:
            d = d.next.contents
        else:
            d = False
    return interfaces

def OpenDevice(deviceHandle):
    fp = libpcap.open_live(deviceHandle, 65536, 1, 1000, errbuf)
    if fp == None:
        print ("Error opening device: %s\n" % errbuf.value)
        sys.exit(1)
    return fp

def build_packet(plist):
    packet = (c_ubyte * len(plist))()
    i = 0
    for bit in plist:
        packet[i] = ord(bit)
        i += 1
    return packet

def convertToHexBinary(hexa):
        converted=""
        for i in hexa.split(':'):
            converted+=r'\x'+i
        return converted

def convertDecimalIpToHexBinary(decimalIp):
        converted=""
        for i in decimalIp.split('.'):
            converted+=r'\x'+hex(int(i))[2:].zfill(2)
        return converted

def bytedondur(integer):
    return divmod(integer, 0x100)

def add_bits(n1, n2):
    result = n1.uint + n2.uint
    if result >= (1 << n1.length):
        result= (result & 0xffff) + (result >> 16)
    return BitArray(uint=result, length=n1.length)

interfaces = ListInterfaces()
index = 0
for i in interfaces:
    print(str(index)+": "+i.description.decode('UTF-8'))
    index+=1
ifaceno=int(input("Interface seciniz: "))
deviceName = interfaces[ifaceno].name
fp=OpenDevice(deviceName)

packetList=[]    
dstmac='30:cc:21:3d:3c:dc'
for spl in dstmac.split(':'):
    packetList.append(hex(int(spl, 16))) #0-5 destination mac

srcmac='f4:8e:38:ea:24:cd'
for spl in srcmac.split(':'):
    packetList.append(hex(int(spl, 16))) #6-11 source mac

ethType='08:00'
for spl in ethType.split(':'):
    packetList.append(format(int(spl, 16), '#04x')) #12-13 Ethernet Tip

versiyon='45'
packetList.append(format(int(versiyon, 16), '#04x')) #14 versiyon+hlen

servisAlani='0'
packetList.append(format(int(servisAlani, 16), '#04x')) #15 servis alani

totalLength='00:1c'
for spl in totalLength.split(':'):
    packetList.append(format(int(spl, 16), '#04x')) #16-17 total length

identification='30:39'
for spl in identification.split(':'):
    packetList.append(format(int(spl, 16), '#04x')) #18-19 identification

fragmantasyon='00:00'
for spl in fragmantasyon.split(':'):
    packetList.append(format(int(spl, 16), '#04x')) #20-21 fragmantasyon

timeToLive='80'
packetList.append(format(int(timeToLive, 16), '#04x')) #22 time to live

protocol='1' #icmp
packetList.append(format(int(protocol, 16), '#04x')) #23 protocol

IPheaderChecksum='00:00'
for spl in IPheaderChecksum.split(':'):
    packetList.append(format(int(spl, 16), '#04x')) #24-25 IP header checksum

srcIP=input("Kaynak IP: ")
for spl in srcIP.split('.'):
    packetList.append(format(int(spl), '#04x')) #26-29 src IP

dstIP=input("Hedef IP: ")
for spl in dstIP.split('.'):
    packetList.append(format(int(spl), '#04x')) #30-33 dst IP

header1 = BitArray(packetList[14]+packetList[15]) #ver+servis alani
header2 = BitArray(packetList[16]+packetList[17]) #total len
header3 = BitArray(packetList[18]+packetList[19]) #ident
header4 = BitArray(packetList[20]+packetList[21]) #frag
header5 = BitArray(packetList[22]+packetList[23]) #ttl+protocol
header6 = BitArray(packetList[24]+packetList[25]) #checksum bos
header7 = BitArray(packetList[26]+packetList[27]) #src ip1
header8 = BitArray(packetList[28]+packetList[29]) #src ip2
header9 = BitArray(packetList[30]+packetList[31]) #dst ip1
header10 = BitArray(packetList[32]+packetList[33]) #dst ip2
headerList=[header1, header2, header3, header4, header5, header6, header7, header8, header9, header10]

first=True
for i in range(9):
    if first==True:
        nba = BitArray(headerList[i])
        nba2= BitArray(headerList[i+1])
        result = add_bits(nba,nba2)
        first=False
    else:
        nba2= BitArray(headerList[i+1])
        result = add_bits(result,nba2)
ipChecksum=~result
packetList[24],packetList[25]=bytedondur(int(ipChecksum.hex, 16))
packetList[24]=hex(packetList[24])
packetList[25]=hex(packetList[25])

tipAlani='8' #ICMP
packetList.append(format(int(tipAlani, 16), '#04x')) #34 tip alani

kod='0' #echo request
packetList.append(format(int(kod, 16), '#04x')) #35 kod

ICMPheaderChecksum='00:00'
for spl in ICMPheaderChecksum.split(':'):
    packetList.append(format(int(spl, 16), '#04x')) #36-37 ICMP header checksum
print(packetList)


kalanICMPheader='03:15:00:01'
for spl in kalanICMPheader.split(':'):
    packetList.append(format(int(spl, 16), '#04x'))#38-41 ICMP header


# kalanICMP='a6:5d:4d:5e:00:00:00:00'
# for spl in kalanICMP.split(':'):
#     packetList.append(format(int(spl, 16), '#04x'))#42-50 ICMP data

# kalanICMP2='6d:65:72:68:61:62:61:54:61:68:61'
# for spl in kalanICMP2.split(':'):
#     packetList.append(format(int(spl, 16), '#04x'))#42-50 ICMP data

header1 = BitArray(packetList[34]+packetList[35]) #tip+kod
header2 = BitArray(packetList[36]+packetList[37]) #icmp header checksum bos
header3 = BitArray(packetList[38]+packetList[39]) #identifier
header4 = BitArray(packetList[40]+packetList[41]) #sequence
# header5 = BitArray(packetList[42]+packetList[43]) #data1
# header6 = BitArray(packetList[44]+packetList[45]) #data2
# header7 = BitArray(packetList[46]+packetList[47]) #data3
# header8 = BitArray(packetList[48]+packetList[49]) #data4
headerList=[header1, header2, header3, header4]
first=True
for i in range(3):
    if first==True:
        nba = BitArray(headerList[i])
        nba2= BitArray(headerList[i+1])
        result = add_bits(nba,nba2)
        first=False
    else:
        nba2= BitArray(headerList[i+1])
        result = add_bits(result,nba2)
icmpChecksum=~result

packetList[36],packetList[37]=bytedondur(int(icmpChecksum.hex, 16))
packetList[36]=hex(packetList[36])
packetList[37]=hex(packetList[37])

packet=bytes([int(x,0) for x in packetList])
packet=str(packet,'latin-1')
 
if (libpcap.sendpacket(fp, build_packet(packet), 50) != 0):
        print("Error sending the packet:\n  %s" % libpcap.pcap_geterr(fp))
senttime=datetime.datetime.now()
def arp_monitor_callback(pkt):
    if ICMP in pkt and pkt[ICMP].type ==0:
        rcvtime=datetime.datetime.now()
        print(str((rcvtime-senttime).microseconds/1000)+"ms")
sniff(prn=arp_monitor_callback, filter="icmp", store=0,iface=str(deviceName,'latin-1'))