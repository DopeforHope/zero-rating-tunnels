from scapy.all import *
import sys
import socket
import threading
import filterRTP as filter
from ctypes import create_string_buffer, addressof
from struct import pack
from pytun import TunTapDevice
import os
import threading
import checksum


# if AUTOMATIC_INIT is true only the OWN_IP parameter is necessary
AUTOMATIC_INIT = True

# Interface to listen on
# MUST be the interface faced towards your WAN (so not the NAT interface!)
INTERFACE = "enp0s31f6"

# IP of the NATted device for iptables DROP
NAT_IP = "10.42.0.28"

OWN_IP = "192.168.42.25"
SKYPE_IP = ""
SKYPE_PORT = -1
NAT_PORT = -1
#required for socket sending
OWN_MAC= "48:ba:4e:89:4d:b7"
ROUTER_MAC = "e0:28:6d:6e:e3:97"


DEBUG = False

# define the byte sequence by which a injected packet is identified
# currently only support 4 byte sequence (because of the assembly bpf from filter.py)
IDENTIFIER = b"\xca\xfe\xba\xbe"

#The call mode defines wether this machine has the calling device in its NAT or the called device
#ONLY VALUE ALLOWED: "CALLEE", "CALLER"
CALL_MODE = "CALLEE"

OFFLINE_TEST = False
OFFLINE_FILE1 = "STUNswitchOffline1.pcap"
OFFLINE_FILE2 = "STUNswitchOffline2.pcap"

# The time until the first packet is send
# it usually takes some time until both parties switch to the same relay
SLEEP_SETUP_TIME = 10

# MTU of the tunnel; Bytes will be reserved for the IP/UDP overhead
# making this value too high is can break the implementation - reasons not really known
# 1468 seems to be the best value
MTU = 1468

# Nr of send worker; ATTENTION: NOT WORKING RIGHT NOW
NR_SEND_WORKER = 1
NR_RCV_WORKER = 1

# Packets can be send via Scapy or via socket; sockets won't build right checksums
# ATTENTION: SOCKETS dont work atm
SEND_SCAPY = False


stop_sniff = False

def catch_parameters():

    def stop_sniff_filter(p):
        global stop_sniff
        return stop_sniff

    def stage1_filter(p):
        #print("Stage 1 Hit")
        global SKYPE_IP
        global SKYPE_PORT
        # check for classic stun msg format
        if p[Raw].load.startswith(stun_byte_sequence):
            p.show()
            # stun starts with 2 byte (checked before) then 2 byte msg length,
            # 4 byte msg cookie then 96-bit transaction identifier
            # after this comes the attributes (so we wanna check this part)

            position = 2 + 2 + 4 + 12

            msg_len = int.from_bytes(p[Raw].load[2:4], "big")

            # an attribute starts with it's type and then th rest length
            # so we go through the attributes and search for the mapped address (type 0x0001)
            while position < msg_len:
                if p[Raw].load[position:position + 2] == attribute_byte_sequence:
                    print("Stage 1.1 Hit")
                    # this is the remote address
                    # at first comes the type (2 bytes) (which we checked)
                    # then the attribute length (2 bytes)
                    # then the protocol family (2 bytes)
                    # then the port (2 byte)
                    # then the IP (4 byte)

                    port_bytes = p[Raw].load[position + 6:position + 8]
                    port = int.from_bytes(port_bytes, "big")

                    # skype turn server always uses 3480 or 3478
                    # TODO: mapped address is always sender address
                    if port == 3480 or port == 3478:
                        # collect IP Address
                        ip_bytes = p[Raw].load[position + 8:position + 12]
                        ip_ints = []
                        for b in ip_bytes:
                            # it seems like python automatically convert the bytes to int if you iterate over them
                            ip_ints.append(b)

                        # we got the IP address and set the parameter
                        SKYPE_IP = "{}.{}.{}.{}".format(ip_ints[0], ip_ints[1], ip_ints[2], ip_ints[3])
                    else:
                        print("Unknown port???")
                    break
                else:
                    # jump to the next attribute
                    # 2 bytes for the attribute, 2 bytes for the msg length and the length by itself
                    len_bytes = p[Raw].load[position + 2:position + 4]
                    position += 2 + 2 + int.from_bytes(len_bytes, "big")
            if SKYPE_IP != "":
                print("[Stage 1 Sniffer] Stopping Stage 1 sniffer")
                global stop_sniff
                stop_sniff = True


    def stage2_filter(p):
        print("Stage 2 Hit")
        global NAT_PORT
        global SKYPE_PORT
        NAT_PORT = p.sport
        SKYPE_PORT = p.dport

        #extract RTP header
        global RTP_HEADER
        RTP_HEADER = Raw(p[UDP]).load[8:28]

        global stop_sniff
        stop_sniff = True

    stun_byte_sequence = b'\x01\x03'
    attribute_byte_sequence = b'\x00\x01'

    stage1_bpf_filter = "ip and ip dst host {own_ip} and udp and udp src port 3478".format(own_ip=OWN_IP)
    print("Stage 1 BPF:\n{}".format(stage1_bpf_filter))


    if OFFLINE_TEST:
        sniff(iface=INTERFACE,
              prn=stage1_filter,
              filter=stage1_bpf_filter,
              stop_filter=stop_sniff_filter,
              offline=OFFLINE_FILE1)

    else:
        sniff(iface=INTERFACE,
              prn=stage1_filter,
              filter=stage1_bpf_filter,
              stop_filter=stop_sniff_filter)


    if SKYPE_IP == "":
        raise Exception("Couldn't find the Mapped Address")


    print("Stage 1 Complete")
    stage2_bpf_filter = "ip and ip src host {own_ip} and ip dst host {skype_ip} " \
                        "and udp and (udp dst port 3478 or udp dst port 3480) and udp[8] = 0x90".format(own_ip=OWN_IP,
                                                                                                 skype_ip=SKYPE_IP)

    print("Stage 2 BPF:\n{}".format(stage2_bpf_filter))

    if OFFLINE_TEST:
        sniff(iface=INTERFACE, prn=stage2_filter, filter=stage2_bpf_filter, stop_filter=stop_sniff_filter,
              offline=OFFLINE_FILE2)
    else:
        sniff(iface=INTERFACE, prn=stage2_filter, filter=stage2_bpf_filter, stop_filter=stop_sniff_filter)# offline="foo.pcap"

    stop_sniff = False


if __name__ == "__main__":

    def tunnel_receiver(interface):
        # with AF_PACKET we can bin to an ethernet interface
        # DGRAM for UDP packets
        s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        # dunno why 0x0800??? guess MSG_CONFIRM and IP from _socket.py?
        s.bind((INTERFACE, 0x0800))

        filters, filters_list_len = filter.create_filter_ip(SKYPE_IP, OWN_IP, SKYPE_PORT, NAT_PORT, IDENTIFIER)

        # create a string buffer out of the assembly filter instruction and get the address of the instruction
        b = create_string_buffer(filters)
        mem_addr_of_filters = addressof(b)
        fprog = pack('HL', filters_list_len, mem_addr_of_filters)

        # attach the filter machine code to the socket
        SO_ATTACH_FILTER = 26

        s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)

        while True:
            rcv_lock_read.acquire()
            data = s.recv(MTU)
            rcv_lock_read.release()
            if DEBUG: print("[Receiver] Received data:\n{}".format(data))
            # skip 28 bytes for ip + UDP header + the len of identifier
            # the bpf already checked for the identifier
            rcv_lock_write.acquire()
            interface.write(data[48 + len(IDENTIFIER):])
            rcv_lock_write.release()

    if OFFLINE_TEST:
        print("ATTENTION! OFFLINE TEST")

    if '--caller' in sys.argv:
        CALL_MODE = "CALLER"
    elif '--callee' in sys.argv:
        CALL_MODE = "CALLEE"
    else:
        print("[Main] Using default call mode")

    print("[Main] Call mode: {}".format(CALL_MODE))


    if AUTOMATIC_INIT:
        print("[Main] Automatic Init")
        SKYPE_IP = ""
        SKYPE_PORT = -1
        NAT_PORT = -1
        catch_parameters()




    print("Informations:\nSource IP: {}\nDestination IP: {}\nSource Port: {}\nDestination Port: {}".format(OWN_IP,
                                                                                                       SKYPE_IP,
                                                                                                       NAT_PORT,
                                                                                                       SKYPE_PORT))

    # Setting up the Tunnel
    # Create TUN device for network capture and injections
    tun = TunTapDevice(name='teletun-device')

    print("[Main] {} has been created, information follows:".format(tun.name))

    # Set IP address based on CALL_MODE
    if CALL_MODE == "CALLEE":
        tun.addr = '10.8.0.1'
        tun.dstaddr = '10.8.0.2'
    elif CALL_MODE == "CALLER":
        tun.addr = '10.8.0.2'
        tun.dstaddr = '10.8.0.1'
    else:
        raise Exception('CALL_MODE not known')

    # adjust the MTU of the device for the IP/UDP overhead
    # Ethernet header length 14 bytes, IP header has a max length of 24 Bytes and UDP header 8 bytes, 20 bytes rtp header
    # magic 4 bytes from the tunnel interface
    tun.mtu = MTU - 14 - 20 - 8 - 20 - len(IDENTIFIER) - 4

    print('\tAddress: ' + tun.addr)
    print('\tDest.-Address: ' + tun.dstaddr)
    print('\tNetmask: ' + tun.netmask)
    print('\tMTU: ' + str(tun.mtu))

    #prepare send stuff

    if SEND_SCAPY:
        templatePkt = IP()/UDP()
        templatePkt.src = OWN_IP
        templatePkt.dst = SKYPE_IP
        templatePkt.sport = NAT_PORT
        templatePkt.dport = SKYPE_PORT
    else:
        templatePkt = Ether()/IP()/UDP()
        templatePkt[Ether].src = OWN_MAC
        templatePkt[Ether].dst = ROUTER_MAC
        templatePkt[Ether].type = 0x0800
        templatePkt[IP].src = OWN_IP
        templatePkt[IP].dst = SKYPE_IP
        templatePkt.sport = NAT_PORT
        templatePkt.dport = SKYPE_PORT



    #block injected packets on the way to the NATed device
    iptables_cmd = 'sudo iptables -I FORWARD  -d {dst} -s {src} -p udp --sport {sport} -m u32 --u32' \
                   ' "28=0x90&&48=0xcafebabe" -j DROP'.format(dst=NAT_IP, src=SKYPE_IP, sport=SKYPE_PORT)
    os.system(iptables_cmd)


    def sender():

        if SEND_SCAPY:
            # see (https://byt3bl33d3r.github.io/mad-max-scapy-improving-scapys-packet-sending-performance.html)
            scapySocket = conf.L3socket(iface=INTERFACE)
        else:
            templatePktraw = templatePkt.build() + RTP_HEADER +  IDENTIFIER

            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.bind((INTERFACE, 0x0800))

        # send loop
        while True:
            send_lock.acquire()
            buf = tun.read(tun.mtu + 4)
            send_lock.release()
            if DEBUG: print("[Sender] Received data:\n{}".format(buf))
            if SEND_SCAPY:
                sendPkt = templatePkt / Raw(IDENTIFIER + buf)

                scapySocket.send(sendPkt)
            else:
                sendPkt = templatePktraw + buf

                # set ip length
                # TypeError: 'bytes' object does not support item assignment
                sendPkt = sendPkt[0:16] + len(sendPkt[14:]).to_bytes(2, byteorder='big') + sendPkt[18:]

                # calculate ip checksum
                cs = checksum.checksum(sendPkt[14:24] + b'\x00\x00' + sendPkt[26:34])

                # insert checksum
                sendPkt = sendPkt[0:24] + cs.to_bytes(2, byteorder='little') + sendPkt[26:]

                # adjust udp length - ether
                sendPkt = sendPkt[0:38] + len(sendPkt[34:]).to_bytes(2, byteorder='big') + b'\x00\x00' + sendPkt[42:]

                if DEBUG: print(sendPkt)

                s.send(sendPkt)

    print("[Main] Waiting for {} seconds until starting everything".format(SLEEP_SETUP_TIME))
    time.sleep(SLEEP_SETUP_TIME)

    receive_worker = []

    rcv_lock_read = threading.Lock()
    rcv_lock_write = threading.Lock()

    for i in range(NR_SEND_WORKER):
        receive_worker.append(threading.Thread(target=tunnel_receiver, args=(tun, )))
        receive_worker[i].setDaemon(True)
        receive_worker[i].start()

    send_lock = threading.Lock()

    send_worker = []

    for i in range(NR_SEND_WORKER):
        send_worker.append(threading.Thread(target=sender))
        send_worker[i].setDaemon(True)
        send_worker[i].start()

    # Start TUN device
    tun.up()

    # send worker will never finish so something like a wait
    send_worker[0].join()
