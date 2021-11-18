from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

def checksum(str):
    csum = 0
    countTo = (len(str) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = str[count+1] * 256 + str[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(str):
        csum = csum + str[len(str) - 1]
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
def build_packet():
    ID = os.getpid() & 0xFFFF  # Return the current process i
    myChecksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    print("Begin traceroute to " + hostname + "(" + gethostbyname(hostname) + ")......\n")
    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            timeLeft = TIMEOUT
            destAddr = gethostbyname(hostname)
            icmp = getprotobyname("icmp")
            try:
                mySocket = socket(AF_INET, SOCK_RAW, icmp)
            except error as msg:
                print("Socket create error:", msg)
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                   print("\t*\t\t*\t\t*\t\tRequest timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("\t*\t*\t*\Request timed out.")
            except timeout:
                continue
            else:
                ttl = recvPacket[8]
                type, pongCode, pongChecksum, pongID, pongSequence = struct.unpack("bbHHh", recvPacket[20:28])
                RTT = (timeReceived - struct.unpack("d", recvPacket[28:36])[0]) * 1000
                try:
                    routerHostname = gethostbyaddr(addr[0])[0]
                except herror as emsg:
                    routerHostname = "(Could not look up name:" + str(emsg) + ")"

                if type == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print("TTL = %d\trtt=%.0f ms\tIP = %s\tHost:%s" % (ttl, (timeReceived - t) * 1000, addr[0], routerHostname))
                elif type == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print("TTL = %d\trtt=%.0f ms\tIP = %s\tHost:%s" % (ttl, (timeReceived - t) * 1000, addr[0], routerHostname))
                elif type == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print("TTL = %d\trtt=%.0f ms\tIP = %s\tHost:%s" % (ttl, (timeReceived - timeSent) * 1000, addr[0], routerHostname))
                    return
                else:
                    print ("Error")
                break
            finally:
                mySocket.close()
get_route("www.google.com")
print("Traceroute Finished!\n\n\n\n\n\n")




