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

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum += thisVal
        csum &= 0xffffffff
        count += 2
    if countTo < len(string):
        csum += string[len(string) - 1]
        csum &= 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    myID = os.getpid() & 0xFFFF  # Return the current process i
    myChecksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace
    tracelist2 = [] #This is your list to contain all traces
    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            timeLeft = TIMEOUT
            destAddr = gethostbyname(hostname)
            icmp = socket.getprotobyname("icmp")
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
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
                   tracelist1.append("* * * Request timed out.")
                   tracelist2.append(tracelist1)
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    tracelist2.append(tracelist1)
            except timeout:
                continue
            else:
                icmpHeader = recvPacket[20:28]
                request_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpheader)
                try:
                    hostaddr = gethostbyaddr(addr[0])[0]
                except herror as emsg:
                    hostaddr = "(Could not look up name:" + str(emsg) + ")"

                if type == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    stringaddr = str(addr[0])
                    stringttl = str(ttl)
                    stringms = str((timeReceived - t) * 1000)
                    tracelist2.append((stringttl, stringms, stringaddr, hostaddr))
                elif type == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    stringaddr = str(addr[0])
                    stringttl = str(ttl)
                    stringms = str((timeReceived - t) * 1000)
                    tracelist2.append((stringttl, stringms, stringaddr, hostaddr))

                elif type == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    stringaddr = str(addr[0])
                    stringttl = str(ttl)
                    stringms = str((timeReceived - t) * 1000)
                    tracelist2.append((stringttl, stringms, stringaddr, hostaddr))
                    return
                else:
                    print ("Error")
                break
            finally:
                mySocket.close()

get_route("www.bing.com")




