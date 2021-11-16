from socket import *
import os
import sys
import struct
import time
import select
import binascii

label = '*************{0}*************'
ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2
def checksum(str):
    csum = 0
    countTo = (len(str) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(str[count + 1]) * 256 + ord(str[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
        if countTo < len(str):
            csum = csum + ord(str[len(str) - 1])
        csum = csum & 0xffffffff
        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def get_name_or_ip(hostip):
        try:
            host = socket.gethostbyaddr(hostip)
        nameorip = nameorip = '{0} ({1})'.format(hostip ,host[0])
        except Exception:
        nameorip = '{0} (host name could not be determined)'.format(hostip)
        return nameorip

    def build_packet():
        myChecksum = 0
        myID = os.getpid() & 0xFFFF
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
        data = struct.pack("d", time.time())
        myChecksum = checksum(header + data)
        if sys.platform == 'darwin':
            myChecksum = socket.htons(myChecksum) & 0xffff

        else:
            myChecksum = socket.htons(myChecksum)
            header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0,myChecksum, myID, 1)
            packet = header + data
            return packet

    def get_route(hostname):
        print label.format(hostname)
        timeLeft = TIMEOUT
        for ttl in xrange(1, MAX_HOPS):
            for tries in xrange(TRIES):
                destAddr = socket.gethostbyname(hostname)
                icmp = socket.getprotobyname("icmp")
                mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                mySocket.setsockopt(socket.IPPROTO_IP,socket.IP_TTL, struct.pack('I', ttl))
                mySocket.settimeout(TIMEOUT)
                try:
                    d = build_packet()
                    mySocket.sendto(d, (hostname, 0))
                    t = time.time()
                    startedSelect = time.time()
                    whatReady = select.select([mySocket], [], [], timeLeft)
                    howLongInSelect = (time.time() - startedSelect)
                    if whatReady[0] == []:
                        print " * * * Request timed out."
                    recvPacket, addr = mySocket.recvfrom(1024)
                    timeReceived = time.time()
                    timeLeft = timeLeft - howLongInSelect
                    if timeLeft <= 0:
                        print " * * * Request timed out."
                except socket.timeout:
                    continue
                else:
                    icmpHeaderContent = recvPacket[20:28]
                    type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeaderContent)
                    printname = get_name_or_ip(addr[0])
                    if type == 11:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        print " %d rtt=%.0f ms %s" % (ttl,(timeReceived -t)*1000, printname)
                    elif type == 3:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d",recvPacket[28:28 + bytes])[0]
                        print " %d rtt=%.0f ms %s" % (ttl,(timeReceived-t)*1000, printname)
                    elif type == 0:
                        bytes = struct.calcsize("d")
                        print " %d rtt=%.0f ms %s" % (ttl,(timeReceived - timeSent) * 1000, printname)
                        return
                    else:
                        print "error"
                    break
                finally:
                    mySocket.close()
get_route("www.google.in")
get_route("www.yahoo.com")
get_route("www.amazon.in")
get_route("www.facebook.com")




