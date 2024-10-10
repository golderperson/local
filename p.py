import optparse, socket, time, binascii,ipaddress,io,ctypes

BUF_SIZE = 1600		# > 1500

ETH_P_ALL = 3		# To receive all Ethernet protocols

Interface = "eth0"
#Interface = "eth1"
IPv4 = 0x0800
IPv6 = 0x86dd
ARP  = 0x806
TCP=6
host = socket.gethostbyname(socket.gethostname())

class TcpHeadr(ctypes.BigEndianStructure):
#class TcpHeadr(ctypes.Structure):
    _fields_ = (
        ("s_port", ctypes.c_uint16),
        ("d_port", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("ack", ctypes.c_uint32),
        ("drc", ctypes.c_uint16),
        ("win", ctypes.c_uint16),
        ("chck", ctypes.c_uint16),
        ("ptr", ctypes.c_uint16),
        ("data", ctypes.c_uint8*1472)
    )

class EtherNetFrame(ctypes.BigEndianStructure):
    _fields_ = (
        #("preamble", ctypes.c_ubyte*7),
        #("sfd", ctypes.c_ubyte),
        ("d_host", ctypes.c_uint8*6),
        ("s_host", ctypes.c_uint8*6),
        ("type", ctypes.c_uint16),
        ("payload", ctypes.c_uint8*1500)
    )

class Ipv4Headr(ctypes.BigEndianStructure):
    _fields_ = (
        ("vit", ctypes.c_uint16),
        ("lenth", ctypes.c_uint16),
        ("id", ctypes.c_uint16),
        ("flag", ctypes.c_uint16),
        ("ttlp", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
        ("chksm", ctypes.c_uint16),
        ("s_ip", ctypes.c_uint32),
        ("d_ip", ctypes.c_uint32),
        ("data", ctypes.c_uint8*1480)
    )

### Packet field access ###

def SMAC(packet):
   return binascii.hexlify(packet[6:12]).decode()

def DMAC(packet):
   return binascii.hexlify(packet[0:6]).decode()

def EtherType(packet):
   return binascii.hexlify(packet[12:14]).decode()

def Payload(packet):
    return packet[14:].decode('utf-8', errors='ignore')
    #return binascii.hexlify(packet[14:]).decode()

### Packet handler ###

def printPacket(packet, now, type,protocol,message,srcip,distip,s_port,d_port):
   # print(message, len(packet), "bytes  time:", now,
   #       "\n  SMAC:", SMAC(packet), " DMAC:", DMAC(packet),
   #       " Type:", EtherType(packet), "\n  Payload:", Payload(packet)) # !! Python 3 !!
   print(message,type,protocol,len(packet), "bytes time:", now, "srcip:",srcip,"port:",s_port,"distip:",distip,"port:",d_port,\
       "\n  SMAC:", SMAC(packet), " DMAC:", DMAC(packet), " Type:", \
       EtherType(packet), "\n  Payload:", Payload(packet)) # !! Python 2 !!


def terminal():
   # Parse command line
   parser = optparse.OptionParser()
   parser.add_option("--p", "--port", dest = "port", type="int",
                     help = "Local network port id")
   parser.add_option("--lm", "--lmac", "--localMAC", dest = "lmac", type="str",
                     help = "Local MAC address")
   parser.add_option("--rm", "--rmac", "--remoteMAC", dest = "rmac", type="str",
                     help = "Remote MAC address")
   parser.add_option("--receiveOnly", "--receiveonly",
                     dest = "receiveOnly", action = "store_true")
   # parser.add_option("--promiscuous", dest = "promiscuous", action = "store_true")
   parser.set_defaults(lmac = "ffffffffffff", rmac = "ffffffffffff")
   opts, args = parser.parse_args()

   # Open socket
   sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
   sock.bind((Interface, ETH_P_ALL))
   sock.setblocking(0)
   # Contents of packet to send (constant)
   sendPacket = binascii.unhexlify(opts.rmac) + binascii.unhexlify(opts.lmac) + \
       b'\x88\xb5' + b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

   # Repeat sending and receiving packets
   interval = 1
   lastTime = time.time()
   while True:
      now = time.time()

      try:
         packet = sock.recv(BUF_SIZE)
         etf = EtherNetFrame()
         buffer = io.BytesIO(packet)
         buffer.readinto(etf)
         type = etf.type
         payload=etf.payload
      except socket.error:
         pass
      else:
         if type == IPv4:
            buffer=io.BytesIO(payload)
            ipv4=Ipv4Headr()
            buffer.readinto(ipv4)
            # 送信元IPアドレスを取得する。
            src_ip = ipaddress.IPv4Address(ipv4.s_ip)
            # 送信先IPアドレスを取得する。
            dist_ip = ipaddress.IPv4Address(ipv4.d_ip)
            # ipヘッダからプロトコルタイプを取得する
            if ipv4.type == TCP:
                buffer = io.BytesIO(ipv4.data)
                tcpdata= TcpHeadr()
                buffer.readinto(tcpdata)             
                printPacket(packet, now,"IPv4", "TCP","Received:",src_ip,dist_ip,tcpdata.s_port,tcpdata.d_port)

            dmac = DMAC(packet)
            
      if not opts.receiveOnly:
         if now > lastTime + interval:
            sendBytes = sock.send(sendPacket)
           # printPacket(sendPacket, now, "Sent:   ")
            lastTime = now
         else:
            time.sleep(0.001001)
      else:
         time.sleep(0.001001)

terminal()