
import socket
import struct
import time
from optparse import OptionParser

DEST = '10.111.30.14'
PORT = 101
PROTO = 132


def get_src(dest):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.connect((DEST,1))
    source_ip = s.getsockname()[0]
    s.close()
    return source_ip


class SCTP(object):
    """
    Chunk Types
    0	DATA	Payload data
    1	INIT	Initiation
    2	INIT ACK	initiation acknowledgement
    3	SACK	Selective acknowledgement
    4	HEARTBEAT	Heartbeat request
    5	HEARTBEAT ACK	Heartbeat acknowledgement
    6	ABORT	Abort
    7	SHUTDOWN	Shutdown
    8	SHUTDOWN ACK	Shutdown acknowledgement
    9	ERROR	Operation error
    10	COOKIE ECHO	State cookie
    11	COOKIE ACK	Cookie acknowledgement
    12	ECNE	Explicit congestion notification echo (reserved)
    13	CWR	Congestion window reduced (reserved)
    14	SHUTDOWN COMPLETE

    Chunk Flags
    # I - SACK chunk should be sent back without delay.
    # U - If set, this indicates this data is an unordered chunk and the stream sequence number
          is invalid. If an unordered chunk is fragmented then each fragment has this flag set.
    # B - If set, this marks the beginning fragment. An unfragmented chunk has this flag set.
    # E - If set, this marks the end fragment. An unfragmented chunk has this flag set
    """
    def __init__(self, srcport, dstport, chunk=None):
        self.src = srcport
        self.dst = dstport
        self.checksum = 0
        self.chunk = chunk or ChunkHdr()

    def pack(self, src=None, dst=None):
        src = src or self.src
        dst = dst or self.dst
        verification_tag = time.time()
        packet = struct.pack('!HHii', src, dst,
                             verification_tag, 0)
        packet += self.chunk.pack()
        return packet


class ChunkHdr(object):
    def __init__(self, chunktype=0, flags=0, chunk=None):
        self.chunktype = chunktype
        self.chunkflags = 0
        self.chunkdataobj = chunk or DataChunk()
        self.chunk_data = self.chunkdataobj.pack()
        self.chunklength = 4 + self.chunkdataobj.length

    def pack(self):
        chunk = struct.pack('!bbH', self.chunktype, self.chunkflags, self.chunklength)
        packet = chunk + self.chunk_data
        return packet

class DataChunk(object):
    def __init__(self, tsn=1, stream_id=12345, stream_seq=54321, payload_proto=0,
                 payload="abcdefghijklmnopqrstuvwxyz1234567890"):
        self.payload = payload
        self.tsn = tsn
        self.stream_id = stream_id
        self.stream_seq = stream_seq
        self.payload_proto = payload_proto

    @property
    def length(self):
        return 12 + len(self.payload)

    def pack(self):
        packet = struct.pack('!iHHi', self.tsn, self.stream_id, self.stream_seq,
                             self.payload_proto)
        packet += self.payload
        return packet


if __name__=="__main__":

    parser = OptionParser()
    parser.add_option("-s", "--srcport", dest="src", type="int", default=1000,
                      help="Source SCTP Port", metavar='PORT')
    parser.add_option("-p", "--dstport", dest="dst", type="int", default=101,
                      help="Destination SCTP Port", metavar="PORT")
    parser.add_option("--proto", dest="proto", type="int", default=132,
                      help="Protocol number, default for sctp: 132", metavar="PROTOCOL")


    options, args = parser.parse_args()
    proto = args.proto
    srcport = args.src
    dstport = args.dst
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sctpobj = SCTP(srcport=srcport, dstport=dstport)
    s.send(sctpobj.pack(), (DEST, PORT))



