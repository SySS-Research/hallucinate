import array
import socket
import struct
import time


def write_header():
    return struct.pack(
        ">IHHiIII",
        0xa1b23c4d,  # magic
        2, 4,  # version
        0,  # timezone (UTC)
        0,  # sigfigs
        65535,  # snaplen
        101,  # network, LINKTYPE_RAW
    )


def write_packet(ts, data, timebase=1000000000):
    tc = ts // timebase
    tf = ts % timebase
    return struct.pack(
        ">IIII",
        tc,
        tf,
        len(data),
        len(data)
    ) + data


# ultimately stolen from scapy
def chksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'
    cs = sum(array.array("H", packet))
    res = (cs >> 16) + (cs & 0xffff)
    res += res >> 16
    return struct.pack("H", (~res) & 0xffff)


def write_ip4(proto, data, src, dst, tos=0, identification=0, flags=0x2, fragment=0, ttl=64):
    pkt = struct.pack(
        ">BBHHHBBH4s4s",
        4 << 4 | 5,  # version | hdr length
        tos,  # TOS
        len(data) + 20,  # total length
        identification,  # identification
        flags << 14 | fragment,  # flags + fragment offset
        ttl,  # TTL
        proto,
        0,  # dummy checksum
        socket.inet_aton(src),  # source addr
        socket.inet_aton(dst),  # dest addr
    )

    return pkt[0:10] + chksum(pkt) + pkt[12:] + data


def write_ip6(nexthdr, data, src, dst, tc=0, flow=0, ttl=64):
    return struct.pack(
        ">IHBB",
        (6 << 28) | ((0xF0 & tc) >> 4) << 24 | (flow & 0xFFFFF),  # version(4) | tc(8) | flow(20)
        len(data),
        nexthdr,
        ttl) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + data


def write_tcp(data, src, dst, seq, ack=0, flags=0, window=64240, urgent=0):
    pkt = struct.pack(
        ">HHIIBBHHH",
        src[1],
        dst[1],
        seq,
        ack,
        5 << 4,  # data offset
        flags,
        window,
        0,  # dummy checksum
        urgent,  # urgent pointer
    )

    pseudohdr = struct.pack(
        '>4s4sBBH',
        socket.inet_aton(src[0]),
        socket.inet_aton(dst[0]),
        0,
        6,
        len(data) + len(pkt)
    )
    return pkt[0:16] + chksum(pseudohdr + pkt + data) + pkt[18:] + data


def write_tcp6(data, src, dst, seq, ack=0, flags=0, window=64240, urgent=0):
    pkt = struct.pack(
        ">HHIIBBHHH",
        src[1],
        dst[1],
        seq,
        ack,
        5 << 4,  # data offset
        flags,
        window,
        0,  # dummy checksum
        urgent,  # urgent pointer
    )
    pseudohdr = socket.inet_pton(socket.AF_INET6, src[0]) + \
                socket.inet_pton(socket.AF_INET6, dst[0]) + \
                struct.pack(
                    ">IBBBB",
                    len(data) + len(pkt),
                    0, 0, 0,
                    6
                )
    return pkt[0:16] + chksum(pseudohdr + pkt + data) + pkt[18:] + data


def write_pcap_tcp(data, ts, src, dst, flags, seq, ack=0):
    try:
        # Check whether address is V4
        socket.inet_aton(src[0])
        return write_packet(ts, write_ip4(6, write_tcp(data, src, dst, seq, ack, flags), src[0], dst[0]))
    except socket.error:
        # IPv6
        return write_packet(ts, write_ip6(6, write_tcp6(data, src, dst, seq, ack, flags), src[0], dst[0]))


CWR = 1 << 7
ECE = 1 << 6
URG = 1 << 5
ACK = 1 << 4
PSH = 1 << 3
RST = 1 << 2
SYN = 1 << 1
FIN = 1


class TCPState:

    def __init__(self, cl, s):
        self.cl = cl
        self.s = s
        self.connected = False
        self.clseq = 0
        self.clack = 0
        self.sseq = 0
        self.sack = 0

    def write_pcap_tcp(self, ts, data, send=True):

        if not self.connected:
            # not yet connected
            self.clseq = 0
            self.sseq = 0

            handshake = \
                write_pcap_tcp(b'', ts, self.cl, self.s, SYN, 0) + \
                write_pcap_tcp(b'', ts + 1, self.s, self.cl, SYN | ACK, 0, 1) + \
                write_pcap_tcp(data, ts + 2, self.cl, self.s, ACK, 1, 1)

            self.sseq = 1
            self.sack = 1
            self.clseq = 1 + len(data)
            self.clack = 1
            self.connected = True
            return handshake
        else:
            # connected
            flags = 0
            ack = 0
            if send:
                # client -> server
                if self.clack < self.sseq:
                    flags = ACK
                    ack = self.sseq
                    self.clack = ack

                p = write_pcap_tcp(data, ts, self.cl, self.s, flags, self.clseq, ack)
                self.clseq += len(data)
            else:
                # server -> client

                if self.sack < self.clseq:
                    flags = ACK
                    ack = self.clseq
                    self.sack = ack

                p = write_pcap_tcp(data, ts, self.s, self.cl, flags, self.sseq, ack)
                self.sseq += len(data)
            return p

    def shutdown(self, ts):
        if self.connected:
            self.connected = False
            p = b''
            if self.clack < self.sseq:
                ack = self.sseq
                self.clack = ack - 1
                p += write_pcap_tcp(b'', ts, self.cl, self.s, ACK, self.clseq, ack)

            p += write_pcap_tcp(b'', ts, self.cl, self.s, FIN, self.clseq)
            p += write_pcap_tcp(b'', ts + 1, self.s, self.cl, FIN | ACK, self.sseq, self.clseq + 1)
            p += write_pcap_tcp(b'', ts + 2, self.cl, self.s, ACK, self.clseq + 1, self.sseq + 1)

            self.clseq += 2
            self.sack = self.clseq
            self.sseq += 1
            self.clack = self.sseq
            return p


if __name__ == '__main__':
    s = ('127.0.0.1', 1234)
    d = ('127.0.0.1', 2345)
    st = TCPState(s, d)
    with open("/tmp/test.pcap", "wb") as f:
        f.write(write_header())
        f.write(st.write_pcap_tcp(time.time_ns(), b'fooobar'))
        f.write(st.write_pcap_tcp(time.time_ns(), b'client1'))
        f.write(st.write_pcap_tcp(time.time_ns(), b'server1', send=False))
        f.write(st.write_pcap_tcp(time.time_ns(), b'client2'))
        f.write(st.write_pcap_tcp(time.time_ns(), b'client3'))
        f.write(st.write_pcap_tcp(time.time_ns(), b'server2', send=False))
        f.write(st.write_pcap_tcp(time.time_ns(), b'server3', send=False))
        f.write(st.shutdown(time.time_ns()))

        s = ('::1', 1234)
        d = ('::1', 2346)
        st = TCPState(s, d)
        f.write(st.write_pcap_tcp(time.time_ns(), b'fooobar'))
