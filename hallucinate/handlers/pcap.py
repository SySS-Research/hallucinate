import time

from hallucinate.api import BaseHandler
from hallucinate.pcap import TCPState, write_header


class PCAPHandler(BaseHandler):

    def __init__(self, fname):
        self.connections = {}
        self.fp = open(fname, 'wb')
        self.fp.write(write_header())

    def find_conn(self, p):
        c = p['conn']
        if isinstance(c, dict):
            t = (c['l']['ip'], c['l']['port'], c['r']['ip'], c['r']['port'])
            if t not in self.connections:
                self.connections[t] = TCPState((c['l']['ip'], c['l']['port']), (c['r']['ip'], c['r']['port']))
        else:
            t = c
            if t not in self.connections:
                self.connections[t] = TCPState(('127.0.0.1', len(self.connections)), ('127.0.0.1', 443))
        return self.connections[t]

    def send(self, data, p):
        self.fp.write(self.find_conn(p).write_pcap_tcp(time.time_ns(), data, send=True))
        self.fp.flush()

    def recv(self, data, p):
        self.fp.write(self.find_conn(p).write_pcap_tcp(time.time_ns(), data, send=False))
        self.fp.flush()

    def shutdown(self, p, direction=2):
        c = self.find_conn(p)
        if c is not None:
            self.fp.write(c.shutdown(time.time_ns()))
            self.fp.flush()

    def close(self):
        self.fp.close()
