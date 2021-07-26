import logging
import os.path
import socketserver
import struct
import subprocess
import sys
import threading
from hmac import compare_digest
from secrets import token_urlsafe

import frida

from hallucinate.handler import RequestHandler
from hallucinate.handlers.logging import LoggingHandler


class JavaAgentHandler(socketserver.BaseRequestHandler):

    def read_bytes(self, n):
        r = b''
        while len(r) < n:
            r += self.request.recv(n - len(r))
        return r

    def read_string(self):
        length, = struct.unpack(">H", self.read_bytes(2))
        return self.request.recv(length).decode('utf-8')

    def read_entry(self):
        return self.read_string(), self.read_string()

    def handle(self):
        key = self.read_string()

        if not compare_digest(key, self.server.key):
            logging.warning("Client provided wrong key")
            self.request.close()
            return

        while True:
            r = self.read_bytes(4)
            nentries, = struct.unpack('>I', r)
            rdata = dict()
            for i in range(nentries):
                k, v = self.read_entry()
                rdata[k] = v

            #  emulate conn entry, no nested array support
            rdata['conn'] = {
                'l': {'ip': rdata['localAddr'], 'port': int(rdata['localPort'])},
                'r': {'ip': rdata['remoteAddr'], 'port': int(rdata['remotePort'])}
            }
            logging.debug('Received request from Java agent: %s', rdata)

            def rhandle(data):
                logging.debug('Sending response to Java agent: %s', data)
                p = struct.pack('>I', len(data))
                for k, v in data.items():
                    ke = str(k).encode('utf-8')
                    ve = str(v).encode('utf-8')
                    p += struct.pack('>H', len(ke)) + ke
                    p += struct.pack('>H', len(ve)) + ve
                self.request.sendall(p)

            self.server.handler(rdata, rhandle)


class JavaAgentServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    block_on_close = False

    def __init__(self, host, port, handler, key):
        super(JavaAgentServer, self).__init__((host, port), JavaAgentHandler)
        self.handler = handler
        self.key = key


def test_handler(r, rhandle):
    rhandle({'decision': 'ignore'})


def start_server(handler, host='localhost', port=0, key=None):
    if key is None:
        key = token_urlsafe(32)
    server = JavaAgentServer(host, port, lambda d, r: handler.handle_payload(d, r), key)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    if port == 0:
        port = server.socket.getsockname()[1]
    return server, key, host, port


def stop_server(s):
    s.server_close()


def java_attach(pid, agentcfg, java='java', agentjar=None):
    if agentjar is None:
        agentjar = os.path.dirname(os.path.realpath(__file__)) + os.sep + 'hallucinate-java-all.jar'
    subprocess.run([
        java, '-cp',
        agentjar,
        'gs.sy.m8.hallucinate.Launcher', str(pid), agentcfg
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


_javaserver = None
_agentcfg = None


def java_attach_runtime(pid, h, args):
    global _javaserver, _agentcfg
    if _javaserver is not None:
        logging.warning("Java server can only be initialized once")
        return
    logging.info('Java process detected, starting server')
    s, key, host, port = start_server(h, host=args.javaagenthost, port=args.javaagentport, key=args.javaagentkey)
    debug = ''
    if args.verbose > 1:
        debug = 'debug;'
    _agentcfg = '%sserverport=%d;serveraddr=%s;serverkey=%s' % (debug, port, host, key)
    # need to resume, otherwise attach fails
    try:
        frida.resume(pid)
    except frida.InvalidArgumentError as e:
        logging.debug('Failed to resume process', exc_info=e)
        pass
    _javaserver = s
    logging.info('Attaching to target process %d with args %s', pid, _agentcfg)
    java_attach(pid, _agentcfg,
                java=args.javavm,
                agentjar=args.agentjar)


def java_attach_startup(cmdline, h, args):
    global _javaserver, _agentcfg
    if _javaserver is not None:
        logging.warning("Java server can only be initialized once")
        return

    logging.info('Injecting agent during Java launch, starting server')
    s, key, host, port = start_server(h, host=args.javaagenthost, port=args.javaagentport, key=args.javaagentkey)
    debug = ''
    if args.verbose > 1:
        debug = 'debug;'
    _agentcfg = '%sserverport=%d;serveraddr=%s;serverkey=%s' % (debug, port, host, key)

    agentjar = args.agentjar
    if agentjar is None:
        agentjar = os.path.dirname(os.path.realpath(__file__)) + os.sep + 'hallucinate-java-all.jar'

    return [cmdline[0], '-javaagent:' + agentjar + '=' + _agentcfg] + cmdline[1:]


def java_stop():
    global _javaserver
    if _javaserver is not None:
        stop_server(_javaserver)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    s, key, host, port = start_server(RequestHandler(LoggingHandler('JAVA')))
    agentcfg = 'debug;serverport=%d;serveraddr=%s;serverkey=%s' % (port, host, key)
    pid = int(sys.argv[1])
    java_attach(pid, agentcfg)
    sys.stdin.read()
    stop_server(s)
