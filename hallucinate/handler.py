import binascii
import logging

from hallucinate.handlers.edit import EditHandler
from hallucinate.handlers.logging import LoggingHandler
from hallucinate.handlers.multi import MultiHandler
from hallucinate.handlers.pcap import PCAPHandler
from hallucinate.handlers.python import PythonHandler


class RequestHandler:

    def __init__(self, handler):
        self.handler = handler

    def process_send(self, p, rhandle):
        logging.debug('-> %s', repr(binascii.unhexlify(p['data'])))
        r = self.handler.send(binascii.unhexlify(p['data']), p)
        if r is not None:
            logging.debug('R> %s', repr(r))
            d = binascii.hexlify(r).decode('ascii')
            rhandle({
                'type': p['type'] + '-resp',
                'decision': 'replace',
                'data': d})
        else:
            rhandle({'type': p['type'] + '-resp', 'decision': 'ignore'})

    def process_recv(self, p, rhandle):
        logging.debug('<- %s', repr(binascii.unhexlify(p['data'])))
        r = self.handler.recv(binascii.unhexlify(p['data']), p)
        if r is not None:
            logging.debug('<R %s', repr(r))
            d = binascii.hexlify(r).decode('ascii')
            rhandle({'type': p['type'] + '-resp', 'decision': 'replace', 'data': d})
        else:
            rhandle({'type': p['type'] + '-resp', 'decision': 'ignore'})

    def process_shutdown(self, p, rhandle):
        logging.debug('Shutdown indicated %s', p)
        self.handler.shutdown(p)
        rhandle({'type': p['type'] + '-resp'})

    def handle_payload(self, p, rhandle):
        if p['type'] == 'pre-send':
            self.process_send(p, rhandle)
        elif p['type'] == 'post-recv':
            self.process_recv(p, rhandle)
        elif p['type'] == 'shutdown':
            self.process_shutdown(p, rhandle)
        else:
            logging.debug('%s', p)
            if 'data' in p:
                logging.debug('%s', repr(binascii.unhexlify(p['data'])))

            rhandle({'type': p['type'] + '-resp'})


class ScriptHandler(RequestHandler):
    def __init__(self, script, handler, extensions=None):
        super(ScriptHandler, self).__init__(handler)
        if extensions is None:
            extensions = {}
        self.script = script
        self.extensions = extensions

    def handle(self, m, data):
        if m['type'] == 'error':
            logging.error(m)
        elif m['type'] == 'send':
            p = m['payload']
            if p['type'] in self.extensions:
                self.extensions[p['type']](self, p)
            else:
                self.handle_payload(p, self.script.post)
        else:
            logging.error("Unknown message type %s", m['type'])


def create_handler_for_args(args):
    h = MultiHandler()

    if args.log:
        h.push(LoggingHandler('TRAFFIC'))

    if args.pcap:
        h.push(PCAPHandler(args.pcap))

    if args.editor:
        h.push(EditHandler(args.editor))

    if args.script:
        h.push(PythonHandler(args.script))

    return h
