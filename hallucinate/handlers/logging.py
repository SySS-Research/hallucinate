import logging

from hallucinate.api import BaseHandler


def hexdump(src, perline=16):
    for i in range(0, len(src), perline):
        chars = src[i:i + perline]
        h = ' '.join(["%02x" % x for x in chars])
        text = ''.join(["%s" % ((x <= 127 and chr(x).isprintable()) and chr(x) or '.') for x in chars])
        yield "%04x  %-*s  %s" % (i, 3 * perline, h, text)


class LoggingHandler(BaseHandler):

    def __init__(self, logname, level=logging.INFO, dump=True):
        self.logger = logging.getLogger(logname)
        self.level = level
        self.dump = dump

    def send(self, data, p):
        desc = '->'
        c = p['conn']

        if isinstance(c, dict):
            desc = '[%s]:%d -> [%s]:%d' % (c['l']['ip'], c['l']['port'], c['r']['ip'], c['r']['port'])
        else:
            desc = '[%s] ->' % c

        self.log(desc, data)

    def recv(self, data, p):
        desc = '<-'
        c = p['conn']
        if isinstance(c, dict):
            desc = '[%s]:%d <- [%s]:%d' % (c['l']['ip'], c['l']['port'], c['r']['ip'], c['r']['port'])
        else:
            desc = '[%s] <-' % c

        self.log(desc, data)

    def log(self, desc, data):
        self.logger.log(self.level, "%s: %d bytes\n%s", desc, len(data), "\n".join(hexdump(data)))
