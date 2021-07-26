from hallucinate.api import BaseHandler


class MultiHandler(BaseHandler):

    def __init__(self, handlers=None):
        if handlers is None:
            handlers = []
        self.handlers = handlers

    def empty(self):
        return len(self.handlers) == 0

    def push(self, handler):
        self.handlers.append(handler)

    def send(self, data, p):
        modified = False
        r = data

        for handler in self.handlers:
            hr = handler.send(r, p)
            if hr is not None:
                modified = True
                r = hr

        if modified:
            return r

    def recv(self, data, p):
        modified = False
        r = data

        for handler in self.handlers:
            hr = handler.recv(r, p)
            if hr is not None:
                modified = True
                r = hr

        if modified:
            return r

    def shutdown(self, p, d=2):
        for handler in self.handlers:
            handler.shutdown(p, d)

    def close(self):
        for handler in self.handlers:
            handler.close()
