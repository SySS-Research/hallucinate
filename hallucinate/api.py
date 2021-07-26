class BaseHandler:

    def send(self, data, p):
        pass

    def recv(self, data, p):
        pass

    def shutdown(self, p, direction=2):
        pass

    def close(self):
        pass
