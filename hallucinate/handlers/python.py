import importlib.machinery
import importlib.util
import logging
import os.path
import sys

from hallucinate.api import BaseHandler


class PythonHandler(BaseHandler):

    def __init__(self, script):
        self.module = self._load(script)
        self.r = self.module.recv
        self.s = self.module.send

    # shamelessly stolen from mitmproxy:
    # Copyright (c) 2013, Aldo Cortesi. All rights reserved.
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy
    # of this software and associated documentation files (the "Software"), to deal
    # in the Software without restriction, including without limitation the rights
    # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    # copies of the Software, and to permit persons to whom the Software is
    # furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in
    # all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    # SOFTWARE.

    def _load(self, path):
        fullname = "__hallucinate_script__.{}".format(
            os.path.splitext(os.path.basename(path))[0]
        )
        sys.modules.pop(fullname, None)
        oldpath = sys.path
        sys.path.insert(0, os.path.dirname(path))
        m = None
        try:
            loader = importlib.machinery.SourceFileLoader(fullname, path)
            spec = importlib.util.spec_from_loader(fullname, loader=loader)
            m = importlib.util.module_from_spec(spec)
            loader.exec_module(m)
            if not getattr(m, "name", None):
                m.name = path
            return m
        except Exception as exc:
            exception = type(exc).__name__
            lineno = ""
            if hasattr(exc, "lineno"):
                lineno = str(exc.lineno)
            logging.error("Error in script %s:%s %s", path, lineno, exception)
            raise
        finally:
            sys.path[:] = oldpath

    def send(self, data, p):
        return self.s(data, p)

    def recv(self, data, p):
        return self.r(data, p)
