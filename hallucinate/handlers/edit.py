import os

from hallucinate.api import BaseHandler
import logging
import subprocess
import shlex
import tempfile


class EditHandler(BaseHandler):
    """Stores the payload in a file and runs a external program
        Command placeholders {in} and {out}, if {out} is not present
        inplace editing is assumed"""

    def __init__(self, cmdline):
        self.cmdline = cmdline
        self.inplace = '{out}' not in cmdline
        if '{in}' not in cmdline:
            logging.warning('Command line %s does not include input placeholder {in}', cmdline)

    def _run(self, cmdline):
        logging.info('Starting editor %s', cmdline)
        subprocess.run(shlex.split(cmdline, posix=0))

    def _edit(self, data):
        with tempfile.NamedTemporaryFile(delete=False) as inp:
            try:
                inp.write(data)
                inp.close()
                if not self.inplace:
                    out = tempfile.NamedTemporaryFile(delete=False)
                    logging.debug(os.fstat(out.fileno()).st_mtime)
                    try:
                        self._run(self.cmdline.replace('{in}', inp.name).replace('{out}', out.name))
                        logging.debug(os.fstat(out.fileno()).st_mtime)
                        return out.read()
                    finally:
                        out.close()
                else:
                    # need to close, otherwise exclusive write on windows
                    inp.close()
                    omod = os.path.getmtime(inp.name)
                    self._run(self.cmdline.replace('{in}', inp.name))
                    if os.path.getmtime(inp.name) != omod:
                        logging.info("File was modified, replacing data")
                        with open(inp.name, "rb") as f:
                            return f.read()
            finally:
                os.remove(inp.name)

    def send(self, data, p):
        return self._edit(data)

    def recv(self, data, p):
        return self._edit(data)
