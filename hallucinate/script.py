import json
import logging
import os

from hallucinate.handler import ScriptHandler
from hallucinate.java import java_attach_runtime


def create_script(session, h, pid, args):
    scriptsrc = create_script_source(args)

    if args.dumpscript:
        with open(args.dumpscript, "w") as f:
            f.write(scriptsrc)

    script = session.create_script(scriptsrc)

    def java_detected(curh, p):
        if args.injectagentstartup:
            return
        java_attach_runtime(pid, curh, args)

    sh = ScriptHandler(script, h, {
        'detect-java': java_detected
    })
    script.on('message', sh.handle)
    return script


def create_script_source(args):
    scriptsrc = ''
    options = {
        'debug': False,
        'replaceBuffer': args.replaceBuffer,
        'map': {}
    }
    if args.verbose >= 2:
        options['debug'] = True

    if args.mapfile is not None:
        with open(args.mapfile, 'rb') as f:
            options['map'] = json.load(f)

    scriptsrc += 'const options = ' + json.dumps(options) + ';'
    mypath = os.path.realpath(os.path.dirname(__file__))
    with open(mypath + os.path.sep + 'utils.js', 'r') as f:
        scriptsrc += f.read()

    # Avoid scope collisions in scripts
    def wrap_module(modname, source):
        return """
    // from module %s
    (function() {
    %s
    }());
        """ % (modname, source)

    def add_dir(root, predicate):
        for name in os.listdir(root):
            p = os.path.join(root, name)
            if not os.path.isfile(p):
                continue
            if not predicate(name):
                logging.debug('Disabled module %s', name)
                continue

            logging.debug('Adding module %s', name)
            with open(p, 'r') as f:
                yield wrap_module(name, f.read())

    for source in add_dir(mypath + os.path.sep + 'modules/', lambda x: x not in args.disable):
        scriptsrc += source

    for source in add_dir(mypath + os.path.sep + 'modules/optional', lambda x: x in args.enable):
        scriptsrc += source

    return scriptsrc
