#!/usr/bin/env python3
import argparse
import logging
import sys
import time

import frida
import psutil

from hallucinate.handler import create_handler_for_args, RequestHandler
from hallucinate.java import java_stop, java_attach_startup
from hallucinate.script import create_script


def main():
    parser = argparse.ArgumentParser(prog='hallucinate',
                                     description='Instrument processes to intercept (encrypted) network communication')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    parser.add_argument('--process', '-p',
                        help='Attach to existing process (by name or PID)')
    parser.add_argument('--remote', '-r', default=False, action='store_true',
                        help='Attach to Frida on remote system (port forwarded 27042)')
    parser.add_argument('--disable', '-d', default=[], action='append',
                        help='Disable default module (gnutls.js, java.js, nss.js, openssl.js, schannel.js)')
    parser.add_argument('--enable', '-e', default=[], action='append',
                        help='Enable optional module (raw.js, ncrypt.js)')
    parser.add_argument('--dump-script', dest='dumpscript',
                        help='Dump complete frida script to file for debugging')
    parser.add_argument('--mapfile',
                        help='JSON configuration to manually override library names and function addresses')
    parser.add_argument('--force-replace-buffer', dest='replaceBuffer', default=False, action='store_true',
                        help='Replace application buffers, even if this likely breaks the application (SChannel only)')

    hgroup = parser.add_argument_group('handlers',
                                       description='Options for processing the intercepted traffic')
    hgroup.add_argument('--log', default=False, action='store_true',
                        help='Log clear-text packet data')
    hgroup.add_argument('--pcap',
                        help='Write clear-text communication to a dump file in PCAP format')
    hgroup.add_argument('--editor',
                        help='Specify a system command to edit individual packet data,' +
                             '{in} and {out} are replaced with temporary files,' +
                             'if only {in} is specified in-place editing is expected')
    hgroup.add_argument('--script',
                        help='Python script to load, functions recv/send(data,props) will be called')

    jgroup = parser.add_argument_group('java',
                                       description='Options relating to the Java agent, re(attaching) to a Java process multiple times is unreliable')
    jgroup.add_argument('--java-vm', default='java', dest='javavm',
                        help='Java binary to use when injecting the agent. This should match the target application\'s Java version')
    jgroup.add_argument('--agent-jar', dest='agentjar',
                        help='Override agent JAR file to inject (typically bundled with hallucinate)')
    jgroup.add_argument('--inject-agent-startup', default=False, action='store_true', dest='injectagentstartup',
                        help='Inject Java agent via VM argument. Not usable when attaching to a running process')
    jgroup.add_argument('--java-server-host', dest='javaagenthost', default='localhost',
                        help='Bind address for Java agent server')
    jgroup.add_argument('--java-server-port', dest='javaagentport', type=int, default=0,
                        help='Port for Java agent server (random by default)')
    jgroup.add_argument('--java-server-key', dest='javaagentkey',
                        help='Secret authentication key for Java agent server connection (random by default)')

    parser.add_argument('cmd', nargs='*', default=[],
                        help='Command to execute')
    args = parser.parse_args()

    if args.verbose >= 1:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    h = create_handler_for_args(args)

    spawned = False
    if args.remote:
        device = frida.get_remote_device()
    else:
        device = frida.get_local_device()
            
    if args.process is not None:
        pid = args.process
        if not args.process.isdigit():
            pid = device.get_process(args.process).pid
        pid = int(pid)
        session = device.attach(pid)
    elif len(args.cmd) > 0:
        cmdline = args.cmd
        if args.injectagentstartup:
            cmdline = java_attach_startup(cmdline, RequestHandler(h), args)
        logging.info("Starting %s", cmdline)
        pid = device.spawn(cmdline)
        spawned = True
        session = device.attach(pid)
    else:
        parser.print_usage(sys.stderr)
        sys.exit(-1)

    if h.empty():
        logging.warning('No handlers configured')

    script = create_script(session, h, pid, args)
    script.load()

    logging.info("Injected script, resuming execution of %d", pid)
    try:
        if spawned:
            device.resume(pid)
    except frida.InvalidArgumentError as e:
        logging.debug('Failed to resume process', exc_info=e)
        pass

    try:
        # if the process was launched by us, wait for the process to exit
        if not args.remote:
            while psutil.pid_exists(pid):
                time.sleep(0.1)
        else:
            while True:
                time.sleep(0.1)
    except OSError:
        pass
    except KeyboardInterrupt:
        pass

    logging.info("Stopping hallucinate")
    frida.shutdown()
    java_stop()
    h.close()


if __name__ == "__main__":
    main()
