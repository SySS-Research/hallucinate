hallucinate
===============================================
Author: Moritz Bechler <moritz.bechler@syss.de>  
Project Repository: https://github.com/SySS-Research/hallucinate  
License: MIT

Originally inspired by Echo Mirage
Intercept clear-text TLS network traffic by instrumenting the target process.
Binary instrumentation based on Frida, Java integration on a custom agent.

Intercepted traffic can be:
- logged, also in PCAP format for convenient protocol analysis
- edited interactively or programmatically using external tools
- analyzed/modified using python scripts


Supported Libraries/APIs:
- Native network IO (POSIX/BSD/Winsock) - disabled by default
- OpenSSL
- GnuTLS
- SChannel 
- low-level Windows NCrypt APIs (SslEncryptPacket/SslDecryptPacket) - disabled by default
- Java JSSE
- NSS


Ideas for future integration:
- Java +BouncyCastle, RSA
- BoringSSL
- Mobile Platforms: Android, iOS

BUILD/INSTALL
----

Using setuptools

```
#> python setup.py install
```

Java/Maven is required to build the Java Agent JAR file required to attach to Java Applications. 
It is recommended to choose the oldest targeted Java version SDK. 
The Java Agent may also be version dependent and should be built with a JDK version similar to the 
targeted applications JVM.

USAGE
----

```
usage: hallucinate [-h] [--verbose] [--process PROCESS] [--disable DISABLE]
                   [--enable ENABLE] [--dump-script DUMPSCRIPT]
                   [--mapfile MAPFILE] [--force-replace-buffer] [--log]
                   [--pcap PCAP] [--editor EDITOR] [--script SCRIPT]
                   [--java-vm JAVAVM] [--agent-jar AGENTJAR]
                   [--inject-agent-startup] [--java-server-host JAVAAGENTHOST]
                   [--java-server-port JAVAAGENTPORT]
                   [--java-server-key JAVAAGENTKEY]
                   [cmd [cmd ...]]

Instrument processes to intercept (encrypted) network communication

positional arguments:
  cmd                   Command to execute

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v
  --process PROCESS, -p PROCESS
                        Attach to existing process (by name or PID)
  --disable DISABLE, -d DISABLE
                        Disable default module (gnutls.js, java.js, nss.js,
                        openssl.js, schannel.js)
  --enable ENABLE, -e ENABLE
                        Enable optional module (raw.js, ncrypt.js)
  --dump-script DUMPSCRIPT
                        Dump complete frida script to file for debugging
  --mapfile MAPFILE     JSON configuration to manually override library names
                        and function addresses
  --force-replace-buffer
                        Replace application buffers, even if this likely
                        breaks the application (SChannel only)

handlers:
  Options for processing the intercepted traffic

  --log                 Log clear-text packet data
  --pcap PCAP           Write clear-text communication to a dump file in PCAP
                        format
  --editor EDITOR       Specify a system command to edit individual packet
                        data,{in} and {out} are replaced with temporary
                        files,if only {in} is specified in-place editing is
                        expected
  --script SCRIPT       Python script to load, functions recv/send(data,props)
                        will be called

java:
  Options relating to the Java agent, re(attaching) to a Java process
  multiple times is unreliable

  --java-vm JAVAVM      Java binary to use when injecting the agent. This
                        should match the target application's Java version
  --agent-jar AGENTJAR  Override agent JAR file to inject (typically bundled
                        with hallucinate)
  --inject-agent-startup
                        Inject Java agent via VM argument. Not usable when
                        attaching to a running process
  --java-server-host JAVAAGENTHOST
                        Bind address for Java agent server
  --java-server-port JAVAAGENTPORT
                        Port for Java agent server (random by default)
  --java-server-key JAVAAGENTKEY
                        Secret authentication key for Java agent server
                        connection (random by default)
```


Usage Examples
----

Launch the target process through the script

```
#> hallucinate  --log -- /usr/bin/curl -k https://localhost
```

Different options for logging, interactive or automated modification of the intercepted traffic
are available, see the application help.

For example the clear-text HTTP request/response of a CURL call could be modified in an editor of your choice:

```
#> hallucinate --disable raw.js  --editor '/usr/bin/gedit {in}' -- /usr/bin/curl -k https://localhost
```

Or, attach to a running process by specify it's PID, or, if unique, process name

```
#> hallucinate --log -p <pid|procname>
```

Java Usage
----

Java processes are automatically detected by hallucinate when attaching.
However, as an agent is injected into these processes and no reloading is supported, 
(re-)attaching multiple times to the same process is unreliable (there may be room for future improvement).
Also, make sure to specify a Java runtime version compatible with the target application as `--java-vm`.

An alternative is to inject the agent during VM startup by specifying the full Java command line for the 
target program, e.g. `java -cp myjar.jar my.Application` as the command to run and the 
`--inject-agent-startup` option. This automatically adds the necessary agent parameters to the VM invocation.

Scripting
----

hallucinate allows python scripting to process/analyze/modify the intercepted traffic.
A python script can be specified using the --script parameter. From this file the functions
`send` and `recv` will be called on each intercepted send/recv. If these functions return data
the sent/received data is be replaced, otherwise it passes as-is.

Example: test.py
```
def send(data,p):
    if b'HTTP/1.1' in data:
        print("Replacing HTTP version")
        return data.replace(b'HTTP/1.1', b'HTTP/1.0')
    print("Not touching: " + repr(data))

def recv(data,p):
    print("Not touching: " + repr(data))
```

```
#> hallucinate -d raw.js --script test.py -- /usr/bin/curl -s -o /dev/null -k https://localhost
INFO:root:Starting ['/usr/bin/curl', '-s', '-o', '/dev/null', '-k', 'https://localhost']
INFO:root:Injected script, resuming execution of 22096
Replacing HTTP version
Not touching: b'HTTP/1.1 200 OK
```

Mapfile
----

A mapfile can be used to manually override the hooked target module and function addresses,
e.g. statically linked library copies. It is a JSON formatted nested dictionary, lookup is
based on the module name on the first nesting level, function name on the second.
The special name `@lib` can be used to specify/override the target module name.

Example: test.json
```
{
        "openssl":{
                "@lib" : "test.so",
                "SSL_read_ex" : "0x24235235"
        }
}
```


KNOWN LIMITATIONS
----
- Receive calls generally must use the application allocated buffers, therefore modified data cannot
    exceed the length of the buffers provided by the application.
- The same is true for SChannel send calls, therefore the length is limited in this case as well. The option
    --force-replace-buffer to replace the buffers nevertheless is provided, but must be expected to break most
    applications.
- Statically linked (without symbols)/inlined library instances won't be detected, hooking may be possible using
    manually identified function addresses and a mapfile.
- No connection/address information is available for SChannel
- Hooking of calls in runtime loaded libraries may not be working properly (room for future improvement?)
- Hooking may not cover all relevant APIs of the respective libraries (let me know)
- Attaching to processes may be limited on Linux, either launch the target process as a child
    or set `sys.kernel.yama.ptrace_scope=0`
