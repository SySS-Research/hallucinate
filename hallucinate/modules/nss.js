const MODULE = 'nss';
const LIBNAME = mapped(MODULE,'@lib');


var PR_GetNameForIdentity;
var getnameforid = mapped(MODULE,'PR_GetNameForIdentity') || Module.findExportByName(LIBNAME, 'PR_GetNameForIdentity')
if ( !getnameforid ) {
    PR_GetNameForIdentity = function() {
        return -1;
    }
} else {
    PR_GetNameForIdentity = new NativeFunction(getnameforid, "pointer", ["pointer"]);
}

function NSS_FindIdentityForName(fd,name) {
    var pLower = fd.add(2*Process.pointerSize).readPointer();
    var pHigher = fd.add(3*Process.pointerSize).readPointer();
    var identity = fd.add(5*Process.pointerSize).readPointer();

    if ( !identity.isNull() ) {
      var nameptr = PR_GetNameForIdentity(identity).readCString();
      if ( nameptr == name ) {
        return fd;
      }
    }

    if ( !pLower.isNull() ) {
        return NSS_FindIdentityForName(pLower, name);
    }

    if ( !pHigher.isNull() ) {
        console.log('Have upper')
    }
}

/*

NSPR_API(PRStatus)  PR_GetSockName(PRFileDesc *fd, PRNetAddr *addr);
NSPR_API(PRStatus)  PR_GetPeerName(PRFileDesc *fd, PRNetAddr *addr);
*/



var PR_GetSockName;
var getsockname = mapped(MODULE,'PR_GetSockName') || Module.findExportByName(LIBNAME, 'PR_GetSockName')
if ( !getsockname ) {
    PR_GetSockName = function() {
        return -1;
    }
} else {
    PR_GetSockName = new NativeFunction(getsockname, "pointer", ["pointer", "pointer"]);
}



var PR_GetPeerName;
var getpeername = mapped(MODULE,'PR_GetPeerName') || Module.findExportByName(LIBNAME, 'PR_GetPeerName')
if ( !getpeername ) {
    PR_GetPeerName = function() {
        return -1;
    }
} else {
    PR_GetPeerName = new NativeFunction(getpeername, "pointer", ["pointer", "pointer"]);
}


var PR_NetAddrToString;
var netaddrtostr = mapped(MODULE,'PR_NetAddrToString') || Module.findExportByName(LIBNAME, 'PR_NetAddrToString')
if ( !netaddrtostr ) {
    PR_NetAddrToString = function() {
        return -1;
    }
} else {
    PR_NetAddrToString = new NativeFunction(netaddrtostr, "pointer", ["pointer", "pointer", "uint32"]);
}

function get_peer_name(fd) {
    var addrptr = Memory.alloc(Process.pointerSize);
    var status = PR_GetPeerName(fd, addrptr);
    if ( ! status.isNull()  || addrptr.isNull() ) { // PR_SUCCESS = 0
        return;
    }
    return addrptr;
}

function get_local_name(fd) {
    var addrptr = Memory.alloc(Process.pointerSize);
    var status = PR_GetSockName(fd, addrptr);
    if ( ! status.isNull()  || addrptr.isNull() ) { // PR_SUCCESS = 0
        return;
    }
    return addrptr;
}

function get_type(addr) {
    var family = addr.readUShort()
    if ( family == 2 ) {
        return 'tcp';
    } else if( family == 100) {
        return 'tcp6';
    }
}

function get_conn(fd) {
    var local = get_local_name(fd);
    var remote = get_peer_name(fd);
    if ( local && remote ) {
        return {t: get_type(local), l: parse_address(local), r: parse_address(remote)};
    } else {
        return String(fd)
    }
}

function parse_address(addr) {
    var family = addr.readUShort()
    var type;
    if ( family == 2 ) {
        type = 'tcp';
    } else if( family == 100) {
        type = 'tcp6';
    } else {
        return;
    }
    var port = addr.add(2).readUShort();
    port = (port >> 8) | ((port & 0xFF) << 8);
    var strbuf = Memory.alloc(1024);
    if (PR_NetAddrToString(addr, strbuf, 1024).isNull()) {
        return {ip:  strbuf.readCString(), port: port};
    }
}


/*
NSPR_API(PRInt32) PR_Write(PRFileDesc *fd,const void *buf,PRInt32 amount);
NSPR_API(PRInt32)    PR_Send(PRFileDesc *fd, const void *buf, PRInt32 amount,
                                PRIntn flags, PRIntervalTime timeout);

NSPR_API(PRInt32) PR_Writev(
    PRFileDesc *fd, const PRIOVec *iov, PRInt32 iov_size,
    PRIntervalTime timeout);

*/


function writeHandler(func) {
    return {
         onEnter: function(args) {
            this.layer = NSS_FindIdentityForName(args[0], 'SSL');
            if ( !this.layer) {
                return;
            }
            this.conn = get_conn(args[0]);
            this.buf = args[1];
            this.bufsize = args[2];
            var b = Memory.readByteArray(this.buf, this.bufsize.toInt32());
            var rv = sendrecv('pre-send', {
                module: MODULE,
                function: func,
                bufsize: this.bufsize,
                data: encode(b),
                conn: this.conn,
            });
            // replace buffer contents if so desired
            if ( rv['decision'] === 'replace') {
                options.debug && console.log('Replacing send data')
                var data = decode(rv['data'])
                if (data.byteLength > args[2].toInt32()) {
                    throw new RangeError('Returned data exceeds buffer size');
                }
                args[2] = new NativePointer(data.byteLength)
                args[1].writeByteArray(data)
            }
         },
         onLeave: function(retval) {
            if ( !this.layer ) {
                return;
            }
            var rl = retval;

            // is this useful in any way?
            var rv = sendrecv('post-send', {
                module: MODULE,
                function: func,
                length: rl,
                bufsize: this.bufsize,
                conn: this.conn
            });
         }
    }
}


var write = mapped(MODULE, 'PR_Write') || Module.findExportByName(LIBNAME, 'PR_Write')
if ( !write ) {
    options.debug && console.log('PR_Write not found ,no NSS?')
} else {
    Interceptor.attach(write, writeHandler('PR_Write'))
}

var nsend = mapped(MODULE, 'PR_Send') || Module.findExportByName(LIBNAME, 'PR_Send')
if ( !nsend ) {
    options.debug && console.log('PR_Write not found ,no NSS?')
} else {
    Interceptor.attach(nsend, writeHandler('PR_Send'))
}




/*
NSPR_API(PRInt32) PR_Read(PRFileDesc *fd, void *buf, PRInt32 amount);
NSPR_API(PRInt32)    PR_Recv(PRFileDesc *fd, void *buf, PRInt32 amount,
                PRIntn flags, PRIntervalTime timeout);


*/

function readHandler(func) {
    return {
         onEnter: function(args) {
            this.layer = NSS_FindIdentityForName(args[0], 'SSL');
            if ( !this.layer) {
                return;
            }
            this.conn = get_conn(args[0]);
            this.buf = args[1];
            this.bufsize = args[2];
            var rv = sendrecv('pre-recv', {
                module: MODULE,
                function: func,
                bufsize: this.bufsize,
                conn: this.conn
            });
         },
         onLeave: function(retval) {
             if ( !this.layer ) {
                return;
             }
             var rl = retval
             try {
                if ( rl.toInt32() <= 0 ) {
                    options.debug && console.log("Error " + rl)
                    return;
                }
             } catch (e) {
                // error status
                options.debug && console.log("Error " + rl)
                return;
             }
             var b = Memory.readByteArray(this.buf, rl.toInt32());
             var rv = sendrecv('post-recv', {
                module: MODULE,
                function: func,
                length: retval,
                bufsize: this.bufsize,
                data: encode(b),
                conn: this.conn
             });
             if ( rv['decision'] === 'replace') {
                var data = decode(rv['data'])
                if ( data.byteLength > this.bufsize ) {
                    throw new RangeError('Returned data exceeds buffer size');
                } else {
                    options.debug && console.log('Replacing received data')
                    Memory.writeByteArray(this.buf, data)
                    rl.replace(data.byteLength)
                }
             }
         }
    }
}


var read = mapped(MODULE, 'PR_Read') || Module.findExportByName(LIBNAME, 'PR_Read')
if ( !read ) {
    options.debug && console.log('PR_Read not found ,no NSS?')
} else {
    Interceptor.attach(read, readHandler('PR_Read'))
}

var recv = mapped(MODULE, 'PR_Recv') || Module.findExportByName(LIBNAME, 'PR_Recv')
if ( !recv ) {
    options.debug && console.log('PR_Recv not found ,no NSS?')
} else {
    Interceptor.attach(recv, readHandler('PR_Recv'))
}


/*
NSPR_API(PRStatus)    PR_Close(PRFileDesc *fd);

typedef enum PRShutdownHow
{
    PR_SHUTDOWN_RCV = 0,
    PR_SHUTDOWN_SEND = 1,
    PR_SHUTDOWN_BOTH = 2
} PRShutdownHow;

NSPR_API(PRStatus)    PR_Shutdown(PRFileDesc *fd, PRShutdownHow how);
*/

function shutdownHandler(func) {
    return {
      onEnter: function(args) {
            this.layer = NSS_FindIdentityForName(args[0], 'SSL');
            if (!this.layer) {
                return;
            }
            this.conn = get_conn(args[0]);
            var dir = 2; // SHUT_RDWR
            if ( func === 'PR_Shutdown') {
                dir = args[1].toInt32();
            }
            send({
                type: 'shutdown',
                module: MODULE,
                function: func,
                conn: this.conn,
                direction: dir
            })
      }
    }
}

var shutdown = mapped(MODULE, 'PR_Shutdown') || Module.findExportByName(LIBNAME, 'PR_Shutdown')
if ( !shutdown ) {
    options.debug && console.log('PR_Shutdown not found, no NSS?')
} else {
    Interceptor.attach(shutdown, shutdownHandler('PR_Shutdown'))
}

var close = mapped(MODULE, 'PR_Close') || Module.findExportByName(LIBNAME, 'PR_Close')
if ( !close ) {
    options.debug && console.log('PR_Close not found, no NSS?')
} else {
    Interceptor.attach(close, shutdownHandler('PR_Close'))
}
