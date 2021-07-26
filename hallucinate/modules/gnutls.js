const MODULE = 'gnutls';
const LIBNAME = mapped(MODULE,'@lib');

var gnutls_transport_get_int;
var transgetint = mapped(MODULE,'gnutls_transport_get_int') || Module.findExportByName(LIBNAME, 'gnutls_transport_get_int')
if ( !transgetint ) {
    gnutls_transport_get_int = function() {
        return -1;
    }
} else {
    gnutls_transport_get_int = new NativeFunction(transgetint, "int", ["pointer"]);
}

var record_send = mapped(MODULE,'gnutls_record_send') || Module.findExportByName(LIBNAME, 'gnutls_record_send');
if ( record_send ) {
    options.debug && console.log('Hooking gnutls_record_send')
    Interceptor.attach(record_send, {
        onEnter: function(args) {
            this.fd = gnutls_transport_get_int(args[0])
            this.buf = args[1];
            this.bufsize = args[2];
            var b = Memory.readByteArray(this.buf, this.bufsize.toInt32());
            var rv = sendrecv('pre-send', {
                module: MODULE,
                function: 'gnutls_record_send',
                fd: this.fd,
                bufsize: this.bufsize,
                data: encode(b),
                conn: connFromFD(this.fd)
            });
            // replace buffer contents if so desired
            if ( rv['decision'] === 'replace') {
                options.debug && console.log('Replacing send data')
                var data = decode(rv['data'])
                this.replaceBuf = Memory.alloc(data.byteLength)
                this.replaceBuf.writeByteArray(data)
                args[1] = this.replaceBuf
                args[2] = new NativePointer(data.byteLength)
             }
         },
         onLeave: function(retval) {
            var rl = retval;
            // is this useful in any way?
            var rv = sendrecv('post-send', {
                module: MODULE,
                fd: this.fd,
                function: 'gnutls_record_send',
                length: rl,
                bufsize: this.bufsize,
                conn: connFromFD(this.fd)
            });
         }
    })
}
else {
    options.debug && console.log('No GnuTLS detected');
}

var record_recv = mapped(MODULE,'gnutls_record_recv') || Module.findExportByName(LIBNAME, 'gnutls_record_recv');
if ( record_recv ) {
    options.debug && console.log('Hooking gnutls_record_recv')
    Interceptor.attach(record_recv, {
        onEnter: function(args) {
            this.fd = gnutls_transport_get_int(args[0])
            this.buf = args[1];
            this.bufsize = args[2];
            var rv = sendrecv('pre-recv', {
                module: MODULE,
                function: 'gnutls_record_recv',
                fd: this.fd,
                bufsize: this.bufsize,
                conn: connFromFD(this.fd)
            });
         },
         onLeave: function(retval) {
             var rl = retval;
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
                function: 'gnutls_record_recv',
                fd: this.fd,
                length: retval,
                bufsize: this.bufsize,
                data: encode(b),
                conn: connFromFD(this.fd)
             });
             if ( rv['decision'] === 'replace') {
                var data = decode(rv['data'])
                if ( data.byteLength > this.bufsize ) {
                    throw new RangeError('Returned data exceeds buffer size');
                } else {
                    options.debug && console.log('Replacing received data')
                    Memory.writeByteArray(this.buf, data)
                    retval.replace(data.byteLength)
                }
             }
         }
    })
}
else {
    options.debug && console.log('No GnuTLS detected');
}

var bye = mapped(MODULE,'gnutls_bye') || Module.findExportByName(LIBNAME, 'gnutls_bye');
if ( bye ) {
    options.debug && console.log('Hooking gnutls_bye')
    Interceptor.attach(bye, {
    onEnter: function(args) {
            var fd = gnutls_transport_get_int(args[0])
            var dir = args[1].toInt32();
            send({
                type: 'shutdown',
                module: MODULE,
                fd: fd,
                function: 'gnutls_bye',
                conn: connFromFD(fd),
                direction: dir
            })
      }
    })
}