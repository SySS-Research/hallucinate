const MODULE = 'openssl';
const LIBNAME = mapped(MODULE,'@lib');

var SSL_get_fd;
var sslgetfd = mapped(MODULE, 'SSL_get_fd') || Module.findExportByName(LIBNAME, 'SSL_get_fd')
if ( !sslgetfd ) {
    SSL_get_fd = function() {
        // SSL_get_fd also returns -1 on error
        return -1;
    }
} else {
    SSL_get_fd = new NativeFunction(sslgetfd, "int", ["pointer"]);
}



/*
int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
 int SSL_read(SSL *ssl, void *buf, int num);

*/


function readHandler(func) {
    return {
         onEnter: function(args) {
            this.fd = SSL_get_fd(args[0]);
            this.buf = args[1];
            this.bufsize = args[2];
            if ( func == 'ssl_read_internal' || func == 'SSL_read_ex') {
                this.lengthptr = args[3];
            }
            var rv = sendrecv('pre-recv', {
                module: MODULE,
                function: func,
                fd: this.fd,
                bufsize: this.bufsize,
                conn: connFromFD(this.fd)
            });
         },
         onLeave: function(retval) {
             var rl;
             if ( this.lengthptr ) {
                if ( retval.compare(0) <= 0 ) {
                    return;
                }
                rl = new NativePointer(Memory.readULong(this.lengthptr))
             } else {
                rl = retval
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
             }
             var b = Memory.readByteArray(this.buf, rl.toInt32());
             var rv = sendrecv('post-recv', {
                module: MODULE,
                function: func,
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
                    if ( this.lengthptr ) {
                        Memory.writeULong(this.lengthptr, data.byteLength)
                    } else {
                        retval.replace(data.byteLength)
                    }
                }
             }
         }
    }
}

var sslreadex = mapped(MODULE, 'SSL_read_ex') || Module.findExportByName(LIBNAME, 'SSL_read_ex');
var sslread = mapped(MODULE, 'SSL_read') ||  Module.findExportByName(LIBNAME, 'SSL_read');
if ( !sslreadex ) {
    if ( !sslread ) {
        options.debug && console.log('SSL_read not found, no OpenSSL? or wrong libname?')
    } else {
        options.debug && console.log('Legacy OpenSSL, no SSL_read_ex, hooking SSL_read')
        Interceptor.attach(sslread, readHandler('SSL_read'))
    }
} else if (sslreadex) {
    // need to hook ssl_write_internal/ssl_read_internal, as  these are directly used by the SSL BIO
    options.debug && console.log('Trying to hook ssl_read_internal')
    var sslreadint = firstCall(sslreadex);
    if ( sslreadint ) {
        options.debug && console.log('Found ssl_read_internal at ' + sslreadint)
        Interceptor.attach(sslreadint, readHandler('ssl_read_internal'))
    } else {
        console.log('Did not find ssl_read_internal, falling back to SSL_read/SSL_read_ex, this will not catch all invocations')
        Interceptor.attach(sslread, readHandler('SSL_read'))
        Interceptor.attach(sslreadex, readHandler('SSL_read_ex'))
    }
} else {
    options.debug && console.log('No OpenSSL detected');
}

/*
 int SSL_write(SSL *ssl, const void *buf, int num);
 int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)
*/
function writeHandler(func) {
    return {
         onEnter: function(args) {
            this.fd = SSL_get_fd(args[0]);
            this.buf = args[1];
            this.bufsize = args[2];
            if ( func == 'ssl_write_internal' || func == 'SSL_write_ex') {
                this.lengthptr = args[3];
            }
            var b = Memory.readByteArray(this.buf, this.bufsize.toInt32());
            var rv = sendrecv('pre-send', {
                module: MODULE,
                function: func,
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
             var rl;
             if ( this.lengthptr ) {
                rl = new NativePointer(Memory.readULong(this.lengthptr))
             } else {
                rl = retval;
             }

            // is this useful in any way?
            var rv = sendrecv('post-send', {
                module: MODULE,
                fd: this.fd,
                function: func,
                length: rl,
                bufsize: this.bufsize,
                conn: connFromFD(this.fd)
            });
         }
    }
}

var sslwriteex = mapped(MODULE, 'SSL_write_ex') || Module.findExportByName(LIBNAME, 'SSL_write_ex');
var sslwrite = mapped(MODULE, 'SSL_write') || Module.findExportByName(LIBNAME, 'SSL_write');
if ( ! sslwriteex ) {

    if ( !sslwrite ) {
        options.debug && console.log('SSL_write not found, no OpenSSL? or wrong libname?')
    } else {
        options.debug && console.log('Legacy OpenSSL, no SSL_write_ex, hooking SSL_write')
        Interceptor.attach(sslwrite, writeHandler('SSL_write'))
    }
} else if ( sslwriteex ) {
    options.debug && console.log('Trying to hook ssl_write_internal');
    var sslwriteint = firstCall(sslwriteex);
    if ( sslwriteint ) {
        options.debug && console.log('Found ssl_write_internal at ' + sslwriteint)
        Interceptor.attach(sslwriteint, writeHandler('ssl_write_internal'))
    } else {
        console.log('Did not find ssl_write_internal, falling back to SSL_write/SSL_write_ex, this will not catch all invocations')
        Interceptor.attach(sslwrite, writeHandler('SSL_write'))
        Interceptor.attach(sslwriteex, writeHandler('SSL_write_ex'))
    }
} else {
    options.debug && console.log('No OpenSSL detected');
}


var sslshutdown = mapped(MODULE, 'SSL_shutdown') || Module.findExportByName(LIBNAME,'SSL_shutdown')
if ( sslshutdown ) {
    Interceptor.attach(sslshutdown, {
         onEnter: function(args) {
            var fd = SSL_get_fd(args[0]);
            send({
                type: 'shutdown',
                module: MODULE,
                fd: fd,
                function: 'SSL_shutdown',
                conn: connFromFD(fd),
                direction: 2
            })
         }
    })
}