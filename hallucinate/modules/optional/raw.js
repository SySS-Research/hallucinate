const socketModule = {
    "windows": ["ws2_32.dll"],
    "darwin": ["libSystem.B.dylib"],
    "linux": ["libc.so.6", "libpthread.so.0"]
};

const MODULE = 'raw';
/*
ssize_t read(int fd, void *buf, size_t count);

ssize_t recv(int sockfd, void *buf, size_t len, int flags);

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                    int flags, struct timespec *timeout);

Scatter/Gather IO
       ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
       ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
*/
function recvHandler(func) {
    return {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
            var st = connFromFD(this.fd);
            if (!st || !supportedSocketTypes.includes(st.t)) {
                return;
            }
            this.buf = args[1]
            this.bufsize = readSizeT(args[2]);
            var rv = sendrecv('pre-recv', {
                module: MODULE,
                fd: this.fd,
                function: func,
                bufsize: this.bufsize,
                conn: st
            });

            // TODO: is the pre-call exchange needed?
            // which is better performance wise?
            // - make the call and allow handler to ignore (avoiding touching the actual data)
            // - avoid the call
        } , onLeave: function(retval) {
            var st = connFromFD(this.fd);
            if (!st || !supportedSocketTypes.includes(st.t)) {
                return;
            }
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
                fd: this.fd,
                function: func,
                length: retval,
                bufsize: this.bufsize,
                data: encode(b),
                conn: st
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
    }
}

/**
ssize_t write(int fd, const void *buf, size_t count);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
              const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                    int flags);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
*/
function sendHandler(func) {
    return {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
            var st = connFromFD(this.fd);
            if (!st || !supportedSocketTypes.includes(st.t)) {
                return;
            }
            this.buf = args[1]
            this.bufsize = readSizeT(args[2]);
            this.address = Socket.peerAddress(this.fd);
            this.laddress = Socket.localAddress(this.fd);
            var b = Memory.readByteArray(this.buf, this.bufsize.toInt32());
            var rv = sendrecv('pre-send', {
                module: MODULE,
                fd: this.fd,
                function: func,
                bufsize: this.bufsize,
                data: encode(b),
                conn: st
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
        }, onLeave: function(retval) {
            var st = connFromFD(this.fd);
            if (!st || !supportedSocketTypes.includes(st.t)) {
                return;
            }

            // TODO: even if we modified the payload the called still probably needs
            // the original size to be returned, as otherwise the client may end up
            // in an inconsistent state. Offer option to return the actual size?
            var rl = retval.toInt32();

            // is this useful in any way?
            var rv = sendrecv('post-send', {
                module: MODULE,
                fd: this.fd,
                function: func,
                length: retval,
                bufsize: this.bufsize,
                conn: st
            });
        }
    }
}

function connectHandler(func) {
    return {
      onEnter: function(args) {
            var fd = args[0].toInt32();
            var st = connFromFD(fd);
            if (!st || !supportedSocketTypes.includes(st.t)) {
                return;
            }
            var sockaddr = Memory.readByteArray(args[1], args[2].toInt32());
            send({
                type: 'connect',
                module: MODULE,
                fd: fd,
                conn: st,
                sockaddr: encode(sockaddr)
            });
      }
    }
}

function shutdownHandler(func) {
    return {
      onEnter: function(args) {
            var fd = args[0].toInt32();
            var st = connFromFD(fd);
            if (!st || !supportedSocketTypes.includes(st.t)) {
                return;
            }
            var dir = 2; // SHUT_RDWR
            if ( func === 'shutdown'){
                dir = args[1].toInt32();
            }
            send({
                type: 'shutdown',
                module: MODULE,
                fd: fd,
                function: func,
                conn: st,
                direction: dir
            })
      }
    }
}

function unsupportedHandler(func) {
    return {
        onEnter: function(args) {
            var st = Socket.type(args[0].toInt32());
            if (!st || !supportedSocketTypes.includes(st)) {
                return;
            }
            send({type: 'unsupported', function: func})
        }
    }
}

const supportedRecv = ['read', 'recv', 'recvfrom'];
const supportedSend = ['write', 'send', 'sendto'];


var sms = socketModule[Process.platform];
for ( var i = 0; i < sms.length; ++i) {
    Module.enumerateExports(sms[i], {
        onMatch: function (exp) {
              if (exp.type !== 'function') {
                return
              }
              if (exp.name.indexOf('recv') === 0 || exp.name === 'read' || exp.name === 'readv') {
                if (supportedRecv.includes(exp.name)) {
                    options.debug && console.log("Hook " + exp.name + " in " + sms[i]);
                    Interceptor.attach(exp.address, recvHandler(exp.name))
                } else {
                    Interceptor.attach(exp.address, unsupportedHandler(exp.name))
                }
              } else if (exp.name.indexOf('send') === 0 || exp.name === 'write' || exp.name === 'writev') {
                if (supportedSend.includes(exp.name)) {
                    options.debug && console.log("Hook " + exp.name + " in " + sms[i]);
                    Interceptor.attach(exp.address, sendHandler(exp.name))
                } else {
                    Interceptor.attach(exp.address, unsupportedHandler(exp.name))
                }
              } else if (exp.name === 'connect') {
                 options.debug && console.log("Hook " + exp.name + " in " + sms[i]);
                 Interceptor.attach(exp.address, connectHandler(exp.name))
              } else if (exp.name === 'close' || exp.name === 'shutdown') {
                 options.debug && console.log("Hook " + exp.name + " in " + sms[i]);
                 Interceptor.attach(exp.address, shutdownHandler(exp.name))
              }
        }, onComplete: function () {
        }
    })
}

