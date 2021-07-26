const MODULE = 'schannel';
const LIBRARY = mapped(MODULE,'@lib');

/*
https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-decryptmessage
https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage
*/

const BUFFER_TYPES = {
    '0': 'empty',
    '1': 'data',
    '2': 'token',
    '3': 'pkg-params',
    '4': 'missing',
    '5': 'extra',
    '6': 'stream-trailer',
    '7': 'stream-header',

    'B': 'mechlist',
    'C': 'mechlist-signature',
    'D': 'target',
    'E': 'channel-bindings',
    'F': 'change-pass-response',
    '10': 'target-host',
    '11': 'alert',
    '12': 'applications-protocols',
    '13': 'srtp-protection-profiles',
    '14': 'srtp-master-key-identifier',
    '15': 'token-binding',
    '16': 'preshared-key',
    '17': 'preshared-key-identity',
    '18': 'dtls-mtu',
    'F0000000': 'attrmask',
};

const BUFFER_FLAG_RO = 0x80000000;
const BUFFER_FLAG_RO_CHECKSUM = 0x10000000;

function parse_SecBufferDesc(ptr) {
    var ulVersion = ptr.readULong();
    var cBuffers = ptr.add(4).readULong();
    var pBuffers = ptr.add(8).readPointer();
    if ( ulVersion != 0 ) {
        console.log('Unsupported SecBufferDesc version ' + ulVersion);
        return null;
    }

    var buffers = [];
    var bptr = pBuffers;
    for ( var i = 0; i < cBuffers; i++) {
        var ptrCbBuffer = bptr;
        var cbBuffer = bptr.readULong();
        var BufferType = bptr.add(4).readULong();
        var type = (BufferType & (~(BUFFER_FLAG_RO | BUFFER_FLAG_RO_CHECKSUM))).toString(16)
        if ( BUFFER_TYPES[type]) {
            type = BUFFER_TYPES[type]
        }
        var flags = (BufferType & (BUFFER_FLAG_RO | BUFFER_FLAG_RO_CHECKSUM)).toString(16)
        var ptrPvBuffer = bptr.add(8);
        var pvBuffer = ptrPvBuffer.readPointer();
        bptr = bptr.add(8 + Process.pointerSize);


        try {
            var data = type != 'empty' ? Memory.readByteArray(pvBuffer, cbBuffer) : [];
            buffers.push({
                cbBuffer: cbBuffer,
                ptrCbBuffer: ptrCbBuffer,
                BufferType: BufferType,
                type: type,
                flags: flags,
                ptrPvBuffer: ptrPvBuffer,
                pvBuffer: pvBuffer,
                data: encode(data),
            })
        } catch (e) {
            console.log('Failed to read buffer of type ' + type);
            console.log(e)
        }
    }

    return {ulVersion: ulVersion, cBuffers: cBuffers, pBuffers: pBuffers, buffers: buffers}
}


var encrypt = mapped(MODULE, 'EncryptMessage') || Module.findExportByName(LIBRARY, 'EncryptMessage');
if ((!encrypt)) {
    options.debug && console.log('No SChannel? EncryptMessage not found')
} else {
    options.debug && console.log('Hooking SSPI EncryptMessage');
    Interceptor.attach(encrypt, {
         onEnter: function(args) {
            this.ctx = args[0];
            this.qop = args[1];
            this.msg = args[2];
            this.seqno = args[3];
            var bufDesc = parse_SecBufferDesc(this.msg);
            options.debug && console.log(JSON.stringify(bufDesc))

            var dataBuf = bufDesc.buffers.find(x => x.type == 'data')
            if ( !dataBuf ) {
                options.debug && console.log('No data buffer found')
                return;
            }
            var rv = sendrecv('pre-send', {
                module: MODULE,
                function: 'EncryptMessage',
                bufsize: dataBuf.cbBuffer,
                data: dataBuf.data,
                conn: this.ctx.toString()
            });
            // replace buffer contents if so desired
            if ( rv['decision'] === 'replace') {
                options.debug && console.log('Replacing send data');
                var data = decode(rv['data']);

                // This API encrypts the buffer in place, caller must be expected
                // to read from a original buffer pointer and we therefore cannot
                // replace the buffer, which means the size is limited to the original
                // buffers size
                if ( !options.replaceBuffer ) {
                    if (data.byteLength > dataBuf.cbBuffer) {
                        throw new RangeError('Returned data exceeds buffer size');
                    }
                    dataBuf.pvBuffer.writeByteArray(data);
                    dataBuf.ptrCbBuffer.writeULong(data.byteLength);
                } else {
                    this.replaceBuf = Memory.alloc(data.byteLength)
                    this.replaceBuf.writeByteArray(data);
                    dataBuf.ptrPvBuffer.writePointer(this.replaceBuf);
                    dataBuf.ptrCbBuffer.writeULong(data.byteLength);
                }
            }
         },
         onLeave: function(retval) {
            var bufDesc = parse_SecBufferDesc(this.msg);
            options.debug && console.log(JSON.stringify(bufDesc))

            var dataBuf = bufDesc.buffers.find(x => x.type == 'data')
            if ( !dataBuf ) {
                options.debug && console.log('No data buffer found')
                return;
            }
            // is this useful in any way?
            var rv = sendrecv('post-send', {
                module: MODULE,
                function: 'EncryptMessage',
                length: dataBuf.cbBuffer,
                bufsize: dataBuf.cbBuffer,
                conn: this.ctx.toString()
            });
         }
    })
}


var decrypt = mapped(MODULE, 'DecryptMessage') || Module.findExportByName(LIBRARY, 'DecryptMessage');
if ((!decrypt)) {
    options.debug && console.log('No SChannel? DecryptMessage not found')
} else {
    options.debug && console.log('Hooking SSPI DecryptMessage');
    Interceptor.attach(decrypt, {
         onEnter: function(args) {
            this.ctx = args[0];
            this.msg = args[1];
            this.seqno = args[2];
            this.ptrQop = args[3];

            var bufDesc = parse_SecBufferDesc(this.msg);
            var dataBuf = bufDesc.buffers.find(x => x.type == 'data')
            if ( !dataBuf ) {
                options.debug && console.log('No data buffer found')
                return;
            }

            var rv = sendrecv('pre-recv', {
                module: MODULE,
                function: 'DecryptMessage',
                bufsize: dataBuf.cbBuffer,
                conn: this.ctx.toString()
            });
         },
         onLeave: function(retval) {
            var bufDesc = parse_SecBufferDesc(this.msg);
            options.debug && console.log(JSON.stringify(bufDesc))
            var dataBuf = bufDesc.buffers.find(x => x.type == 'data')
            if ( !dataBuf ) {
                options.debug && console.log('No data buffer found')
                return;
            }
            var rv = sendrecv('post-recv', {
                module: MODULE,
                function: 'DecryptMessage',
                length: dataBuf.cbBuffer,
                bufsize: dataBuf.cbBuffer,
                data: dataBuf.data,
                conn: this.ctx.toString()
            });
            if ( rv['decision'] === 'replace') {
                var data = decode(rv['data'])
                if ( !options.replaceBuffer ) {
                    if ( data.byteLength > this.bufsize ) {
                        throw new RangeError('Returned data exceeds buffer size');
                    } else {
                        options.debug && console.log('Replacing received data')
                        dataBuf.pvBuffer.writeByteArray(data);
                        dataBuf.ptrCbBuffer.writeULong(data.byteLength);
                    }
                } else {
                    this.replaceBuf = Memory.alloc(data.byteLength)
                    this.replaceBuf.writeByteArray(data);
                    dataBuf.ptrPvBuffer.writePointer(this.replaceBuf);
                    dataBuf.ptrCbBuffer.writeULong(data.byteLength);
                }
            }
         }
    })
}

var destroy = mapped(MODULE, 'DeleteSecurityContext') || Module.findExportByName(LIBRARY, 'DeleteSecurityContext');
if (!destroy) {
    options.debug && console.log('No SChannel? DeleteSecurityContext not found')
} else {
    options.debug && console.log('Hooking SSPI DeleteSecurityContext');
    Interceptor.attach(destroy, {
        onEnter: function(args) {
            send({
                type: 'shutdown',
                module: MODULE,
                function: 'DeleteSecurityContext',
                conn: args[0].toString(),
                direction: 2
            })
        }
    });
}


/*
TODO: Needed?

SECURITY_STATUS WINAPI SslEncryptPacket(
  _In_    NCRYPT_PROV_HANDLE hSslProvider,
  _Inout_ NCRYPT_KEY_HANDLE  hKey,
  _In_    PBYTE              *pbInput,
  _In_    DWORD              cbInput,
  _Out_   PBYTE              pbOutput,
  _In_    DWORD              cbOutput,
  _Out_   DWORD              *pcbResult,
  _In_    ULONGLONG          SequenceNumber,
  _In_    DWORD              dwContentType,
  _In_    DWORD              dwFlags
);

SECURITY_STATUS WINAPI SslDecryptPacket(
  _In_    NCRYPT_PROV_HANDLE hSslProvider,
  _Inout_ NCRYPT_KEY_HANDLE  hKey,
  _In_    PBYTE              *pbInput,
  _In_    DWORD              cbInput,
  _Out_   PBYTE              pbOutput,
  _In_    DWORD              cbOutput,
  _Out_   DWORD              *pcbResult,
  _In_    ULONGLONG          SequenceNumber,
  _In_    DWORD              dwFlags
);
*/
