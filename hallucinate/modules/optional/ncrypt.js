const MODULE = 'ncrypt';
const LIBRARY = mapped(MODULE,'@lib');



var encrypt = mapped(MODULE, 'SslEncryptPacket') || Module.findExportByName(LIBRARY, 'SslEncryptPacket');
if ((!encrypt)) {
    options.debug && console.log('No Ncrypt? SslEncryptPacket not found')
} else {
    options.debug && console.log('Hooking Ncrypt SslEncryptPacket');
    Interceptor.attach(encrypt, {
         onEnter: function(args) {
            this.ctx = args[0];
            this.key = args[1];
            this.inpBuf = args[2];
			this.inpLen = args[3];
			this.outBuf = args[4];
			this.outSize = args[5];
			this.outLenPtr = args[6];
            
            var rv = sendrecv('pre-send', {
                module: MODULE,
                function: 'SslEncryptPacket',
                bufsize: this.inpLen,
                data: encode(Memory.readByteArray(this.inpBuf, this.inpLen.toInt32())),
                conn: this.ctx.toString()
            });
            // replace buffer contents if so desired
            if ( rv['decision'] === 'replace') {
                options.debug && console.log('Replacing send data');
                var data = decode(rv['data']);

				this.replaceBuf = Memory.alloc(data.byteLength)
				this.replaceBuf.writeByteArray(data);
				args[2] = data.replaceBuf;
				args[3] = data.byteLength;                
            }
         },
         onLeave: function(retval) {
            // is this useful in any way?
            var rv = sendrecv('post-send', {
                module: MODULE,
                function: 'SslEncryptPacket',
                conn: this.ctx.toString()
            });
         }
    })
}


var decrypt = mapped(MODULE, 'SslDecryptPacket') || Module.findExportByName(LIBRARY, 'SslDecryptPacket');
if ((!decrypt)) {
    options.debug && console.log('No NCrypt? SslDecryptPacket not found')
} else {
    options.debug && console.log('Hooking SSPI SslDecryptPacket');
    Interceptor.attach(decrypt, {
         onEnter: function(args) {
            this.ctx = args[0];
            this.key = args[1];
            this.inpBuf = args[2];
			this.inpLen = args[3];
			this.outBuf = args[4];
			this.outSize = args[5];
			this.outLenPtr = args[6];
            var rv = sendrecv('pre-recv', {
                module: MODULE,
                function: 'SslDecryptPacket',
                bufsize: this.outSize,
                conn: this.ctx.toString()
            });
         },
         onLeave: function(retval) {
            var rv = sendrecv('post-recv', {
                module: MODULE,
                function: 'SslDecryptPacket',
                length: this.outLenPtr.readULong(),
                bufsize: this.outSize,
                data:  encode(Memory.readByteArray(this.outBuf, this.outLenPtr.readULong())),
                conn: this.ctx.toString()
            });
            if ( rv['decision'] === 'replace') {
                var data = decode(rv['data'])
				if ( data.byteLength > this.outSize ) {
					throw new RangeError('Returned data exceeds buffer size');
				} else {
					options.debug && console.log('Replacing received data')
					this.outBuf.writeByteArray(data);
					this.outLenPtr.writeULong(data.byteLength);
				}
            }
         }
    })
}
