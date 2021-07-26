function sendrecv(t, m) {
    var r = Object.assign({type: t}, m);
    var rv = null;
    send(r);
    var r = recv(t + '-resp', function onMessage(m) {
        rv = m;
    });
    r.wait()
    return rv
}

function readSizeT(a) {
    return a;
}

const byteToHex = [];
for (let n = 0; n <= 0xff; ++n) {
    const hexOctet = n.toString(16).padStart(2, '0');
    byteToHex.push(hexOctet);
}

function encode(arrayBuffer) {
    const buff = new Uint8Array(arrayBuffer);
    const hexOctets = new Array(buff.length);
    for (let i = 0; i < buff.length; ++i) {
        hexOctets[i] = byteToHex[buff[i]];
    }
    return hexOctets.join('');
}

function decode(hexData) {
    if (hexData.length % 2 != 0) {
        throw new RangeError('Expected even-length string')
    }
    var outLen = hexData.length / 2
    var view = new Uint8Array(outLen)
    for (var i = 0; i < outLen; i += 1) {
        var i2 = i*2;
        view[i] = parseInt(hexData.substring(i2, i2 + 2), 16)
    }
    return view.buffer
}

function firstCall(addr) {
    var limit = 20;
    var ni = addr;
    while ( --limit > 0 ) {
        var i = Instruction.parse(ni);
        if ( i.mnemonic === 'call' ) {
            return new NativePointer(i.opStr);
        }
        ni = i.next;
    }
    return null;
}


const supportedSocketTypes = ['tcp', 'tcp6', 'udp', 'udp6'];

function connFromFD(fd) {
    if (fd < 0 || !fd) {
        return null;
    }
    var st = Socket.type(fd);
    if (!st || !supportedSocketTypes.includes(st)) {
        return {t:st};
    }
    return {t:st,l:Socket.localAddress(fd),r:Socket.peerAddress(fd)}
}

function mapped(mod,item) {
    if ( options.map[mod] && options.map[mod][item] ) {
        var v = options.map[mod][item];
        if ( item == '@lib') {
            return v;
        }
        return new NativePointer(options.map[mod][item]);
    }
    return null;
}