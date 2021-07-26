package gs.sy.m8.hallucinate;

import javax.net.ssl.SSLSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

public class Util {

    private static final char[] HEXCHARS = "0123456789ABCDEF".toCharArray();
    public static String toHex(byte[] bytes) {
        char[] o = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            o[j * 2] = HEXCHARS[v >> 4];
            o[j * 2 + 1] = HEXCHARS[v & 0xF];
        }
        return new String(o);
    }

    public static byte[] fromHex(String resp) {
        int olen = resp.length()/2;
        byte[] data = new byte[olen];
        for ( int i = 0; i < olen; i++) {
            int p = i * 2;
            data[i] = (byte)Integer.parseUnsignedInt(resp.substring(p,p+1),16);
        }
        return data;
    }

    public static InetSocketAddress tryGetLocalAddr(Object instance) {
        if ( instance instanceof SSLSocket ) {
            SSLSocket s = (SSLSocket) instance;
            return new InetSocketAddress(s.getLocalAddress(), s.getLocalPort());
        }
        return null;
    }

    public static InetSocketAddress tryGetRemoteAddr(Object instance) {
        if ( instance instanceof SSLSocket ) {
            return (InetSocketAddress) ((SSLSocket) instance).getRemoteSocketAddress();
        }
        return null;
    }



}
