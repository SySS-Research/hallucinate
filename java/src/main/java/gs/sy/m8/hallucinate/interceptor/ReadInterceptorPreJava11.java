package gs.sy.m8.hallucinate.interceptor;

import gs.sy.m8.hallucinate.Config;
import gs.sy.m8.hallucinate.Util;
import net.bytebuddy.asm.Advice;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ReadInterceptorPreJava11 {

    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Method method,
                             @Advice.Argument(value = 0, readOnly = false) byte[] buffer,
                             @Advice.Argument(value = 1, readOnly = false) int offset,
                             @Advice.Argument(value = 2, readOnly = false) int bufSize,
                             @Advice.Local(value="connId") int connId,
                             @Advice.Local(value="localAddr") InetSocketAddress local,
                             @Advice.Local(value="remoteAddr") InetSocketAddress remote,
                             @Advice.FieldValue(value = "c") Object c,
                             @Advice.This Object thiz) {

        local = Util.tryGetLocalAddr(c);
        remote = Util.tryGetRemoteAddr(c);
        connId = System.identityHashCode(c);

        Config.getInstance().sendrecv(
                "pre-recv", method,
                connId,
                local,
                remote,
                Collections.singletonMap("bufSize", String.valueOf(bufSize))
        );
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Method method,
                            @Advice.Argument(value = 0, readOnly = false) byte[] buffer,
                            @Advice.Argument(value = 1, readOnly = false) int offset,
                            @Advice.Argument(value = 2, readOnly = false) int bufSize,
                            @Advice.Local(value="connId") int connId,
                            @Advice.Local(value="localAddr") InetSocketAddress local,
                            @Advice.Local(value="remoteAddr") InetSocketAddress remote,
                            @Advice.This Object thiz, @Advice.Return(readOnly = false) int rv) {

        int length = (int) rv;
        if ( length < 0 ) {
            return;
        }
        Map<String,String> rdata = new HashMap<>();
        rdata.put("bufSize", String.valueOf(bufSize-offset));
        rdata.put("length", String.valueOf(bufSize));
        rdata.put("data", Util.toHex(Arrays.copyOfRange(buffer, offset, length)));

        String resp = Config.getInstance().sendrecv(
                "post-recv", method,
                connId,
                local,
                remote,
                rdata
        );
        if ( resp == null ) {
            return;
        }
        byte[] decoded = Util.fromHex(resp);
        if ( decoded.length > (bufSize-offset)) {
            System.err.println("Replacement data exceeds available buffer size");
            return;
        }
        System.arraycopy(decoded, 0, buffer, offset, decoded.length);
        rv = decoded.length;
    }



}
