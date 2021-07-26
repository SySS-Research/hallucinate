package gs.sy.m8.hallucinate.interceptor;

import gs.sy.m8.hallucinate.Config;
import gs.sy.m8.hallucinate.Util;
import net.bytebuddy.asm.Advice;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class WriteInterceptorPreJava11 {


    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Method method,
                             @Advice.Argument(value = 0, readOnly = false) byte[] buffer,
                             @Advice.Argument(value = 1, readOnly = false) int offset,
                             @Advice.Argument(value = 2, readOnly = false) int length,
                             @Advice.Local(value="connId") int connId,
                             @Advice.Local(value="localAddr") InetSocketAddress local,
                             @Advice.Local(value="remoteAddr") InetSocketAddress remote,
                             @Advice.FieldValue(value = "c") Object c,
                             @Advice.This Object thiz) {

        local = Util.tryGetLocalAddr(c);
        remote = Util.tryGetRemoteAddr(c);
        connId = System.identityHashCode(c);

        byte[] data = Arrays.copyOfRange(buffer, offset, length);
        Map<String,String> rdata = new HashMap<>();
        rdata.put("bufSize", String.valueOf(length));
        rdata.put("data", Util.toHex(Arrays.copyOfRange(buffer, offset, length)));

        String resp = Config.getInstance().sendrecv(
                "pre-send", method,
                connId,
                local,
                remote,
                rdata
        );
        if ( resp == null ) {
            return;
        }
        byte[] decoded = Util.fromHex(resp);
        buffer = decoded;
        offset = 0;
        length = decoded.length;
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Method method,
                            @Advice.Argument(value = 0, readOnly = false) byte[] buffer,
                            @Advice.Argument(value = 1, readOnly = false) int offset,
                            @Advice.Argument(value = 2, readOnly = false) int length,
                            @Advice.Local(value="connId") int connId,
                            @Advice.Local(value="localAddr") InetSocketAddress local,
                            @Advice.Local(value="remoteAddr") InetSocketAddress remote,
                            @Advice.This Object thiz) {

        Map<String,String> rdata = new HashMap<>();
        rdata.put("bufSize", String.valueOf(length-offset));
        rdata.put("length", String.valueOf(length-offset));

        Config.getInstance().sendrecv(
                "post-send", method,
                connId,
                local,
                remote,
                rdata
        );
    }
}
