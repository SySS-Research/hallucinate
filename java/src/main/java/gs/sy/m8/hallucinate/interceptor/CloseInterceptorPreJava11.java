package gs.sy.m8.hallucinate.interceptor;

import gs.sy.m8.hallucinate.Config;
import gs.sy.m8.hallucinate.Util;
import net.bytebuddy.asm.Advice;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;

public class CloseInterceptorPreJava11 {

    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Method method,
                             @Advice.FieldValue(value = "c") Object c) {
        InetSocketAddress local = Util.tryGetLocalAddr(c);
        InetSocketAddress remote = Util.tryGetRemoteAddr(c);
        int connId = System.identityHashCode(c);
        Config.getInstance().sendrecv("close", method, connId, local, remote, null);
    }
}
