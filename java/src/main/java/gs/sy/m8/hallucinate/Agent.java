package gs.sy.m8.hallucinate;

import gs.sy.m8.hallucinate.interceptor.*;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.loading.ClassInjector;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Agent {



    public static void premain(String agentArgs, Instrumentation inst){
        try {
            setUp(agentArgs, inst);
        } catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    public static void agentmain(String agentArgs, Instrumentation inst){
        try {
            setUp(agentArgs, inst);
        } catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static void setUp(String agentArgs, Instrumentation inst) throws Exception {
        Class ais;
        boolean java11 = false;
        try {
            ais = findClass("sun.security.ssl.SSLSocketImpl$AppInputStream", inst);
            java11 = true;
        } catch ( ClassNotFoundException e ) {
            ais = findClass("sun.security.ssl.AppInputStream", inst);
        }
        Class aos;
        try {
            aos = findClass("sun.security.ssl.SSLSocketImpl$AppOutputStream", inst);
            java11 = true;
        }  catch ( ClassNotFoundException e ) {
            aos = findClass("sun.security.ssl.AppOutputStream", inst);
        }

        final boolean fjava11 = java11;

        Config c = Config.parseOptions(agentArgs);
        injectClasses(c, inst);
        AgentBuilder b = setupByteBuddy(c, ais, aos);
        b = b.type(ElementMatchers.anyOf(ais,aos))
            .transform((DynamicType.Builder<?> builder,
                        TypeDescription type,
                        ClassLoader loader,
                        JavaModule module) ->
                    builder
                        .visit(
                            Advice.to(fjava11 ? ReadInterceptorJava11.class : ReadInterceptorPreJava11.class)
                                    .on(ElementMatchers.named("read").and(ElementMatchers.takesArguments(byte[].class, int.class, int.class))))
                        .visit(
                            Advice.to(fjava11 ? WriteInterceptorJava11.class :WriteInterceptorPreJava11.class)
                                    .on(ElementMatchers.named("write").and(ElementMatchers.takesArguments(byte[].class, int.class, int.class))))
                        .visit(
                            Advice.to(fjava11 ? CloseInterceptorJava11.class : CloseInterceptorPreJava11.class)
                                    .on(ElementMatchers.named("close")))
            );
        b.installOn(inst);
    }

    private static void injectClasses(Config c, Instrumentation inst) throws IOException {
        File temp = Files.createTempDirectory("hallucinate-java-tmp").toFile();
        Map<TypeDescription, byte[]> clazzes = new HashMap<>();
        for ( Class<?> clazz : Arrays.asList(Util.class)) {
            clazzes.put(new TypeDescription.ForLoadedType(clazz), ClassFileLocator.ForClassLoader.read(clazz));
        }


        clazzes.put(new TypeDescription.ForLoadedType(Config.class),
                new ByteBuddy()
                        .redefine(Config.class)
                        .method(ElementMatchers.named("isDebug"))
                        .intercept(FixedValue.value(c.DEBUG))
                        .method(ElementMatchers.named("getServerAddr"))
                        .intercept(FixedValue.value(c.SERVERADDR))
                        .method(ElementMatchers.named("getServerKey"))
                        .intercept(FixedValue.value(c.SERVERKEY))
                        .method(ElementMatchers.named("getServerPort"))
                        .intercept(FixedValue.value(c.SERVERPORT))
                .make().getBytes()
        );

        ClassInjector.UsingInstrumentation
                .of(temp, ClassInjector.UsingInstrumentation.Target.BOOTSTRAP, inst)
                .inject(clazzes);
    }

    private static AgentBuilder setupByteBuddy(Config c, Class ais, Class aos) {

        AgentBuilder b = new AgentBuilder.Default(new ByteBuddy().with(TypeValidation.DISABLED))
            .ignore(ElementMatchers.none())
            .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(new AgentBuilder.RedefinitionStrategy.DiscoveryStrategy.Explicit(ais, aos, Config.class))
            .disableClassFormatChanges();

        if ( c.DEBUG ) {
            b = b.with(AgentBuilder.Listener.StreamWriting.toSystemOut());
        }
        return b;
    }

    private static Class findClass(String s, Instrumentation inst) throws ClassNotFoundException {
        try {
            return Class.forName(s);
        } catch ( ClassNotFoundException e ) {
            // ignore
        }

        for(Class<?> clazz: inst.getAllLoadedClasses()) {
            if ( s.equals(clazz.getName() )) {
                return clazz;
            }
        }

        throw new ClassNotFoundException(s);
    }
}

