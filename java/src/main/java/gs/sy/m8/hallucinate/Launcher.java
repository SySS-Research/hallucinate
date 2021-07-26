package gs.sy.m8.hallucinate;

import net.bytebuddy.agent.ByteBuddyAgent;

import java.io.File;
import java.security.CodeSource;

public class Launcher {


    public static void main(String[] args) throws Exception {
        if ( args.length < 1 ) {
            System.out.println("Usage: Launcher <TargetPID> [<options>]");
            System.exit(-1);
        }
        CodeSource cs = Launcher.class.getProtectionDomain().getCodeSource();
        File u = new File(cs.getLocation().toURI());
        String opts = null;
        if ( args.length > 1 ) {
            opts = args[1];
        }
        ByteBuddyAgent.attach(u, args[0], opts);
    }
}
