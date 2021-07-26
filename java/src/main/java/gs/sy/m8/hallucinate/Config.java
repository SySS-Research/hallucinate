package gs.sy.m8.hallucinate;

import javax.net.SocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class Config {
    public final boolean DEBUG;
    public final String SERVERADDR;
    public final String SERVERKEY;
    public final int SERVERPORT;

    private Socket sock;

    private static Config INSTANCE;

    private Config(boolean debug, String serveraddr, int serverport, String serverkey) {
        DEBUG=debug;
        SERVERADDR=serveraddr;
        SERVERPORT=serverport;
        SERVERKEY=serverkey;
    }


    private Socket getConnection() throws IOException {
        Socket s = this.sock;
        if ( s == null ) {
            s = SocketFactory.getDefault().createSocket(SERVERADDR, SERVERPORT);
            if  ( DEBUG ) {
                System.err.println(String.format("Connect to %s:%d", SERVERADDR, SERVERPORT));
            }
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());
            dos.writeUTF(SERVERKEY);
            this.sock = s;
        }
        return s;
    }

    public String sendrecv(String type, Method m, long connId, InetSocketAddress local, InetSocketAddress remote, Map<String,String> data) {
        try {
            Socket sock = getConnection();
            try {
                return sendrecv(sock, type, m, connId, local, remote, data);
            } catch (IOException e ) {
                try {
                    sock.close();
                } finally {
                    this.sock = null;
                }
            }
        } catch (IOException e ) {
            e.printStackTrace();
        }
        return null;
    }

    private String sendrecv(Socket sock, String type, Method m, long connId, InetSocketAddress local, InetSocketAddress remote, Map<String, String> data) throws IOException {
        // super simplistic serialization format to avoid pulling a dependency
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
        DataInputStream dis = new DataInputStream(sock.getInputStream());
        sendRequest(type, m, connId, local, remote, data, dos);

        Map<String,String> resp = recvResponse(dis);
        if ( resp != null &&
                resp.containsKey("decision") &&
                resp.containsKey("data") &&
                "replace".equals(resp.get("decision"))) {
            return resp.get("data");
        }
        return null;
    }

    private Map<String, String> recvResponse(DataInputStream dis) throws IOException {
        int nentries = dis.readInt();
        Map<String,String> r = new HashMap<>();

        for ( int i = 0; i < nentries; i++) {
            r.put(dis.readUTF(), dis.readUTF());
        }

        return r;
    }

    private void sendRequest(String type, Method m, long connId, InetSocketAddress local, InetSocketAddress remote, Map<String, String> data, DataOutputStream dos) throws IOException {
        int nentries = 4 +
                (local != null ? 2 : 0) +
                (remote != null ? 2 : 0) +
                (data != null ? data.size() : 0);
        dos.writeInt(nentries);
        writeEntry(dos, "type", type);
        writeEntry(dos, "module", "jsse");
        writeEntry(dos, "func", m.getName());
        writeEntry(dos, "connId", String.valueOf(connId));
        if (local != null) {
            writeEntry(dos, "localAddr", local.getAddress().getHostAddress());
            writeEntry(dos, "localPort", String.valueOf(local.getPort()));
        }
        if (remote != null) {
            writeEntry(dos, "remoteAddr", remote.getAddress().getHostAddress());
            writeEntry(dos, "remotePort", String.valueOf(remote.getPort()));
        }
        if (data != null) {
            for (Map.Entry<String, String> e : data.entrySet()) {
                writeEntry(dos, e.getKey(), e.getValue());
            }
        }
    }

    private void writeEntry(DataOutputStream dos, String k, String v) throws IOException {
        if ( DEBUG ) {
            System.out.println(String.format("%s = %s", k, v));
        }
        dos.writeUTF(k);
        dos.writeUTF(v);
    }

    public static Config parseOptions(String agentArgs) {
        StringTokenizer st = new StringTokenizer(agentArgs != null ? agentArgs : "", ";");
        String token;
        boolean debug = false;
        String serveraddr = "localhost";
        int serverport = 37234;
        String serverkey = "";

        while ( st.hasMoreElements() ) {
            token = st.nextToken();
            if ( "debug".equals(token)) {
                debug = true;
            } else if ( token.startsWith("serveraddr=")) {
                serveraddr = token.substring("serveraddr=".length());
            } else if ( token.startsWith("serverport=")) {
                serverport = Integer.parseInt(token.substring("serverport=".length()));
            } else if ( token.startsWith("serverkey=")) {
                serverkey = token.substring("serverkey=".length());
            }
        }
        return new Config(debug, serveraddr, serverport, serverkey);
    }

    public static Config getInstance() {
        Config i = INSTANCE;
        if ( i == null ) {
            INSTANCE = new Config(isDebug(), getServerAddr(), getServerPort(), getServerKey());
            i = INSTANCE;
        }
        return i;
    }

    public static String getServerKey() {
        return "<uninit>";
    }

    public static int getServerPort() {
        return 0;
    }

    public static String getServerAddr() {
        return "<uninit>";
    }

    public static boolean isDebug() {
        return true;
    }


}
