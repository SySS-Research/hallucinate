package gs.sy.m8.hallucinate;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Test {

    public static void main(String[] args) throws Exception {

        if ( args.length > 0 && args[0].equals("single") ) {
            run();
            return;
        }

        while ( true ) {

            run();

            Thread.sleep(5000);
        }

    }

    private static void run() throws IOException, NoSuchAlgorithmException, KeyManagementException {
        URL u = new URL("https://localhost/");
        HttpsURLConnection uc = (HttpsURLConnection) u.openConnection();

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[0], new TrustManager[]{
                new TrustAllTrustManager()
        }, new SecureRandom());

        uc.setSSLSocketFactory(ctx.getSocketFactory());
        uc.setHostnameVerifier((s, sslSession) -> true);


        System.out.println(uc.getResponseCode());
    }

    private static class TrustAllTrustManager extends X509ExtendedTrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {

        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {

        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
