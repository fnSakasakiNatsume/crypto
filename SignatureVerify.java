package tls.demo;

import java.security.*;

public class SignatureVerify {
    
    public static KeyPair generateCAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    
    public static byte[] signCertificate(String serverInfo, PrivateKey caPrivateKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] certificateHash = digest.digest(serverInfo.getBytes());
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(caPrivateKey);
        signature.update(certificateHash);
        return signature.sign();
    }
    
    public static boolean verifySignature(String serverInfo, byte[] signature, PublicKey caPublicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] certificateHash = digest.digest(serverInfo.getBytes());
        
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(caPublicKey);
        sig.update(certificateHash);
        return sig.verify(signature);
    }
}