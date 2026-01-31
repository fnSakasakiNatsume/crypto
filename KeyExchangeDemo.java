package tls.demo;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.MessageDigest;

public class KeyExchangeDemo {
    
    private static final int RSA_KEY_SIZE = 2048;
    private static final int PMS_SIZE = 48; 
    
    public static KeyPair generateServerKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    
    public static byte[] generatePreMasterSecret() {
        SecureRandom random = new SecureRandom();
        byte[] pms = new byte[PMS_SIZE];
        random.nextBytes(pms);
        pms[0] = 0x03; 
        pms[1] = 0x03; 
        return pms;
    }
    
    public static byte[] encryptPreMasterSecret(byte[] pms, java.security.PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(pms);
    }
    
    public static byte[] decryptPreMasterSecret(byte[] encrypted, java.security.PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encrypted);
    }
    
    public static byte[] generateSessionKey(byte[] r1, byte[] r2, byte[] pms) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(r1);
        digest.update(r2);
        digest.update(pms);
        return digest.digest();
    }
}