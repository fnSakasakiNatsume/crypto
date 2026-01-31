package tls.demo;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class CipherSuite {
    
    private static final int GCM_IV_LENGTH = 12; 
    private static final int GCM_TAG_LENGTH = 128; 
    
    public static SecretKey deriveAESKey(byte[] sessionKey) {
        byte[] aesKeyBytes = new byte[32];
        System.arraycopy(sessionKey, 0, aesKeyBytes, 0, 32);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }
    
    public static EncryptedData encryptHTTPMessage(String httpMessage, SecretKey key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        
        byte[] plaintext = httpMessage.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        return new EncryptedData(ciphertext, iv);
    }
    
    public static String decryptHTTPMessage(EncryptedData encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, encryptedData.iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        
        byte[] plaintext = cipher.doFinal(encryptedData.ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
    
    public static class EncryptedData {
        public final byte[] ciphertext;
        public final byte[] iv;
        
        public EncryptedData(byte[] ciphertext, byte[] iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }
    }
}