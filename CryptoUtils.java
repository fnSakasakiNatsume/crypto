package tls.demo;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * CryptoUtils.java
 * 
 * 密码学工具类 - 封装所有密码学操作
 * 对外提供简单接口，隐藏实现细节
 * 
 * 功能：
 * 1. RSA密钥交换（生成密钥对、加密/解密PMS）
 * 2. 数字证书（CA签名、验证）
 * 3. AES-GCM对称加密（加密/解密数据）
 * 4. 会话密钥生成
 */
public class CryptoUtils {
    
    private static final int RSA_KEY_SIZE = 2048;
    private static final int PMS_SIZE = 48;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    
    // ========== RSA密钥交换 ==========
    
    /**
     * 生成RSA密钥对（服务器使用）
     */
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    
    /**
     * 生成Pre-Master Secret（客户端使用）
     * 48字节：前2字节为TLS版本号，后46字节为随机数
     */
    public static byte[] generatePMS() {
        SecureRandom random = new SecureRandom();
        byte[] pms = new byte[PMS_SIZE];
        random.nextBytes(pms);
        pms[0] = 0x03; // TLS 1.2
        pms[1] = 0x03;
        return pms;
    }
    
    /**
     * 加密PMS（客户端使用服务器公钥）
     * 数学公式：C ≡ PMS^e (mod n)
     */
    public static byte[] encryptPMS(byte[] pms, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(pms);
    }
    
    /**
     * 解密PMS（服务器使用私钥）
     * 数学公式：PMS ≡ C^d (mod n)
     */
    public static byte[] decryptPMS(byte[] encryptedPMS, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedPMS);
    }
    
    /**
     * 生成会话密钥
     * 使用SHA-256结合R1, R2, PMS生成
     * 实际TLS使用PRF（伪随机函数），这里简化演示
     */
    public static byte[] generateSessionKey(byte[] r1, byte[] r2, byte[] pms) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(r1);
        digest.update(r2);
        digest.update(pms);
        return digest.digest();
    }
    
    // ========== 数字证书 ==========
    
    /**
     * 生成CA密钥对
     */
    public static KeyPair generateCAKeyPair() throws Exception {
        return generateRSAKeyPair(); // CA也使用RSA
    }
    
    /**
     * 对证书签名
     * 流程：计算证书哈希值 -> 使用CA私钥签名
     */
    public static byte[] signCertificate(String certInfo, PrivateKey caPrivateKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(certInfo.getBytes(StandardCharsets.UTF_8));
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(caPrivateKey);
        signature.update(hash);
        return signature.sign();
    }
    
    /**
     * 验证证书签名
     * 流程：重新计算证书哈希值 -> 使用CA公钥验证签名
     */
    public static boolean verifyCertificate(String certInfo, byte[] signature, PublicKey caPublicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(certInfo.getBytes(StandardCharsets.UTF_8));
        
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(caPublicKey);
        sig.update(hash);
        return sig.verify(signature);
    }
    
    // ========== AES-GCM加密 ==========
    
    /**
     * 从会话密钥派生AES密钥
     * 实际TLS中，会话密钥会被分割用于不同用途（加密、MAC等）
     */
    public static javax.crypto.SecretKey deriveAESKey(byte[] sessionKey) {
        byte[] aesKeyBytes = new byte[32];
        System.arraycopy(sessionKey, 0, aesKeyBytes, 0, 32);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }
    
    /**
     * AES-GCM加密
     * 返回加密数据和IV
     */
    public static EncryptedMessage encrypt(byte[] plaintext, javax.crypto.SecretKey key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        
        byte[] ciphertext = cipher.doFinal(plaintext);
        return new EncryptedMessage(ciphertext, iv);
    }
    
    /**
     * AES-GCM解密
     * 自动验证数据完整性，如果被篡改会抛出异常
     */
    public static byte[] decrypt(EncryptedMessage encrypted, javax.crypto.SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, encrypted.iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        
        return cipher.doFinal(encrypted.ciphertext);
    }
    
    // ========== 数据类 ==========
    
    /**
     * 封装加密消息（密文 + IV）
     */
    public static class EncryptedMessage {
        public final byte[] ciphertext;
        public final byte[] iv;
        
        public EncryptedMessage(byte[] ciphertext, byte[] iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }
    }
}
