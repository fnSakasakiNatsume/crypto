package tls.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * CipherSuite.java
 * 
 * 演示TLS中的对称加密（使用会话密钥）
 * 
 * 核心概念：
 * 1. 密钥交换完成后，双方拥有相同的会话密钥
 * 2. 使用对称加密算法（如AES-GCM）加密实际数据
 * 3. 对称加密比非对称加密快得多，适合大量数据传输
 * 
 * AES-GCM (Galois/Counter Mode) 特性：
 * - 提供加密和认证（Authenticated Encryption）
 * - 防止篡改和重放攻击
 * - TLS 1.2+推荐使用
 */
public class CipherSuite {
    
    private static final int AES_KEY_SIZE = 256; // 256位密钥
    private static final int GCM_IV_LENGTH = 12; // GCM IV标准长度
    private static final int GCM_TAG_LENGTH = 128; // GCM认证标签长度（位）
    
    /**
     * 从会话密钥生成AES密钥
     * 实际TLS中，会话密钥会被分割用于不同用途（加密、MAC等）
     */
    public static SecretKey deriveAESKey(byte[] sessionKey) {
        // 简化版：直接使用会话密钥的前32字节作为AES密钥
        byte[] aesKeyBytes = new byte[32];
        System.arraycopy(sessionKey, 0, aesKeyBytes, 0, 32);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }
    
    /**
     * 客户端：使用会话密钥加密HTTP报文
     */
    public static EncryptedData encryptHTTPMessage(String httpMessage, SecretKey key) throws Exception {
        System.out.println("\n=== 客户端：加密HTTP报文 ===");
        System.out.println("原始HTTP报文：");
        System.out.println(httpMessage);
        
        // 生成随机IV（初始化向量）
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        // 初始化AES-GCM加密器
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        
        // 加密数据
        byte[] plaintext = httpMessage.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        System.out.println("\n✓ 加密完成");
        System.out.println("  - 加密算法: AES-256-GCM");
        System.out.println("  - IV长度: " + iv.length + " bytes");
        System.out.println("  - 原始长度: " + plaintext.length + " bytes");
        System.out.println("  - 密文长度: " + ciphertext.length + " bytes");
        System.out.println("  - IV (Base64): " + Base64.getEncoder().encodeToString(iv));
        System.out.println("  - 密文 (Base64): " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("\n  AES-GCM特性：");
        System.out.println("  - 提供加密和认证（Authenticated Encryption）");
        System.out.println("  - 密文包含认证标签，防止篡改");
        System.out.println("  - 每次加密使用不同的IV，确保相同明文产生不同密文");
        
        return new EncryptedData(ciphertext, iv);
    }
    
    /**
     * 服务器端：使用会话密钥解密HTTP报文
     */
    public static String decryptHTTPMessage(EncryptedData encryptedData, SecretKey key) throws Exception {
        System.out.println("\n=== 服务器端：解密HTTP报文 ===");
        
        // 初始化AES-GCM解密器
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, encryptedData.iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        
        // 解密数据
        byte[] plaintext = cipher.doFinal(encryptedData.ciphertext);
        String httpMessage = new String(plaintext, StandardCharsets.UTF_8);
        
        System.out.println("✓ 解密完成");
        System.out.println("  - 解密算法: AES-256-GCM");
        System.out.println("  - 密文长度: " + encryptedData.ciphertext.length + " bytes");
        System.out.println("  - 解密后长度: " + plaintext.length + " bytes");
        System.out.println("\n解密后的HTTP报文：");
        System.out.println(httpMessage);
        System.out.println("\n  安全性说明：");
        System.out.println("  - GCM模式自动验证数据完整性");
        System.out.println("  - 如果密文被篡改，解密会抛出异常");
        System.out.println("  - 只有拥有正确密钥的服务器才能解密");
        
        return httpMessage;
    }
    
    /**
     * 演示完整的加密/解密流程
     */
    public static void main(String[] args) {
        try {
            System.out.println("╔════════════════════════════════════════════════════════════╗");
            System.out.println("║        TLS 对称加密演示 (AES-GCM Cipher Suite)             ║");
            System.out.println("╚════════════════════════════════════════════════════════════╝");
            
            // 模拟从密钥交换获得的会话密钥
            System.out.println("\n=== 前提：密钥交换已完成 ===");
            System.out.println("假设双方已经通过密钥交换获得了相同的会话密钥");
            
            // 生成一个示例会话密钥（实际中来自KeyExchangeDemo）
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE);
            SecretKey sessionKey = keyGen.generateKey();
            System.out.println("会话密钥 (Base64): " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
            
            // 从会话密钥派生AES密钥
            SecretKey aesKey = deriveAESKey(sessionKey.getEncoded());
            
            // 模拟HTTP请求报文
            String httpRequest = 
                "GET /search?q=TLS+handshake HTTP/1.1\r\n" +
                "Host: www.google.com\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Accept: text/html\r\n" +
                "\r\n";
            
            // 客户端加密
            EncryptedData encrypted = encryptHTTPMessage(httpRequest, aesKey);
            
            // 服务器解密
            String decrypted = decryptHTTPMessage(encrypted, aesKey);
            
            // 验证
            System.out.println("\n=== 验证结果 ===");
            if (httpRequest.equals(decrypted)) {
                System.out.println("✓ 解密成功！数据完全匹配");
            } else {
                System.out.println("✗ 解密失败！数据不匹配");
            }
            
            // 演示篡改检测
            System.out.println("\n=== 演示：篡改检测 ===");
            try {
                byte[] tamperedCiphertext = encrypted.ciphertext.clone();
                tamperedCiphertext[0] ^= 1; // 修改一个字节
                EncryptedData tampered = new EncryptedData(tamperedCiphertext, encrypted.iv);
                decryptHTTPMessage(tampered, aesKey);
                System.out.println("✗ 错误：篡改未被检测到！");
            } catch (Exception e) {
                System.out.println("✓ 篡改被成功检测到！");
                System.out.println("  错误信息: " + e.getMessage());
            }
            
            System.out.println("\n╔════════════════════════════════════════════════════════════╗");
            System.out.println("║              对称加密演示完成！                             ║");
            System.out.println("║  AES-GCM提供了加密和认证，确保数据机密性和完整性           ║");
            System.out.println("╚════════════════════════════════════════════════════════════╝");
            
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 封装加密数据和IV
     */
    public static class EncryptedData {
        public final byte[] ciphertext;
        public final byte[] iv;
        
        public EncryptedData(byte[] ciphertext, byte[] iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }
    }
}
