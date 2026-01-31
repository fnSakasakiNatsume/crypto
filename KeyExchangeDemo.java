package tls.demo;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * KeyExchangeDemo.java
 * 
 * 演示TLS握手中的密钥交换过程（RSA方式）
 * 
 * 核心流程：
 * 1. 服务器生成RSA密钥对（公钥/私钥）
 * 2. 客户端生成Pre-Master Secret (PMS) - 一个48字节的随机数
 * 3. 客户端使用服务器公钥加密PMS：C ≡ PMS^e (mod n)
 * 4. 服务器使用私钥解密：PMS ≡ C^d (mod n)
 * 5. 双方现在都拥有PMS，可以生成相同的会话密钥
 * 
 * 数学原理：
 * - 加密：C = M^e mod n （M为PMS，e为公钥指数，n为模数）
 * - 解密：M = C^d mod n （d为私钥指数）
 * - 安全性：只有拥有私钥d的服务器才能解密
 */
public class KeyExchangeDemo {
    
    private static final int RSA_KEY_SIZE = 2048;
    private static final int PMS_SIZE = 48; // Pre-Master Secret标准长度
    
    /**
     * 模拟服务器端：生成RSA密钥对
     */
    public static KeyPair generateServerKeyPair() throws Exception {
        System.out.println("\n=== 服务器端：生成RSA密钥对 ===");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        
        System.out.println("✓ RSA密钥对生成成功");
        System.out.println("  - 密钥长度: " + RSA_KEY_SIZE + " bits");
        System.out.println("  - 公钥算法: RSA");
        System.out.println("  - 公钥格式: " + keyPair.getPublic().getFormat());
        
        return keyPair;
    }
    
    /**
     * 模拟客户端：生成Pre-Master Secret
     * Pre-Master Secret是一个48字节的随机数，包含：
     * - 2字节：TLS版本号
     * - 46字节：随机数
     */
    public static byte[] generatePreMasterSecret() {
        System.out.println("\n=== 客户端：生成Pre-Master Secret ===");
        SecureRandom random = new SecureRandom();
        byte[] pms = new byte[PMS_SIZE];
        random.nextBytes(pms);
        
        // 设置TLS版本号（前2字节）
        pms[0] = 0x03; // TLS 1.0+
        pms[1] = 0x03; // TLS 1.2
        
        System.out.println("✓ Pre-Master Secret生成成功");
        System.out.println("  - 长度: " + PMS_SIZE + " bytes");
        System.out.println("  - 前2字节（版本）: 0x" + String.format("%02x%02x", pms[0], pms[1]));
        System.out.println("  - Base64编码: " + Base64.getEncoder().encodeToString(pms));
        
        return pms;
    }
    
    /**
     * 模拟客户端：使用服务器公钥加密PMS
     * 数学公式：C ≡ PMS^e (mod n)
     */
    public static byte[] encryptPreMasterSecret(byte[] pms, java.security.PublicKey publicKey) throws Exception {
        System.out.println("\n=== 客户端：使用服务器公钥加密PMS ===");
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(pms);
        
        System.out.println("✓ PMS加密成功");
        System.out.println("  - 原始PMS长度: " + pms.length + " bytes");
        System.out.println("  - 加密后长度: " + encrypted.length + " bytes");
        System.out.println("  - 加密算法: RSA/ECB/PKCS1Padding");
        System.out.println("  - 加密数据(Base64): " + Base64.getEncoder().encodeToString(encrypted));
        System.out.println("\n  数学原理：C = PMS^e mod n");
        System.out.println("  - PMS: Pre-Master Secret (明文)");
        System.out.println("  - e: 公钥指数 (通常为65537)");
        System.out.println("  - n: RSA模数 (2048位)");
        System.out.println("  - C: 密文");
        
        return encrypted;
    }
    
    /**
     * 模拟服务器端：使用私钥解密PMS
     * 数学公式：PMS ≡ C^d (mod n)
     */
    public static byte[] decryptPreMasterSecret(byte[] encrypted, java.security.PrivateKey privateKey) throws Exception {
        System.out.println("\n=== 服务器端：使用私钥解密PMS ===");
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(encrypted);
        
        System.out.println("✓ PMS解密成功");
        System.out.println("  - 密文长度: " + encrypted.length + " bytes");
        System.out.println("  - 解密后长度: " + decrypted.length + " bytes");
        System.out.println("  - 解密算法: RSA/ECB/PKCS1Padding");
        System.out.println("  - 解密数据(Base64): " + Base64.getEncoder().encodeToString(decrypted));
        System.out.println("\n  数学原理：PMS = C^d mod n");
        System.out.println("  - C: 密文");
        System.out.println("  - d: 私钥指数 (只有服务器知道)");
        System.out.println("  - n: RSA模数");
        System.out.println("  - PMS: Pre-Master Secret (明文)");
        System.out.println("\n  安全性证明：");
        System.out.println("  - 只有拥有私钥d的服务器才能解密");
        System.out.println("  - 即使攻击者截获密文C，没有d也无法计算PMS");
        
        return decrypted;
    }
    
    /**
     * 生成会话密钥（简化版）
     * 实际TLS使用PRF（伪随机函数）结合R1, R2, PMS生成
     * 这里使用SHA-256作为简化演示
     */
    public static byte[] generateSessionKey(byte[] r1, byte[] r2, byte[] pms) throws Exception {
        System.out.println("\n=== 双方：生成会话密钥 ===");
        
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        digest.update(r1);
        digest.update(r2);
        digest.update(pms);
        byte[] sessionKey = digest.digest();
        
        System.out.println("✓ 会话密钥生成成功");
        System.out.println("  - 输入: R1 (Client Random) + R2 (Server Random) + PMS");
        System.out.println("  - 算法: SHA-256 (实际TLS使用PRF)");
        System.out.println("  - 会话密钥长度: " + sessionKey.length + " bytes (256 bits)");
        System.out.println("  - 会话密钥(Base64): " + Base64.getEncoder().encodeToString(sessionKey));
        System.out.println("\n  说明：");
        System.out.println("  - 客户端和服务器使用相同的R1, R2, PMS");
        System.out.println("  - 因此生成的会话密钥完全相同");
        System.out.println("  - 这个密钥将用于后续的对称加密通信");
        
        return sessionKey;
    }
    
    /**
     * 完整演示流程
     */
    public static void main(String[] args) {
        try {
            System.out.println("╔════════════════════════════════════════════════════════════╗");
            System.out.println("║        TLS 密钥交换演示 (RSA Key Exchange)                ║");
            System.out.println("╚════════════════════════════════════════════════════════════╝");
            
            // 步骤1: 服务器生成密钥对
            KeyPair serverKeyPair = generateServerKeyPair();
            
            // 步骤2: 生成随机数R1和R2（模拟Client Hello和Server Hello）
            SecureRandom random = new SecureRandom();
            byte[] r1 = new byte[32]; // Client Random
            byte[] r2 = new byte[32]; // Server Random
            random.nextBytes(r1);
            random.nextBytes(r2);
            System.out.println("\n=== Client Hello & Server Hello ===");
            System.out.println("✓ 客户端随机数 R1: " + Base64.getEncoder().encodeToString(r1));
            System.out.println("✓ 服务器随机数 R2: " + Base64.getEncoder().encodeToString(r2));
            
            // 步骤3: 客户端生成PMS
            byte[] pms = generatePreMasterSecret();
            
            // 步骤4: 客户端加密PMS
            byte[] encryptedPMS = encryptPreMasterSecret(pms, serverKeyPair.getPublic());
            
            // 步骤5: 服务器解密PMS
            byte[] decryptedPMS = decryptPreMasterSecret(encryptedPMS, serverKeyPair.getPrivate());
            
            // 步骤6: 验证解密结果
            System.out.println("\n=== 验证解密结果 ===");
            if (java.util.Arrays.equals(pms, decryptedPMS)) {
                System.out.println("✓ 解密成功！PMS完全匹配");
            } else {
                System.out.println("✗ 解密失败！PMS不匹配");
                return;
            }
            
            // 步骤7: 生成会话密钥
            byte[] sessionKey = generateSessionKey(r1, r2, pms);
            
            System.out.println("\n╔════════════════════════════════════════════════════════════╗");
            System.out.println("║              密钥交换完成！                                ║");
            System.out.println("║  双方现在拥有相同的会话密钥，可以开始安全通信              ║");
            System.out.println("╚════════════════════════════════════════════════════════════╝");
            
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
