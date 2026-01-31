package tls.demo;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * SignatureVerify.java
 * 
 * 演示数字证书和CA签名验证过程
 * 
 * 核心概念：
 * 1. CA（证书颁发机构）使用私钥对服务器证书进行签名
 * 2. 客户端使用CA的公钥验证签名
 * 3. 如果签名验证通过，说明证书确实由CA签发，服务器身份可信
 * 
 * 防止中间人攻击（MITM）：
 * - 攻击者无法伪造CA的签名（没有CA私钥）
 * - 即使攻击者截获通信，也无法冒充合法服务器
 * 
 * Java中的信任存储：
 * - cacerts文件位于 JRE/lib/security/cacerts
 * - 包含所有受信任的CA根证书
 * - 默认密码：changeit
 */
public class SignatureVerify {
    
    /**
     * 模拟CA：生成CA密钥对
     * 实际中，CA是受信任的第三方机构（如DigiCert, Let's Encrypt等）
     */
    public static KeyPair generateCAKeyPair() throws Exception {
        System.out.println("\n=== CA：生成密钥对 ===");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair caKeyPair = keyGen.generateKeyPair();
        
        System.out.println("✓ CA密钥对生成成功");
        System.out.println("  - CA私钥：用于签名证书（绝密，只有CA知道）");
        System.out.println("  - CA公钥：用于验证签名（公开，内置在操作系统中）");
        
        return caKeyPair;
    }
    
    /**
     * 模拟CA：对服务器证书信息进行签名
     * 
     * 实际流程：
     * 1. CA收集服务器信息（域名、公钥、有效期等）
     * 2. 生成证书结构（X.509格式）
     * 3. 计算证书的哈希值
     * 4. 使用CA私钥对哈希值进行签名
     * 5. 将签名附加到证书中
     * 
     * 数学原理：
     * - 签名 = Sign(Hash(证书内容), CA私钥)
     * - 验证 = Verify(签名, Hash(证书内容), CA公钥)
     */
    public static byte[] signCertificate(String serverInfo, PrivateKey caPrivateKey) throws Exception {
        System.out.println("\n=== CA：对服务器证书进行签名 ===");
        System.out.println("服务器信息：");
        System.out.println(serverInfo);
        
        // 步骤1：计算证书信息的哈希值
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] certificateHash = digest.digest(serverInfo.getBytes());
        
        System.out.println("\n步骤1：计算证书哈希值");
        System.out.println("  - 算法: SHA-256");
        System.out.println("  - 哈希值 (Base64): " + Base64.getEncoder().encodeToString(certificateHash));
        
        // 步骤2：使用CA私钥对哈希值进行签名
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(caPrivateKey);
        signature.update(certificateHash);
        byte[] digitalSignature = signature.sign();
        
        System.out.println("\n步骤2：使用CA私钥签名");
        System.out.println("  - 签名算法: SHA256withRSA");
        System.out.println("  - 签名长度: " + digitalSignature.length + " bytes");
        System.out.println("  - 签名 (Base64): " + Base64.getEncoder().encodeToString(digitalSignature));
        System.out.println("\n  数学原理：");
        System.out.println("  - 签名 = RSA_Encrypt(Hash(证书), CA私钥)");
        System.out.println("  - 只有拥有CA私钥的机构才能生成有效签名");
        
        return digitalSignature;
    }
    
    /**
     * 客户端：验证CA签名
     * 
     * 验证过程：
     * 1. 重新计算证书的哈希值
     * 2. 使用CA公钥解密签名，得到原始哈希值
     * 3. 比较两个哈希值是否相同
     * 4. 如果相同，说明证书确实由CA签发，未被篡改
     */
    public static boolean verifySignature(String serverInfo, byte[] signature, PublicKey caPublicKey) throws Exception {
        System.out.println("\n=== 客户端：验证CA签名 ===");
        
        // 步骤1：重新计算证书信息的哈希值
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] certificateHash = digest.digest(serverInfo.getBytes());
        
        System.out.println("步骤1：重新计算证书哈希值");
        System.out.println("  - 算法: SHA-256");
        System.out.println("  - 哈希值 (Base64): " + Base64.getEncoder().encodeToString(certificateHash));
        
        // 步骤2：使用CA公钥验证签名
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(caPublicKey);
        sig.update(certificateHash);
        boolean isValid = sig.verify(signature);
        
        System.out.println("\n步骤2：使用CA公钥验证签名");
        System.out.println("  - 验证算法: SHA256withRSA");
        System.out.println("  - CA公钥来源: 操作系统内置的cacerts文件");
        System.out.println("  - 验证结果: " + (isValid ? "✓ 签名有效" : "✗ 签名无效"));
        
        if (isValid) {
            System.out.println("\n  验证成功说明：");
            System.out.println("  1. 证书确实由CA签发（只有CA有私钥）");
            System.out.println("  2. 证书内容未被篡改（哈希值匹配）");
            System.out.println("  3. 服务器身份可信，可以安全通信");
        } else {
            System.out.println("\n  验证失败可能原因：");
            System.out.println("  1. 证书不是由CA签发的（可能是伪造的）");
            System.out.println("  2. 证书内容被篡改（哈希值不匹配）");
            System.out.println("  3. 中间人攻击！拒绝连接");
        }
        
        return isValid;
    }
    
    /**
     * 演示中间人攻击场景
     */
    public static void demonstrateMITM() throws Exception {
        System.out.println("\n=== 演示：中间人攻击防护 ===");
        
        // 真实CA
        KeyPair realCA = generateCAKeyPair();
        
        // 攻击者（试图冒充CA）
        KeyPair attackerCA = generateCAKeyPair();
        
        // 服务器信息
        String serverInfo = "CN=www.google.com, O=Google LLC, C=US";
        
        // 真实CA签名
        byte[] realSignature = signCertificate(serverInfo, realCA.getPrivate());
        
        // 攻击者试图用假CA签名
        byte[] fakeSignature = signCertificate(serverInfo, attackerCA.getPrivate());
        
        System.out.println("\n场景1：使用真实CA公钥验证真实签名");
        boolean result1 = verifySignature(serverInfo, realSignature, realCA.getPublic());
        System.out.println("结果: " + (result1 ? "✓ 验证通过，连接安全" : "✗ 验证失败"));
        
        System.out.println("\n场景2：使用真实CA公钥验证攻击者签名");
        boolean result2 = verifySignature(serverInfo, fakeSignature, realCA.getPublic());
        System.out.println("结果: " + (result2 ? "✗ 危险！验证通过（不应该发生）" : "✓ 验证失败，成功阻止攻击"));
        
        System.out.println("\n场景3：攻击者篡改证书内容");
        String tamperedInfo = "CN=evil.com, O=Attacker, C=XX";
        boolean result3 = verifySignature(tamperedInfo, realSignature, realCA.getPublic());
        System.out.println("结果: " + (result3 ? "✗ 危险！验证通过（不应该发生）" : "✓ 验证失败，成功检测篡改"));
        
        System.out.println("\n  中间人攻击防护机制：");
        System.out.println("  - 攻击者无法获得CA私钥，无法伪造有效签名");
        System.out.println("  - 即使攻击者截获通信，也无法冒充合法服务器");
        System.out.println("  - 客户端会检测到签名不匹配，拒绝连接");
    }
    
    /**
     * 演示Java中的cacerts文件
     */
    public static void demonstrateCacerts() {
        System.out.println("\n=== Java中的信任存储：cacerts文件 ===");
        System.out.println("位置：$JAVA_HOME/jre/lib/security/cacerts");
        System.out.println("默认密码：changeit");
        System.out.println("\n包含内容：");
        System.out.println("  - 所有受信任的CA根证书");
        System.out.println("  - 包括DigiCert, Let's Encrypt, GlobalSign等");
        System.out.println("  - 这些CA的公钥用于验证服务器证书");
        System.out.println("\n查看命令：");
        System.out.println("  keytool -list -keystore $JAVA_HOME/jre/lib/security/cacerts");
        System.out.println("\n重要性：");
        System.out.println("  - 这是Java信任所有合法证书的来源");
        System.out.println("  - 如果cacerts被篡改，可能导致安全风险");
        System.out.println("  - 生产环境应该定期更新cacerts");
    }
    
    /**
     * 完整演示流程
     */
    public static void main(String[] args) {
        try {
            System.out.println("╔════════════════════════════════════════════════════════════╗");
            System.out.println("║       数字证书与CA签名验证演示                             ║");
            System.out.println("╚════════════════════════════════════════════════════════════╝");
            
            // 步骤1：CA生成密钥对
            KeyPair caKeyPair = generateCAKeyPair();
            
            // 步骤2：服务器向CA申请证书
            String serverInfo = 
                "Certificate Information:\n" +
                "  Subject: CN=www.google.com\n" +
                "  Issuer: CN=DigiCert Global Root CA\n" +
                "  Public Key: RSA 2048-bit\n" +
                "  Valid From: 2024-01-01\n" +
                "  Valid To: 2025-01-01\n" +
                "  Serial Number: 1234567890";
            
            System.out.println("\n=== 服务器向CA申请证书 ===");
            System.out.println(serverInfo);
            
            // 步骤3：CA对证书进行签名
            byte[] signature = signCertificate(serverInfo, caKeyPair.getPrivate());
            
            // 步骤4：客户端验证签名
            boolean isValid = verifySignature(serverInfo, signature, caKeyPair.getPublic());
            
            if (isValid) {
                System.out.println("\n╔════════════════════════════════════════════════════════════╗");
                System.out.println("║           证书验证成功！服务器身份可信                      ║");
                System.out.println("║           可以安全地进行密钥交换和通信                        ║");
                System.out.println("╚════════════════════════════════════════════════════════════╝");
            }
            
            // 演示中间人攻击防护
            demonstrateMITM();
            
            // 演示cacerts
            demonstrateCacerts();
            
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
