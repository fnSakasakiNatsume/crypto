package tls.demo;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * TLSHandshakeSimulator.java
 * 
 * TLS握手完整流程模拟器
 * 
 * 整合所有模块，演示完整的TLS握手过程：
 * 1. Client Hello & Server Hello - 协商算法，交换随机数
 * 2. Server Certificate - 服务器出示证书
 * 3. Certificate Verification - 客户端验证证书
 * 4. Key Exchange - Pre-Master Secret交换
 * 5. Session Key Generation - 生成会话密钥
 * 6. Encrypted Communication - 使用会话密钥加密通信
 * 
 * 扩展话题：
 * - TLS 1.3改进
 * - 前向安全性
 * - 性能优化
 */
public class TLSHandshakeSimulator {
    
    /**
     * 模拟完整的TLS握手流程
     */
    public static void simulateTLSHandshake() throws Exception {
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    TLS 握手完整流程模拟                                        ║");
        System.out.println("║                    Complete TLS Handshake Simulation                         ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
        
        // ========== 阶段1: Client Hello & Server Hello ==========
        System.out.println("\n");
        System.out.println("┌──────────────────────────────────────────────────────────────────────────────┐");
        System.out.println("│ 阶段 1: Client Hello & Server Hello                                        │");
        System.out.println("└──────────────────────────────────────────────────────────────────────────────┘");
        
        System.out.println("\n[客户端] → [服务器]");
        System.out.println("Client Hello:");
        System.out.println("  - TLS Version: 1.2");
        System.out.println("  - Cipher Suites: TLS_RSA_WITH_AES_256_GCM_SHA384");
        System.out.println("  - Compression: null");
        System.out.println("  - Extensions: Server Name Indication (SNI)");
        
        SecureRandom random = new SecureRandom();
        byte[] clientRandom = new byte[32];
        random.nextBytes(clientRandom);
        System.out.println("  - Client Random (R1): " + Base64.getEncoder().encodeToString(clientRandom));
        
        System.out.println("\n[服务器] → [客户端]");
        System.out.println("Server Hello:");
        System.out.println("  - TLS Version: 1.2");
        System.out.println("  - Selected Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384");
        System.out.println("  - Compression: null");
        
        byte[] serverRandom = new byte[32];
        random.nextBytes(serverRandom);
        System.out.println("  - Server Random (R2): " + Base64.getEncoder().encodeToString(serverRandom));
        
        System.out.println("\n✓ 双方已协商好加密算法和版本");
        System.out.println("✓ 双方已交换随机数 R1 和 R2");
        
        // ========== 阶段2: Server Certificate ==========
        System.out.println("\n");
        System.out.println("┌──────────────────────────────────────────────────────────────────────────────┐");
        System.out.println("│ 阶段 2: Server Certificate                                                  │");
        System.out.println("└──────────────────────────────────────────────────────────────────────────────┘");
        
        System.out.println("\n[服务器] → [客户端]");
        System.out.println("Server Certificate:");
        System.out.println("  - Subject: CN=www.google.com");
        System.out.println("  - Issuer: CN=DigiCert Global Root CA");
        System.out.println("  - Public Key: RSA 2048-bit");
        System.out.println("  - Valid From: 2024-01-01");
        System.out.println("  - Valid To: 2025-01-01");
        System.out.println("  - Signature Algorithm: SHA256withRSA");
        
        // 生成服务器密钥对（模拟证书中的公钥）
        KeyPair serverKeyPair = KeyExchangeDemo.generateServerKeyPair();
        
        // ========== 阶段3: Certificate Verification ==========
        System.out.println("\n");
        System.out.println("┌──────────────────────────────────────────────────────────────────────────────┐");
        System.out.println("│ 阶段 3: Certificate Verification (证书验证)                                 │");
        System.out.println("└──────────────────────────────────────────────────────────────────────────────┘");
        
        System.out.println("\n[客户端] 验证证书:");
        System.out.println("  1. 检查证书是否过期");
        System.out.println("  2. 检查证书域名是否匹配");
        System.out.println("  3. 验证CA签名");
        
        // 模拟证书验证
        String serverInfo = "CN=www.google.com, O=Google LLC, C=US";
        KeyPair caKeyPair = SignatureVerify.generateCAKeyPair();
        byte[] signature = SignatureVerify.signCertificate(serverInfo, caKeyPair.getPrivate());
        boolean certValid = SignatureVerify.verifySignature(serverInfo, signature, caKeyPair.getPublic());
        
        if (certValid) {
            System.out.println("\n✓ 证书验证通过！服务器身份可信");
        } else {
            System.out.println("\n✗ 证书验证失败！拒绝连接");
            return;
        }
        
        // ========== 阶段4: Key Exchange ==========
        System.out.println("\n");
        System.out.println("┌──────────────────────────────────────────────────────────────────────────────┐");
        System.out.println("│ 阶段 4: Key Exchange (密钥交换)                                             │");
        System.out.println("└──────────────────────────────────────────────────────────────────────────────┘");
        
        // 生成Pre-Master Secret
        byte[] pms = KeyExchangeDemo.generatePreMasterSecret();
        
        // 客户端加密PMS
        byte[] encryptedPMS = KeyExchangeDemo.encryptPreMasterSecret(pms, serverKeyPair.getPublic());
        
        // 服务器解密PMS
        byte[] decryptedPMS = KeyExchangeDemo.decryptPreMasterSecret(encryptedPMS, serverKeyPair.getPrivate());
        
        // 验证
        if (!java.util.Arrays.equals(pms, decryptedPMS)) {
            System.out.println("\n✗ 密钥交换失败！");
            return;
        }
        
        // ========== 阶段5: Session Key Generation ==========
        System.out.println("\n");
        System.out.println("┌──────────────────────────────────────────────────────────────────────────────┐");
        System.out.println("│ 阶段 5: Session Key Generation (会话密钥生成)                                │");
        System.out.println("└──────────────────────────────────────────────────────────────────────────────┘");
        
        byte[] sessionKey = KeyExchangeDemo.generateSessionKey(clientRandom, serverRandom, pms);
        
        // ========== 阶段6: Change Cipher Spec & Finished ==========
        System.out.println("\n");
        System.out.println("┌──────────────────────────────────────────────────────────────────────────────┐");
        System.out.println("│ 阶段 6: Change Cipher Spec & Finished                                       │");
        System.out.println("└──────────────────────────────────────────────────────────────────────────────┘");
        
        System.out.println("\n[客户端] → [服务器]");
        System.out.println("Change Cipher Spec: 切换到加密模式");
        System.out.println("Finished: 使用会话密钥加密的握手完成消息");
        
        System.out.println("\n[服务器] → [客户端]");
        System.out.println("Change Cipher Spec: 切换到加密模式");
        System.out.println("Finished: 使用会话密钥加密的握手完成消息");
        
        System.out.println("\n✓ 握手完成！双方已切换到加密通信模式");
        
        // ========== 阶段7: Encrypted Communication ==========
        System.out.println("\n");
        System.out.println("┌──────────────────────────────────────────────────────────────────────────────┐");
        System.out.println("│ 阶段 7: Encrypted Communication (加密通信)                                    │");
        System.out.println("└──────────────────────────────────────────────────────────────────────────────┘");
        
        // 使用会话密钥进行加密通信
        javax.crypto.SecretKey aesKey = CipherSuite.deriveAESKey(sessionKey);
        String httpRequest = 
            "GET /search?q=TLS+handshake HTTP/1.1\r\n" +
            "Host: www.google.com\r\n" +
            "User-Agent: Mozilla/5.0\r\n" +
            "\r\n";
        
        CipherSuite.EncryptedData encrypted = CipherSuite.encryptHTTPMessage(httpRequest, aesKey);
        String decrypted = CipherSuite.decryptHTTPMessage(encrypted, aesKey);
        
        if (httpRequest.equals(decrypted)) {
            System.out.println("\n✓ 加密通信正常！数据完整传输");
        }
        
        // ========== 总结 ==========
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                          TLS 握手完成！                                       ║");
        System.out.println("║                                                                              ║");
        System.out.println("║  关键要点：                                                                  ║");
        System.out.println("║  1. 非对称加密（RSA）用于安全交换对称密钥                                    ║");
        System.out.println("║  2. 对称加密（AES-GCM）用于高效加密实际数据                                  ║");
        System.out.println("║  3. 数字证书和CA签名防止中间人攻击                                            ║");
        System.out.println("║  4. 会话密钥由双方随机数和PMS共同生成，确保唯一性                            ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
    }
    
    /**
     * 演示TLS 1.3的改进
     */
    public static void demonstrateTLS13() {
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    TLS 1.3 改进特性                                          ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
        
        System.out.println("\n1. 强制使用ECDHE（椭圆曲线Diffie-Hellman）");
        System.out.println("   - 删除RSA密钥交换（RSA Key Exchange）");
        System.out.println("   - 提供前向安全性（Forward Secrecy）");
        System.out.println("   - 即使服务器私钥泄露，历史通信仍安全");
        
        System.out.println("\n2. 0-RTT（零往返时间）握手");
        System.out.println("   - 利用Session Ticket实现快速重连");
        System.out.println("   - 第二次连接无需完整握手");
        System.out.println("   - 显著降低延迟");
        
        System.out.println("\n3. 更快的握手速度");
        System.out.println("   - 减少往返次数（从2次减少到1次）");
        System.out.println("   - 更少的加密操作");
        System.out.println("   - 更短的握手时间");
        
        System.out.println("\n4. 更强的加密算法");
        System.out.println("   - 移除不安全的算法（如RC4, MD5, SHA-1）");
        System.out.println("   - 强制使用AEAD（Authenticated Encryption）");
        System.out.println("   - 默认使用ChaCha20-Poly1305或AES-GCM");
        
        System.out.println("\n5. 更好的安全性");
        System.out.println("   - 握手消息本身也加密");
        System.out.println("   - 防止握手过程中的信息泄露");
    }
    
    /**
     * 演示前向安全性
     */
    public static void demonstrateForwardSecrecy() {
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    前向安全性 (Forward Secrecy)                             ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
        
        System.out.println("\n问题场景：");
        System.out.println("  假设攻击者长期监控网络，记录所有加密通信");
        System.out.println("  如果服务器私钥在未来某天泄露，攻击者能否解密历史通信？");
        
        System.out.println("\n传统RSA密钥交换：");
        System.out.println("  ✗ 没有前向安全性");
        System.out.println("  - 所有会话的PMS都用同一个服务器公钥加密");
        System.out.println("  - 一旦私钥泄露，所有历史通信都能被解密");
        
        System.out.println("\nECDHE/DHE密钥交换：");
        System.out.println("  ✓ 提供前向安全性");
        System.out.println("  - 每次握手都生成新的临时密钥对");
        System.out.println("  - 会话密钥由临时密钥计算，不依赖服务器长期私钥");
        System.out.println("  - 即使服务器长期私钥泄露，历史通信仍安全");
        
        System.out.println("\n数学原理（ECDHE）：");
        System.out.println("  1. 服务器生成临时密钥对 (d_server, Q_server = d_server * G)");
        System.out.println("  2. 客户端生成临时密钥对 (d_client, Q_client = d_client * G)");
        System.out.println("  3. 双方交换公钥 Q_server 和 Q_client");
        System.out.println("  4. 共享密钥 = d_server * Q_client = d_client * Q_server");
        System.out.println("  5. 会话密钥从共享密钥派生");
        System.out.println("  6. 握手结束后，临时私钥被销毁");
        
        System.out.println("\n为什么安全：");
        System.out.println("  - 临时私钥只存在于内存中，握手后立即销毁");
        System.out.println("  - 即使攻击者记录所有通信，也无法恢复临时私钥");
        System.out.println("  - 即使服务器长期私钥泄露，也无法解密历史通信");
    }
    
    /**
     * Java后端开发实践
     */
    public static void demonstrateJavaBackend() {
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    Java 后端开发实践                                         ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
        
        System.out.println("\n1. Spring Boot SSL配置 (application.properties):");
        System.out.println("   server.ssl.key-store=classpath:keystore.jks");
        System.out.println("   server.ssl.key-store-password=changeit");
        System.out.println("   server.ssl.key-store-type=JKS");
        System.out.println("   server.ssl.key-alias=tomcat");
        System.out.println("   server.port=8443");
        
        System.out.println("\n2. 常见错误：SSLHandshakeException");
        System.out.println("   原因：");
        System.out.println("     - 证书过期");
        System.out.println("     - 证书不被信任（不在cacerts中）");
        System.out.println("     - 证书域名不匹配");
        System.out.println("     - 证书链不完整");
        System.out.println("   解决方法：");
        System.out.println("     - 检查证书有效期");
        System.out.println("     - 将CA证书添加到cacerts");
        System.out.println("     - 使用keytool导入证书");
        
        System.out.println("\n3. 证书管理命令：");
        System.out.println("   # 查看cacerts中的证书");
        System.out.println("   keytool -list -keystore $JAVA_HOME/jre/lib/security/cacerts");
        System.out.println("   # 导入证书");
        System.out.println("   keytool -import -alias myca -file ca.crt -keystore cacerts");
        System.out.println("   # 生成自签名证书");
        System.out.println("   keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -keystore keystore.jks");
        
        System.out.println("\n4. 性能优化建议：");
        System.out.println("   - 使用TLS 1.3（更快的握手）");
        System.out.println("   - 启用Session Resumption（减少握手次数）");
        System.out.println("   - 使用硬件加速（如果可用）");
        System.out.println("   - 合理配置连接池");
    }
    
    /**
     * 主函数
     */
    public static void main(String[] args) {
        try {
            // 完整握手流程
            simulateTLSHandshake();
            
            // TLS 1.3改进
            demonstrateTLS13();
            
            // 前向安全性
            demonstrateForwardSecrecy();
            
            // Java后端实践
            demonstrateJavaBackend();
            
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
