package tls.demo;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;

public class TLSHandshakeSimulator {

    // 用于读取用户按键
    private static Scanner scanner = new Scanner(System.in);

    /**
     * 交互式暂停：等待用户按回车
     */
    private static void step(String stepTitle) {
        System.out.println("\n\n"); // 打印空行，制造视觉隔离
        System.out.println("================================================================");
        System.out.println("即将执行: [" + stepTitle + "]");
        System.out.print(">>> 请按 [回车键] 继续...");
        scanner.nextLine(); // 等待输入
        System.out.println("----------------------------------------------------------------");
    }

    public static void simulateTLSHandshake() throws Exception {
        System.out.println("################################################################");
        System.out.println("#              TLS 握手模拟器 (交互演示版)                     #");
        System.out.println("################################################################");

        // ========== 步骤 1: 握手协商 ==========
        step("1. Client Hello & Server Hello (协商算法)");
        
        SecureRandom random = new SecureRandom();
        byte[] clientRandom = new byte[32]; random.nextBytes(clientRandom);
        byte[] serverRandom = new byte[32]; random.nextBytes(serverRandom);

        System.out.println("[Client] 发送 Hello:");
        System.out.println("  - TLS版本: TLS 1.2");
        System.out.println("  - 加密套件: TLS_RSA_WITH_AES_256_GCM");
        System.out.println("  - 随机数(R1): " + shortHex(clientRandom));
        
        System.out.println("\n[Server] 回复 Hello:");
        System.out.println("  - 确认算法: AES_256_GCM");
        System.out.println("  - 随机数(R2): " + shortHex(serverRandom));
        System.out.println("\n✓ 第一步完成：双方确认了算法，交换了随机数。");


        // ========== 步骤 2: 证书验证 ==========
        step("2. Server Certificate (身份认证)");
        
        // 生成模拟证书数据（不调用 verbose 的方法，只做逻辑）
        KeyPair caKeyPair = SignatureVerify.generateCAKeyPair(); 
        // 注意：这里为了不刷屏，我们不再打印 SignatureVerify 内部的日志
        // 如果那些类里的 System.out.println 还在，控制台还是会输出。
        // 为了演示效果，我们尽量用这一行概括：
        System.out.println("[Server] 发送数字证书 (包含公钥)...");
        
        String serverInfo = "CN=www.google.com";
        byte[] signature = SignatureVerify.signCertificate(serverInfo, caKeyPair.getPrivate());
        System.out.println("[Client] 收到证书，正在验证 CA 签名...");
        
        boolean certValid = SignatureVerify.verifySignature(serverInfo, signature, caKeyPair.getPublic());
        if (certValid) {
            System.out.println("✓ 验证通过：证书是由可信 CA 签发的。");
        } else {
            System.out.println("✗ 验证失败：危险！");
            return;
        }

        // ========== 步骤 3: 密钥交换 ==========
        step("3. Key Exchange (交换核心机密)");
        
        // 1. 生成 PMS
        byte[] pms = new byte[48]; 
        random.nextBytes(pms);
        System.out.println("[Client] 生成 Pre-Master Secret (PMS): " + shortHex(pms));
        
        // 2. 获取服务器公钥（这里我们模拟生成一个）
        KeyPair serverKP = KeyExchangeDemo.generateServerKeyPair();
        
        // 3. 加密 PMS
        byte[] encryptedPMS = KeyExchangeDemo.encryptPreMasterSecret(pms, serverKP.getPublic());
        System.out.println("[Client] 使用服务器公钥加密 PMS -> 发送密文 [" + encryptedPMS.length + " bytes]");
        
        // 4. 服务器解密
        byte[] decryptedPMS = KeyExchangeDemo.decryptPreMasterSecret(encryptedPMS, serverKP.getPrivate());
        System.out.println("[Server] 使用私钥解密得到 PMS: " + shortHex(decryptedPMS));
        
        if (java.util.Arrays.equals(pms, decryptedPMS)) {
            System.out.println("\n✓ 第三步完成：双方安全共享了 PMS，且未在网络上明文传输。");
        }


        // ========== 步骤 4: 生成会话密钥 ==========
        step("4. Generate Session Key (生成会话密钥)");
        
        // 模拟计算过程
        System.out.println("算法公式: SessionKey = PRF(PMS + R1 + R2)");
        byte[] sessionKey = KeyExchangeDemo.generateSessionKey(clientRandom, serverRandom, pms);
        
        System.out.println(">>> [Client] 计算出会话密钥: " + Base64.getEncoder().encodeToString(sessionKey).substring(0, 20) + "...");
        System.out.println(">>> [Server] 计算出会话密钥: " + Base64.getEncoder().encodeToString(sessionKey).substring(0, 20) + "...");
        System.out.println("\n✓ 第四步完成：握手结束，准备切换到加密通信。");


        // ========== 步骤 5: 加密通信演示 ==========
        step("5. Encrypted Data Transfer (加密通信)");
        
        SecretKey aesKey = CipherSuite.deriveAESKey(sessionKey);
        String msg = "GET /account/balance HTTP/1.1";
        
        System.out.println("[Client] 原始请求: \"" + msg + "\"");
        
        // 加密
        CipherSuite.EncryptedData encData = CipherSuite.encryptHTTPMessage(msg, aesKey);
        System.out.println("[Network] 传输密文: " + Base64.getEncoder().encodeToString(encData.ciphertext));
        
        // 解密
        String decryptedMsg = CipherSuite.decryptHTTPMessage(encData, aesKey);
        System.out.println("[Server] 解密收到: \"" + decryptedMsg + "\"");
        
        System.out.println("\n################################################################");
        System.out.println("#                  演示结束 (Demo Finished)                    #");
        System.out.println("################################################################");
    }

    // 辅助工具：截断显示过长的 Hex 字符串
    private static String shortHex(byte[] data) {
        String s = Base64.getEncoder().encodeToString(data);
        return s.length() > 15 ? s.substring(0, 15) + "..." : s;
    }

    public static void main(String[] args) {
        try {
            simulateTLSHandshake();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}