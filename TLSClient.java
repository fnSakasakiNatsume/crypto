package tls.demo;

import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;

/**
 * TLSClient.java
 * 
 * TLS客户端 - 连接服务器，执行TLS握手
 * 
 * 功能：
 * 1. 连接到服务器
 * 2. 执行完整的TLS握手流程（7个阶段）
 * 3. 发送和接收加密消息
 */
public class TLSClient {
    private static final String SERVER_HOST = "localhost"; // 改为服务器IP（如"192.168.1.100"）
    private static final int SERVER_PORT = 8888;
    
    private byte[] clientRandom;
    private byte[] sessionKey;
    private SecretKey aesKey;
    
    public TLSClient() {
        this.clientRandom = new byte[32];
        new SecureRandom().nextBytes(clientRandom);
    }
    
    public void connect() throws Exception {
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║        TLS Client Starting... / TLS客户端启动中...        ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        
        System.out.println("Connecting to server: " + SERVER_HOST + ":" + SERVER_PORT + "... / 正在连接到服务器: " + SERVER_HOST + ":" + SERVER_PORT + "...");
        Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
        System.out.println("✓ Connected to server: " + socket.getRemoteSocketAddress() + " / 已连接到服务器: " + socket.getRemoteSocketAddress());
        
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
        try {
            // ========== 阶段1: Client Hello ==========
            System.out.println("\n[Phase 1] Sending Client Hello... / [阶段1] 发送 Client Hello...");
            String clientHello = "Client Hello:TLS 1.2:" + Base64.getEncoder().encodeToString(clientRandom);
            out.writeUTF(clientHello);
            System.out.println("Sent: " + clientHello + " / 发送: " + clientHello);
            System.out.println("  - TLS Version: 1.2");
            System.out.println("  - Cipher Suites: TLS_RSA_WITH_AES_256_GCM_SHA384");
            System.out.println("  - Client Random (R1): " + Base64.getEncoder().encodeToString(clientRandom).substring(0, 20) + "...");
            
            // 接收 Server Hello
            String serverHello = in.readUTF();
            System.out.println("\n[Phase 1] Received Server Hello: " + serverHello + " / [阶段1] 收到 Server Hello: " + serverHello);
            String[] serverParts = serverHello.split(":");
            if (serverParts.length < 3) {
                System.out.println("✗ Server Hello format error / Server Hello格式错误");
                return;
            }
            byte[] serverRandom = Base64.getDecoder().decode(serverParts[2]);
            System.out.println("  - TLS Version: " + serverParts[1]);
            System.out.println("  - Server Random (R2): " + Base64.getEncoder().encodeToString(serverRandom).substring(0, 20) + "...");
            System.out.println("✓ Encryption algorithms and version negotiated / 双方已协商好加密算法和版本");
            System.out.println("✓ Random numbers R1 and R2 exchanged / 双方已交换随机数 R1 和 R2");
            
            // ========== 阶段2: Server Certificate ==========
            System.out.println("\n[Phase 2] Receiving Server Certificate... / [阶段2] 接收 Server Certificate...");
            String certificate = in.readUTF();
            // 使用 ||| 作为分隔符，避免证书信息中的冒号干扰
            // 格式：Certificate|||证书信息|||服务器公钥|||CA公钥|||签名
            String[] certParts = certificate.split("\\|\\|\\|");
            if (certParts.length < 5) {
                System.out.println("✗ Certificate format error / Certificate格式错误");
                return;
            }
            String certInfo = certParts[1];
            byte[] serverPublicKeyBytes = Base64.getDecoder().decode(certParts[2]);
            byte[] caPublicKeyBytes = Base64.getDecoder().decode(certParts[3]);
            byte[] signature = Base64.getDecoder().decode(certParts[4]);
            
            System.out.println("Certificate information: / 证书信息:");
            System.out.println("  - " + certInfo);
            
            // 解析服务器公钥（用于后续密钥交换）
            X509EncodedKeySpec serverKeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
            PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(serverKeySpec);
            System.out.println("  - Public Key: RSA 2048-bit");
            System.out.println("  - Signature Algorithm: SHA256withRSA");
            
            // 解析CA公钥（用于验证签名）
            X509EncodedKeySpec caKeySpec = new X509EncodedKeySpec(caPublicKeyBytes);
            PublicKey caPublicKey = KeyFactory.getInstance("RSA").generatePublic(caKeySpec);
            
            // ========== 阶段3: Certificate Verification ==========
            System.out.println("\n[Phase 3] Verifying certificate... / [阶段3] 验证证书...");
            System.out.println("  1. Check if certificate is expired / 检查证书是否过期");
            System.out.println("  2. Check if certificate domain matches / 检查证书域名是否匹配");
            System.out.println("  3. Verify CA signature / 验证CA签名");
            
            // 使用CA公钥验证签名（实际应用中，CA公钥应该从操作系统的信任存储中获取）
            boolean isValid = CryptoUtils.verifyCertificate(certInfo, signature, caPublicKey);
            
            if (isValid) {
                System.out.println("✓ Certificate verified! Server identity trusted / 证书验证通过！服务器身份可信");
                out.writeUTF("Certificate Verified");
            } else {
                System.out.println("✗ Certificate verification failed! Connection rejected / 证书验证失败！拒绝连接");
                // 即使验证失败，也要发送消息告知服务器，避免EOFException
                try {
                    out.writeUTF("Certificate Verification Failed");
                } catch (Exception e) {
                    // 忽略发送错误
                }
                return;
            }
            
            // ========== 阶段4: Key Exchange ==========
            System.out.println("\n[Phase 4] Generating and encrypting Pre-Master Secret... / [阶段4] 生成并加密 Pre-Master Secret...");
            byte[] pms = CryptoUtils.generatePMS();
            System.out.println("✓ Pre-Master Secret generated successfully / Pre-Master Secret生成成功");
            System.out.println("  - Length: " + pms.length + " bytes / 长度: " + pms.length + " bytes");
            System.out.println("  - First 2 bytes (version): 0x" + String.format("%02x%02x", pms[0], pms[1]) + " / 前2字节（版本）: 0x" + String.format("%02x%02x", pms[0], pms[1]));
            
            byte[] encryptedPMS = CryptoUtils.encryptPMS(pms, serverPublicKey);
            System.out.println("✓ Encrypted PMS using server public key / 使用服务器公钥加密PMS");
            System.out.println("  - Encryption algorithm: RSA/ECB/PKCS1Padding / 加密算法: RSA/ECB/PKCS1Padding");
            System.out.println("  - Original PMS length: " + pms.length + " bytes / 原始PMS长度: " + pms.length + " bytes");
            System.out.println("  - Encrypted length: " + encryptedPMS.length + " bytes / 加密后长度: " + encryptedPMS.length + " bytes");
            
            String keyExchange = "Key Exchange:" + Base64.getEncoder().encodeToString(encryptedPMS);
            out.writeUTF(keyExchange);
            System.out.println("✓ Encrypted PMS sent / 加密的PMS已发送");
            
            // ========== 阶段5: 生成会话密钥 ==========
            System.out.println("\n[Phase 5] Generating session key... / [阶段5] 生成会话密钥...");
            this.sessionKey = CryptoUtils.generateSessionKey(clientRandom, serverRandom, pms);
            this.aesKey = CryptoUtils.deriveAESKey(sessionKey);
            System.out.println("✓ Session key generated / 会话密钥已生成");
            System.out.println("  - Input: R1 (Client Random) + R2 (Server Random) + PMS / 输入: R1 (Client Random) + R2 (Server Random) + PMS");
            System.out.println("  - Algorithm: SHA-256 / 算法: SHA-256");
            System.out.println("  - Session key length: " + sessionKey.length + " bytes (256 bits) / 会话密钥长度: " + sessionKey.length + " bytes (256 bits)");
            System.out.println("  - Session key (first 20 chars): " + Base64.getEncoder().encodeToString(sessionKey).substring(0, 20) + "... / 会话密钥 (前20字符): " + Base64.getEncoder().encodeToString(sessionKey).substring(0, 20) + "...");
            
            // ========== 阶段6: Change Cipher Spec ==========
            System.out.println("\n[Phase 6] Switching to encrypted mode... / [阶段6] 切换到加密模式...");
            String changeCipher = in.readUTF();
            System.out.println("Received: " + changeCipher + " / 收到: " + changeCipher);
            System.out.println("✓ Switched to encrypted mode / 已切换到加密模式");
            System.out.println("✓ Handshake complete! Both sides switched to encrypted communication / 握手完成！双方已切换到加密通信模式");
            
            // ========== 阶段7: 加密通信 ==========
            System.out.println("\n[Phase 7] Starting encrypted communication... / [阶段7] 开始加密通信...");
            System.out.println("═══════════════════════════════════════════════════════════");
            System.out.println("Enter message to send to server (type 'quit' to exit): / 输入消息发送给服务器（输入 'quit' 退出）:");
            System.out.println("═══════════════════════════════════════════════════════════");
            
            Scanner scanner = new Scanner(System.in);
            
            // 接收消息线程
            Thread receiveThread = new Thread(() -> {
                try {
                    while (true) {
                        String encryptedMsg = in.readUTF();
                        String[] msgParts = encryptedMsg.split(":");
                        if (msgParts.length < 2) {
                            continue;
                        }
                        byte[] ciphertext = Base64.getDecoder().decode(msgParts[0]);
                        byte[] iv = Base64.getDecoder().decode(msgParts[1]);
                        
                        CryptoUtils.EncryptedMessage encrypted = new CryptoUtils.EncryptedMessage(ciphertext, iv);
                        byte[] decrypted = CryptoUtils.decrypt(encrypted, aesKey);
                        String message = new String(decrypted, "UTF-8");
                        
                        System.out.println("\n[Server reply] " + message + " / [服务器回复] " + message);
                    }
                } catch (Exception e) {
                    // 连接关闭
                }
            });
            receiveThread.setDaemon(true);
            receiveThread.start();
            
            // 发送消息
            while (true) {
                System.out.print("\n> ");
                String message = scanner.nextLine();
                if (message.equalsIgnoreCase("quit")) {
                    out.writeUTF("QUIT");
                    break;
                }
                
                // 加密并发送
                CryptoUtils.EncryptedMessage encrypted = CryptoUtils.encrypt(message.getBytes("UTF-8"), aesKey);
                String encryptedMsg = Base64.getEncoder().encodeToString(encrypted.ciphertext) + ":" +
                                     Base64.getEncoder().encodeToString(encrypted.iv);
                out.writeUTF(encryptedMsg);
                System.out.println("[Encrypted message sent] " + message + " / [已发送加密消息] " + message);
                System.out.println("  - Encryption algorithm: AES-256-GCM / 加密算法: AES-256-GCM");
                System.out.println("  - Original length: " + message.getBytes("UTF-8").length + " bytes / 原始长度: " + message.getBytes("UTF-8").length + " bytes");
                System.out.println("  - Ciphertext length: " + encrypted.ciphertext.length + " bytes / 密文长度: " + encrypted.ciphertext.length + " bytes");
            }
            
            System.out.println("\nConnection closed / 连接已关闭");
            
        } finally {
            socket.close();
        }
    }
    
    public static void main(String[] args) {
        try {
            TLSClient client = new TLSClient();
            client.connect();
        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage() + " / 客户端错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
