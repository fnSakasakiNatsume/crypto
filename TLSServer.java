package tls.demo;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * TLSServer.java
 * 
 * TLS服务器 - 监听客户端连接，执行TLS握手
 * 
 * 功能：
 * 1. 监听客户端连接
 * 2. 执行完整的TLS握手流程（7个阶段）
 * 3. 处理加密通信
 * 4. 支持多客户端连接（多线程）
 */
public class TLSServer {
    private static final int PORT = 8888;
    private KeyPair serverKeyPair;
    private KeyPair caKeyPair;
    private byte[] serverRandom;
    
    public TLSServer() throws Exception {
        // 初始化：生成服务器密钥对和CA密钥对
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║        TLS Server Starting... / TLS服务器启动中...        ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        
        this.serverKeyPair = CryptoUtils.generateRSAKeyPair();
        this.caKeyPair = CryptoUtils.generateCAKeyPair();
        this.serverRandom = new byte[32];
        new SecureRandom().nextBytes(serverRandom);
        
        System.out.println("✓ Server key pair generated (RSA 2048-bit) / 服务器密钥对已生成 (RSA 2048-bit)");
        System.out.println("✓ CA key pair generated / CA密钥对已生成");
        System.out.println("✓ Server random generated / 服务器随机数已生成");
    }
    
    public void start() throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("\n✓ Server listening on port " + PORT + " / 服务器监听在端口 " + PORT);
        System.out.println("Waiting for client connections... / 等待客户端连接...\n");
        
        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("═══════════════════════════════════════════════════════════");
            System.out.println("New client connected: " + clientSocket.getRemoteSocketAddress() + " / 新客户端连接: " + clientSocket.getRemoteSocketAddress());
            System.out.println("═══════════════════════════════════════════════════════════");
            
            // 为每个客户端创建新线程处理
            new Thread(() -> {
                try {
                    handleClient(clientSocket);
                } catch (Exception e) {
                    System.err.println("Error handling client: " + e.getMessage() + " / 处理客户端时出错: " + e.getMessage());
                    e.printStackTrace();
                }
            }).start();
        }
    }
    
    private void handleClient(Socket clientSocket) throws Exception {
        DataInputStream in = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
        
        try {
            // ========== 阶段1: Server Hello ==========
            System.out.println("\n[Phase 1] Receiving Client Hello... / [阶段1] 接收 Client Hello...");
            String clientHello = in.readUTF();
            System.out.println("Received: " + clientHello + " / 收到: " + clientHello);
            
            // 解析客户端随机数
            String[] parts = clientHello.split(":");
            if (parts.length < 3) {
                System.out.println("✗ Client Hello format error / Client Hello格式错误");
                return;
            }
            byte[] clientRandom = Base64.getDecoder().decode(parts[2]);
            
            System.out.println("\n[Phase 1] Sending Server Hello... / [阶段1] 发送 Server Hello...");
            String serverHello = "Server Hello:TLS 1.2:" + Base64.getEncoder().encodeToString(serverRandom);
            out.writeUTF(serverHello);
            System.out.println("Sent: " + serverHello + " / 发送: " + serverHello);
            System.out.println("✓ Encryption algorithms and version negotiated / 双方已协商好加密算法和版本");
            System.out.println("✓ Random numbers R1 and R2 exchanged / 双方已交换随机数 R1 和 R2");
            
            // ========== 阶段2: Server Certificate ==========
            System.out.println("\n[Phase 2] Sending Server Certificate... / [阶段2] 发送 Server Certificate...");
            String certInfo = "CN=localhost, O=Demo Server, C=US, Valid From: 2024-01-01, Valid To: 2025-01-01";
            byte[] certSignature = CryptoUtils.signCertificate(certInfo, caKeyPair.getPrivate());
            
            // 使用 ||| 作为分隔符，避免证书信息中的冒号干扰
            // 格式：Certificate|||证书信息|||服务器公钥|||CA公钥|||签名
            String certificate = "Certificate|||" + certInfo + "|||" + 
                               Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()) + "|||" +
                               Base64.getEncoder().encodeToString(caKeyPair.getPublic().getEncoded()) + "|||" +
                               Base64.getEncoder().encodeToString(certSignature);
            out.writeUTF(certificate);
            System.out.println("Certificate sent / 证书已发送");
            System.out.println("  - Subject: CN=localhost");
            System.out.println("  - Public Key: RSA 2048-bit");
            System.out.println("  - Signature Algorithm: SHA256withRSA");
            
            // ========== 阶段3: 等待证书验证 ==========
            System.out.println("\n[Phase 3] Waiting for certificate verification... / [阶段3] 等待客户端验证证书...");
            String certVerify = in.readUTF();
            if (!certVerify.equals("Certificate Verified")) {
                System.out.println("✗ Certificate verification failed! Connection terminated / 证书验证失败！连接终止");
                return;
            }
            System.out.println("✓ Certificate verified! Server identity trusted / 证书验证通过！服务器身份可信");
            
            // ========== 阶段4: Key Exchange ==========
            System.out.println("\n[Phase 4] Receiving encrypted Pre-Master Secret... / [阶段4] 接收加密的 Pre-Master Secret...");
            String keyExchange = in.readUTF();
            String[] keyParts = keyExchange.split(":");
            if (keyParts.length < 2) {
                System.out.println("✗ Key Exchange format error / Key Exchange格式错误");
                return;
            }
            byte[] encryptedPMSBytes = Base64.getDecoder().decode(keyParts[1]);
            
            // 解密PMS
            byte[] pms = CryptoUtils.decryptPMS(encryptedPMSBytes, serverKeyPair.getPrivate());
            System.out.println("✓ PMS decrypted successfully / PMS解密成功");
            System.out.println("  - Decryption algorithm: RSA/ECB/PKCS1Padding / 解密算法: RSA/ECB/PKCS1Padding");
            System.out.println("  - PMS length: " + pms.length + " bytes / PMS长度: " + pms.length + " bytes");
            
            // ========== 阶段5: 生成会话密钥 ==========
            System.out.println("\n[Phase 5] Generating session key... / [阶段5] 生成会话密钥...");
            byte[] sessionKey = CryptoUtils.generateSessionKey(clientRandom, serverRandom, pms);
            System.out.println("✓ Session key generated / 会话密钥已生成");
            System.out.println("  - Input: R1 (Client Random) + R2 (Server Random) + PMS / 输入: R1 (Client Random) + R2 (Server Random) + PMS");
            System.out.println("  - Algorithm: SHA-256 / 算法: SHA-256");
            System.out.println("  - Session key length: " + sessionKey.length + " bytes (256 bits) / 会话密钥长度: " + sessionKey.length + " bytes (256 bits)");
            System.out.println("  - Session key (first 20 chars): " + Base64.getEncoder().encodeToString(sessionKey).substring(0, 20) + "... / 会话密钥 (前20字符): " + Base64.getEncoder().encodeToString(sessionKey).substring(0, 20) + "...");
            
            // ========== 阶段6: Change Cipher Spec ==========
            System.out.println("\n[Phase 6] Switching to encrypted mode... / [阶段6] 切换到加密模式...");
            out.writeUTF("Change Cipher Spec");
            System.out.println("✓ Switched to encrypted mode / 已切换到加密模式");
            System.out.println("✓ Handshake complete! Both sides switched to encrypted communication / 握手完成！双方已切换到加密通信模式");
            
            // ========== 阶段7: 加密通信 ==========
            System.out.println("\n[Phase 7] Starting encrypted communication... / [阶段7] 开始加密通信...");
            System.out.println("═══════════════════════════════════════════════════════════");
            
            javax.crypto.SecretKey aesKey = CryptoUtils.deriveAESKey(sessionKey);
            
            // 接收加密消息
            while (true) {
                String encryptedMsg = in.readUTF();
                if (encryptedMsg.equals("QUIT")) {
                    break;
                }
                
                // 解析加密消息
                String[] msgParts = encryptedMsg.split(":");
                if (msgParts.length < 2) {
                    System.out.println("✗ Message format error / 消息格式错误");
                    continue;
                }
                
                byte[] ciphertext = Base64.getDecoder().decode(msgParts[0]);
                byte[] iv = Base64.getDecoder().decode(msgParts[1]);
                
                // 解密
                CryptoUtils.EncryptedMessage encrypted = new CryptoUtils.EncryptedMessage(ciphertext, iv);
                byte[] decrypted = CryptoUtils.decrypt(encrypted, aesKey);
                String message = new String(decrypted, "UTF-8");
                
                System.out.println("Received encrypted message: " + message + " / 收到加密消息: " + message);
                System.out.println("  - Encryption algorithm: AES-256-GCM / 加密算法: AES-256-GCM");
                System.out.println("  - Ciphertext length: " + ciphertext.length + " bytes / 密文长度: " + ciphertext.length + " bytes");
                
                // 回复加密消息
                String response = "Server received: " + message + " / Server收到: " + message;
                CryptoUtils.EncryptedMessage encryptedResponse = CryptoUtils.encrypt(response.getBytes("UTF-8"), aesKey);
                String reply = Base64.getEncoder().encodeToString(encryptedResponse.ciphertext) + ":" +
                              Base64.getEncoder().encodeToString(encryptedResponse.iv);
                out.writeUTF(reply);
                System.out.println("Replied with encrypted message / 已回复加密消息");
            }
            
            System.out.println("═══════════════════════════════════════════════════════════");
            System.out.println("Client disconnected / 客户端断开连接");
            
        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage() + " / 处理客户端时出错: " + e.getMessage());
            throw e;
        } finally {
            clientSocket.close();
        }
    }
    
    public static void main(String[] args) {
        try {
            TLSServer server = new TLSServer();
            server.start();
        } catch (Exception e) {
            System.err.println("Server error: " + e.getMessage() + " / 服务器错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
