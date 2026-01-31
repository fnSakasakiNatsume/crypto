package tls.demo;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;

public class TLSHandshakeSimulator {

    private static Scanner scanner = new Scanner(System.in);

    private static void step(String title) {
        System.out.println("\n"); 
        System.out.println(">>> NEXT STEP: " + title);
        System.out.print("    [Press Enter to continue...]");
        scanner.nextLine();
        System.out.println("--------------------------------------------------");
    }

    public static void simulateTLSHandshake() throws Exception {
        System.out.println("=== TLS Handshake Demo ===");

        // [1] Negotiation
        step("ClientHello & ServerHello");
        SecureRandom random = new SecureRandom();
        byte[] clientRandom = new byte[32]; random.nextBytes(clientRandom);
        byte[] serverRandom = new byte[32]; random.nextBytes(serverRandom);

        System.out.println("[1] Negotiation Finished");
        System.out.println(" - Version: TLS 1.2");
        System.out.println(" - Cipher: AES_GCM");
        System.out.println(" - Client Random: " + shortHex(clientRandom));
        System.out.println(" - Server Random: " + shortHex(serverRandom));

        // [2] Authentication
        step("Verify Server Certificate");
        KeyPair caKeyPair = SignatureVerify.generateCAKeyPair(); 
        String serverInfo = "CN=www.google.com";
        byte[] signature = SignatureVerify.signCertificate(serverInfo, caKeyPair.getPrivate());
        
        System.out.print("[2] Verifying CA Signature... ");
        boolean certValid = SignatureVerify.verifySignature(serverInfo, signature, caKeyPair.getPublic());
        if (certValid) {
            System.out.println("Passed");
            System.out.println(" - Server identity confirmed");
        } else {
            System.out.println("Failed"); return;
        }

        // [3] Key Exchange
        step("Pre-Master Secret (PMS) Exchange");
        byte[] pms = new byte[48]; random.nextBytes(pms);
        KeyPair serverKP = KeyExchangeDemo.generateServerKeyPair();
        
        System.out.println("[3] Encrypting & Transferring PMS");
        System.out.println(" - Generated PMS: " + shortHex(pms));
        byte[] encryptedPMS = KeyExchangeDemo.encryptPreMasterSecret(pms, serverKP.getPublic());
        System.out.println(" - Encrypted Data: [" + encryptedPMS.length + " bytes]");
        
        byte[] decryptedPMS = KeyExchangeDemo.decryptPreMasterSecret(encryptedPMS, serverKP.getPrivate());
        System.out.println(" - Server Decrypted: " + shortHex(decryptedPMS));
        
        if (java.util.Arrays.equals(pms, decryptedPMS)) {
            System.out.println(" - Status: Key material verified ✓");
        }

        // [4] Key Generation
        step("Derive Session Key");
        byte[] sessionKey = KeyExchangeDemo.generateSessionKey(clientRandom, serverRandom, pms);
        System.out.println("[4] Generation Finished");
        System.out.println(" - Session Key: " + Base64.getEncoder().encodeToString(sessionKey).substring(0, 20) + "...");

        // [5] Communication
        step("Test Encrypted Data Transfer");
        SecretKey aesKey = CipherSuite.deriveAESKey(sessionKey);
        String msg = "GET /index.html HTTP/1.1";
        
        System.out.println("[Client] Plaintext: \"" + msg + "\"");
        CipherSuite.EncryptedData encData = CipherSuite.encryptHTTPMessage(msg, aesKey);
        System.out.println("   ↓ (Ciphertext: " + Base64.getEncoder().encodeToString(encData.ciphertext).substring(0, 15) + "...)");
        
        String decryptedMsg = CipherSuite.decryptHTTPMessage(encData, aesKey);
        System.out.println("[Server] Decrypted: \"" + decryptedMsg + "\"");
        
        System.out.println("\n=== Demo Finished ===");
    }

    private static String shortHex(byte[] data) {
        String s = Base64.getEncoder().encodeToString(data);
        return s.length() > 10 ? s.substring(0, 10) + "..." : s;
    }

    public static void main(String[] args) {
        try {
            simulateTLSHandshake();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}