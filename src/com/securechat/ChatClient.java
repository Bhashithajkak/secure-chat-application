package com.securechat;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.util.concurrent.*;
import java.security.MessageDigest;

public class ChatClient {
    private Socket socket;
    private ObjectOutputStream output;
    private ObjectInputStream input;
    private String username;
    private String password;
    private PublicKey serverPublicKey;
    private PrivateKey clientPrivateKey;
    private PublicKey clientPublicKey;
    private Map<String, SecretKey> sessionKeys;
    private Map<String, KeyPair> dhKeyPairs;
    private Map<String, Integer> messageCounters;
    private Scanner scanner;
    private Set<String> onlineUsers;
    private boolean running;
    private boolean authenticated;
    private AuditLogger auditLogger;
    private Map<String, PublicKey> userPublicKeys;

    
    // Perfect Forward Secrecy - Key rotation interval (messages)
    private static final int KEY_ROTATION_INTERVAL = 50;
    
    public ChatClient(String username) {
        this.username = username;
        this.sessionKeys = new ConcurrentHashMap<>();
        this.dhKeyPairs = new ConcurrentHashMap<>();
        this.messageCounters = new ConcurrentHashMap<>();
        this.scanner = new Scanner(System.in);
        this.onlineUsers = new HashSet<>();
        this.running = true;
        this.authenticated = false;
        this.userPublicKeys = new ConcurrentHashMap<>();
        this.auditLogger = new AuditLogger("client_" + username + "_audit.log");
        generateKeyPair();
    }
    
    private void generateKeyPair() {
        try {
            System.out.println("Generating RSA key pair...");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            this.clientPrivateKey = keyPair.getPrivate();
            this.clientPublicKey = keyPair.getPublic();
            System.out.println("Key pair generated successfully");
            auditLogger.logEvent("CLIENT_KEYPAIR_GENERATED", username, "RSA-2048 key pair generated");
        } catch (Exception e) {
            System.err.println("Error generating key pair: " + e.getMessage());
            auditLogger.logEvent("CLIENT_KEYPAIR_ERROR", username, "Failed to generate key pair: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public boolean connect(String host, int port, boolean isRegistration){
        try {
            System.out.println("Connecting to server at " + host + ":" + port + "...");
            socket = new Socket(host, port);
            output = new ObjectOutputStream(socket.getOutputStream());
            input = new ObjectInputStream(socket.getInputStream());
            
            System.out.println("Connected to server successfully");
            auditLogger.logEvent("CONNECTION_ESTABLISHED", username, "Connected to " + host + ":" + port);
            
            // Receive server's public key
            serverPublicKey = (PublicKey) input.readObject();
            System.out.println("Received server's public key");
            auditLogger.logEvent("SERVER_PUBKEY_RECEIVED", username, "Server public key received");
            
            // Handle login or registration
            if (handleAuthentication(isRegistration)) {
                authenticated = true;
                System.out.println("\n=== Authentication Successful! ===");
                System.out.println("Welcome to Secure Chat, " + username + "!");
                auditLogger.logEvent("AUTHENTICATION_SUCCESS", username, "User successfully authenticated");

                // Start message listener thread
                new Thread(this::listenForMessages).start();

                // Start user interface
                startUserInterface();
                return true;
            } else {
                System.out.println("Authentication failed! Connection will be closed.");
                auditLogger.logEvent("AUTHENTICATION_FAILED", username, "User authentication failed");
                try {
                    socket.close();
                } catch (IOException e) {
                    System.err.println("Error closing socket after failed auth: " + e.getMessage());
                }
                return false; 
            }

            
        } catch (Exception e) {
            System.err.println("Connection error: " + e.getMessage());
            auditLogger.logEvent("CONNECTION_ERROR", username, "Connection error: " + e.getMessage());
            e.printStackTrace();
        }
		return false; // Fixed: was returning isRegistration
    }
    
    private boolean handleAuthentication(boolean isRegistration){
        try {
            
            System.out.print("Enter password: ");
            password = scanner.nextLine().trim();
            
            if (password.length() < 6) {
                System.out.println("Password must be at least 6 characters long!");
                return false;
            }
            
            // Send authentication request
            AuthRequest authRequest = new AuthRequest(username, hashPassword(password), 
                clientPublicKey, isRegistration);
            output.writeObject(authRequest);
            output.flush();
            
            // Receive authentication response
            AuthResponse authResponse = (AuthResponse) input.readObject();
            
            if (!authResponse.success) {
                System.out.println("Authentication failed: " + authResponse.message);
                return false;
            }
            
            System.out.println("Authentication successful: " + authResponse.message);
            
            // Perform mutual authentication with server
            return performMutualAuthentication();
            
        } catch (Exception e) {
            System.err.println("Authentication error: " + e.getMessage());
            auditLogger.logEvent("AUTHENTICATION_ERROR", username, "Authentication error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest((password + username).getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
    
    private boolean performMutualAuthentication() {
        try {
            System.out.println("\n=== Starting Mutual Authentication ===");
            auditLogger.logEvent("MUTUAL_AUTH_START", username, "Starting mutual authentication");
            
            // Receive challenge from server
            String challenge = (String) input.readObject();
            System.out.println("Received challenge from server");
            
            // Sign the challenge with client's private key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(clientPrivateKey);
            signature.update(challenge.getBytes());
            byte[] signedChallenge = signature.sign();
            
            System.out.println("Signed challenge with client private key");
            
            // Send signed challenge back
            output.writeObject(signedChallenge);
            
            // Send challenge to server for mutual authentication
            String clientChallenge = UUID.randomUUID().toString();
            System.out.println("Sending challenge to server");
            output.writeObject(clientChallenge);
            output.flush();
            
            // Receive authentication result
            String authResult = (String) input.readObject();
            if (!"AUTH_SUCCESS".equals(authResult)) {
                System.out.println("Server rejected client authentication");
                auditLogger.logEvent("MUTUAL_AUTH_FAILED", username, "Server rejected client authentication");
                return false;
            }
            
            System.out.println("Server accepted client authentication");
            
            // Verify server's signature
            byte[] serverSignedChallenge = (byte[]) input.readObject();
            signature.initVerify(serverPublicKey);
            signature.update(clientChallenge.getBytes());
            
            boolean serverVerified = signature.verify(serverSignedChallenge);
            if (serverVerified) {
                System.out.println("Server signature verified successfully");
                auditLogger.logEvent("MUTUAL_AUTH_SUCCESS", username, "Mutual authentication completed successfully");
            } else {
                System.out.println("Server signature verification failed");
                auditLogger.logEvent("MUTUAL_AUTH_FAILED", username, "Server signature verification failed");
            }
            
            return serverVerified;
            
        } catch (Exception e) {
            System.err.println("Authentication error: " + e.getMessage());
            auditLogger.logEvent("MUTUAL_AUTH_ERROR", username, "Mutual authentication error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    private void listenForMessages() {
        try {
            while (running && authenticated) {
                Object message = input.readObject();
                
                if (message instanceof ChatMessage) {
                    handleChatMessage((ChatMessage) message);
                } else if (message instanceof UserListMessage) {
                    handleUserListMessage((UserListMessage) message);
                } else if (message instanceof KeyRotationMessage) {
                    handleKeyRotation((KeyRotationMessage) message);
                } else if (message instanceof PublicKeyResponse) {
                    // Handle public key responses
                    handlePublicKeyResponse((PublicKeyResponse) message);
                }
                
            }
        } catch (Exception e) {
            if (running) {
                System.err.println("\nConnection lost: " + e.getMessage());
                System.out.println("Please restart the client to reconnect.");
                auditLogger.logEvent("CONNECTION_LOST", username, "Connection lost: " + e.getMessage());
            }
        }
    }
    
    private void handlePublicKeyResponse(PublicKeyResponse response) {
        if (response.success && response.publicKey != null) {
            userPublicKeys.put(response.targetUser, response.publicKey);
            System.out.println("Received public key for " + response.targetUser);
            auditLogger.logEvent("PUBKEY_RECEIVED", username, 
                "Received public key for user: " + response.targetUser);
        } else {
            System.out.println("Failed to get public key for " + response.targetUser);
            auditLogger.logEvent("PUBKEY_FAILED", username, 
                "Failed to get public key for user: " + response.targetUser);
        }
    }
    
    private void requestUserPublicKey(String targetUser) {
        try {
            PublicKeyRequest request = new PublicKeyRequest(username, targetUser);
            output.writeObject(request);
            output.flush();
            
            auditLogger.logEvent("PUBKEY_REQUEST_SENT", username, 
                "Requested public key for user: " + targetUser);
        } catch (Exception e) {
            auditLogger.logEvent("PUBKEY_REQUEST_ERROR", username, 
                "Error requesting public key: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void handleChatMessage(ChatMessage message) {
        try {
            if (message.isKeyExchange) {
                // Handle Diffie-Hellman key exchange
                handleDHKeyExchange(message);
            } else {
                // Decrypt and display regular message
                SecretKey sessionKey = sessionKeys.get(message.sender);
                if (sessionKey != null) {
                    String decryptedMessage = decryptMessage(message.encryptedMessage, sessionKey);
                    System.out.println("\n[" + message.sender + "]: " + decryptedMessage);
                    auditLogger.logEvent("MESSAGE_RECEIVED", username, "Message received from " + message.sender);
                } else {
                    System.out.println("\nReceived message from " + message.sender + " but no session key available");
                }
            }
        } catch (Exception e) {
            System.err.println("Error handling message: " + e.getMessage());
            auditLogger.logEvent("MESSAGE_ERROR", username, "Error handling message: " + e.getMessage());
        }
    }
    
    private void handleDHKeyExchange(ChatMessage message) {
        try {
            System.out.println("Performing key exchange with " + message.sender + "...");
            auditLogger.logEvent("KEY_EXCHANGE_START", username, 
                "Starting key exchange with " + message.sender);
            
            byte[] dhPublicKeyBytes;
            
            // Check if DH key is encrypted
            if (message.isDHEncrypted) {
                // Decrypt DH public key with our private RSA key
                dhPublicKeyBytes = decryptWithRSA(message.dhPublicKey, clientPrivateKey);
                auditLogger.logEvent("DH_DECRYPTED", username, 
                    "Decrypted DH public key from " + message.sender);
            } else {
                // Use unencrypted DH key (backward compatibility)
                dhPublicKeyBytes = message.dhPublicKey;
            }
            
            // Convert received DH public key
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(dhPublicKeyBytes);
            PublicKey otherPublicKey = keyFactory.generatePublic(keySpec);
            
            // Get our DH key pair for this user
            KeyPair dhKeyPair = dhKeyPairs.get(message.sender);
            if (dhKeyPair == null) {
                dhKeyPair = DiffieHellmanHelper.generateKeyPair();
                dhKeyPairs.put(message.sender, dhKeyPair);
                
                // Get sender's RSA public key for encryption
                PublicKey senderPublicKey = userPublicKeys.get(message.sender);
                if (senderPublicKey == null) {
                    requestUserPublicKey(message.sender);
                    // Wait briefly for response
                    Thread.sleep(1000);
                    senderPublicKey = userPublicKeys.get(message.sender);
                }
                
                if (senderPublicKey != null) {
                    // Send our encrypted DH public key back
                    byte[] ourDHPublicKey = dhKeyPair.getPublic().getEncoded();
                    byte[] encryptedDHKey = encryptWithRSA(ourDHPublicKey, senderPublicKey);
                    
                    ChatMessage dhResponse = new ChatMessage(username, message.sender, 
                        encryptedDHKey, System.currentTimeMillis(), true, true);
                    output.writeObject(dhResponse);
                    output.flush();
                    
                    auditLogger.logEvent("ENCRYPTED_DH_RESPONSE", username, 
                        "Sent encrypted DH response to " + message.sender);
                } else {
                    System.out.println("Warning: Sending unencrypted DH key to " + message.sender);
                    // Fallback to unencrypted
                    byte[] ourDHPublicKey = dhKeyPair.getPublic().getEncoded();
                    ChatMessage dhResponse = new ChatMessage(username, message.sender, 
                        ourDHPublicKey, System.currentTimeMillis(), true, false);
                    output.writeObject(dhResponse);
                    output.flush();
                }
            }
            
            // Generate shared secret
            byte[] sharedSecret = DiffieHellmanHelper.generateSharedSecret(
                dhKeyPair.getPrivate(), otherPublicKey);
            
            if (sharedSecret != null) {
                // Derive session key from shared secret
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] keyBytes = sha256.digest(sharedSecret);
                SecretKey sessionKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");
                
                // Store session key and initialize message counter
                sessionKeys.put(message.sender, sessionKey);
                messageCounters.put(message.sender, 0);
                
                System.out.println("Secure session established with " + message.sender);
                auditLogger.logEvent("SESSION_ESTABLISHED", username, 
                    "Secure session established with " + message.sender);
            }
            
        } catch (Exception e) {
            System.err.println("Error in key exchange: " + e.getMessage());
            auditLogger.logEvent("KEY_EXCHANGE_ERROR", username, 
                "Key exchange error with " + message.sender + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void handleKeyRotation(KeyRotationMessage message) {
        try {
            System.out.println("Rotating session key with " + message.sender + "...");
            auditLogger.logEvent("KEY_ROTATION_START", username, "Starting key rotation with " + message.sender);
            
            // Generate new DH key pair
            KeyPair newDHKeyPair = DiffieHellmanHelper.generateKeyPair();
            dhKeyPairs.put(message.sender, newDHKeyPair);
            
            // Convert received new DH public key
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(message.newDHPublicKey);
            PublicKey otherNewPublicKey = keyFactory.generatePublic(keySpec);
            
            // Generate new shared secret
            byte[] newSharedSecret = DiffieHellmanHelper.generateSharedSecret(
                newDHKeyPair.getPrivate(), otherNewPublicKey);
            
            // Derive new session key
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha256.digest(newSharedSecret);
            SecretKey newSessionKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");
            
            // Update session key and reset counter
            sessionKeys.put(message.sender, newSessionKey);
            messageCounters.put(message.sender, 0);
            
            // Send our new DH public key back
            byte[] ourNewDHPublicKey = newDHKeyPair.getPublic().getEncoded();
            KeyRotationMessage rotationResponse = new KeyRotationMessage(username, message.sender, 
                ourNewDHPublicKey, System.currentTimeMillis());
            output.writeObject(rotationResponse);
            output.flush();
            
            System.out.println("Session key rotated successfully with " + message.sender);
            auditLogger.logEvent("KEY_ROTATION_SUCCESS", username, "Session key rotated with " + message.sender);
            
        } catch (Exception e) {
            System.err.println("Error in key rotation: " + e.getMessage());
            auditLogger.logEvent("KEY_ROTATION_ERROR", username, "Key rotation error with " + message.sender + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    // FIXED: Use more compatible RSA padding
    private byte[] encryptWithRSA(byte[] data, PublicKey publicKey) throws Exception {
        try {
            // First try OAEP padding (preferred for security)
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Fallback to PKCS1 padding (more widely supported)
            System.out.println("OAEP padding not available, falling back to PKCS1 padding");
            auditLogger.logEvent("RSA_FALLBACK", username, "Using PKCS1 padding instead of OAEP");
            
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        }
    }
    
    // FIXED: Use more compatible RSA padding
    private byte[] decryptWithRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        try {
            // First try OAEP padding (preferred for security)
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Fallback to PKCS1 padding (more widely supported)
            System.out.println("OAEP padding not available, falling back to PKCS1 padding");
            auditLogger.logEvent("RSA_FALLBACK", username, "Using PKCS1 padding instead of OAEP");
            
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        }
    }
    
    private void handleUserListMessage(UserListMessage message) {
        synchronized(onlineUsers) {
            onlineUsers = new HashSet<>(message.users);
            onlineUsers.remove(username); // Remove self from list
        }
    }
    
   private void startUserInterface() {
    while (running && authenticated) {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("SECURE CHAT MENU");
        System.out.println("=".repeat(50));
        System.out.println("1. Show Online Users");
        System.out.println("2. Start Secure Chat");
        System.out.println("3. Quit Application");
        System.out.println("=".repeat(50));
        System.out.print("Enter choice (1-3): ");

        String choice = scanner.nextLine().trim();

        switch (choice) {
            case "1":
                showOnlineUsers();
                break;
            case "2":
                startChat();
                break;
            case "3":
                quit();
                break;
            default:
                System.out.println("Invalid input. Please enter 1, 2, or 3.");
        }
    }
}

    private void showOnlineUsers() {
        System.out.println("\n" + "-".repeat(30));
        System.out.println("ONLINE USERS");
        System.out.println("-".repeat(30));
        synchronized(onlineUsers) {
            if (onlineUsers.isEmpty()) {
                System.out.println("   No other users online.");
            } else {
                for (String user : onlineUsers) {
                    boolean hasSession = sessionKeys.containsKey(user);
                    System.out.println("   " + user + (hasSession ? " [SECURE]" : ""));
                }
                System.out.println("\n[SECURE] = Secure session established");
            }
        }
        System.out.println("-".repeat(30));
    }
    
    private void startChat() {
        showOnlineUsers();
        synchronized(onlineUsers) {
            if (onlineUsers.isEmpty()) {
                return;
            }
        }
        
        System.out.print("\nEnter username to chat with: ");
        String recipient = scanner.nextLine().trim();
        
        synchronized(onlineUsers) {
            if (!onlineUsers.contains(recipient)) {
                System.out.println("User not found or offline.");
                return;
            }
        }
        
        // Check if session key exists, if not, initiate DH key exchange
        if (!sessionKeys.containsKey(recipient)) {
            System.out.println("Establishing secure session with " + recipient + "...");
            initiateDHKeyExchange(recipient);
            
            // Wait for key exchange to complete
            System.out.print("Waiting for key exchange");
            for (int i = 0; i < 20; i++) { // Increased wait time
                try {
                    Thread.sleep(500);
                    System.out.print(".");
                    if (sessionKeys.containsKey(recipient)) {
                        break;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            System.out.println();
            
            if (!sessionKeys.containsKey(recipient)) {
                System.out.println("Failed to establish secure session. Please try again.");
                return;
            }
        }
        
        System.out.println("\n" + "=".repeat(50));
        System.out.println("SECURE CHAT WITH " + recipient.toUpperCase());
        System.out.println("=".repeat(50));
        System.out.println("Type your messages below (type 'exit' to stop chatting)");
        System.out.println("-".repeat(50));
        
        while (true) {
            System.out.print("You: ");
            String message = scanner.nextLine();
            
            if ("exit".equalsIgnoreCase(message.trim())) {
                System.out.println("Chat session ended.");
                break;
            }
            
            if (!message.trim().isEmpty()) {
                sendEncryptedMessage(recipient, message);
                
                // Check if key rotation is needed
                Integer count = messageCounters.get(recipient);
                if (count != null && count >= KEY_ROTATION_INTERVAL) {
                    initiateKeyRotation(recipient);
                }
            }
        }
    }
    
    private void initiateKeyRotation(String recipient) {
        try {
            System.out.println("Initiating key rotation with " + recipient + "...");
            auditLogger.logEvent("KEY_ROTATION_INIT", username, "Initiating key rotation with " + recipient);
            
            // Generate new DH key pair
            KeyPair newDHKeyPair = DiffieHellmanHelper.generateKeyPair();
            dhKeyPairs.put(recipient, newDHKeyPair);
            
            // Send key rotation message
            byte[] newDHPublicKey = newDHKeyPair.getPublic().getEncoded();
            KeyRotationMessage rotationMessage = new KeyRotationMessage(username, recipient, 
                newDHPublicKey, System.currentTimeMillis());
            
            output.writeObject(rotationMessage);
            output.flush();
            
        } catch (Exception e) {
            System.err.println("Error initiating key rotation: " + e.getMessage());
            auditLogger.logEvent("KEY_ROTATION_INIT_ERROR", username, "Error initiating key rotation with " + recipient + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void initiateDHKeyExchange(String recipient) {
        try {
            // Check if we have recipient's public key
            PublicKey recipientPublicKey = userPublicKeys.get(recipient);
            if (recipientPublicKey == null) {
                System.out.println("Requesting " + recipient + "'s public key...");
                requestUserPublicKey(recipient);
                
                // Wait for public key response with better synchronization
                for (int i = 0; i < 20; i++) {
                    Thread.sleep(500);
                    recipientPublicKey = userPublicKeys.get(recipient);
                    if (recipientPublicKey != null) break;
                }
                
                if (recipientPublicKey == null) {
                    System.out.println("Failed to get " + recipient + "'s public key, attempting unencrypted key exchange");
                    // Fallback to unencrypted key exchange
                    performUnencryptedKeyExchange(recipient);
                    return;
                }
            }
            
            // Generate DH key pair for this conversation
            KeyPair dhKeyPair = DiffieHellmanHelper.generateKeyPair();
            dhKeyPairs.put(recipient, dhKeyPair);
            
            // Get raw DH public key
            byte[] dhPublicKey = dhKeyPair.getPublic().getEncoded();
            
            // Encrypt DH public key with recipient's RSA public key
            byte[] encryptedDHKey = encryptWithRSA(dhPublicKey, recipientPublicKey);
            
            // Send encrypted DH public key
            ChatMessage dhMessage = new ChatMessage(username, recipient, encryptedDHKey, 
                System.currentTimeMillis(), true, true); // true for encrypted
            
            output.writeObject(dhMessage);
            output.flush();
            
            auditLogger.logEvent("ENCRYPTED_DH_SENT", username, 
                "Sent encrypted DH public key to " + recipient);
            
        } catch (Exception e) {
            System.err.println("Error initiating encrypted key exchange: " + e.getMessage());
            auditLogger.logEvent("ENCRYPTED_DH_ERROR", username, 
                "Error initiating encrypted key exchange: " + e.getMessage());
            
            // Fallback to unencrypted key exchange
            System.out.println("Falling back to unencrypted key exchange...");
            performUnencryptedKeyExchange(recipient);
        }
    }
    
    // Fallback method for unencrypted key exchange
    private void performUnencryptedKeyExchange(String recipient) {
        try {
            // Generate DH key pair for this conversation
            KeyPair dhKeyPair = DiffieHellmanHelper.generateKeyPair();
            dhKeyPairs.put(recipient, dhKeyPair);
            
            // Send unencrypted DH public key
            byte[] dhPublicKey = dhKeyPair.getPublic().getEncoded();
            ChatMessage dhMessage = new ChatMessage(username, recipient, dhPublicKey, 
                System.currentTimeMillis(), true, false); // false for unencrypted
            
            output.writeObject(dhMessage);
            output.flush();
            
            auditLogger.logEvent("UNENCRYPTED_DH_SENT", username, 
                "Sent unencrypted DH public key to " + recipient);
            
        } catch (Exception e) {
            System.err.println("Error in unencrypted key exchange: " + e.getMessage());
            auditLogger.logEvent("UNENCRYPTED_DH_ERROR", username, 
                "Error in unencrypted key exchange: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void sendEncryptedMessage(String recipient, String message) {
        try {
            SecretKey sessionKey = sessionKeys.get(recipient);
            if (sessionKey == null) {
                System.out.println("No secure session with " + recipient);
                return;
            }
            
            byte[] encryptedMessage = encryptMessage(message, sessionKey);
            ChatMessage chatMessage = new ChatMessage(username, recipient, encryptedMessage, 
                System.currentTimeMillis());
            
            output.writeObject(chatMessage);
            output.flush();
            
            // Increment message counter for key rotation
            Integer currentCount = messageCounters.get(recipient);
            messageCounters.put(recipient, currentCount != null ? currentCount + 1 : 1);
            auditLogger.logEvent("MESSAGE_SENT", username, "Message sent to " + recipient);
            
        } catch (Exception e) {
            System.err.println("Error sending message: " + e.getMessage());
            auditLogger.logEvent("MESSAGE_SEND_ERROR", username, "Error sending message to " + recipient + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private byte[] encryptMessage(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(message.getBytes("UTF-8"));
        
        // Combine IV and encrypted data
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        
        return result;
    }
    
    private String decryptMessage(byte[] encryptedData, SecretKey key) throws Exception {
        // Extract IV and encrypted message
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[encryptedData.length - 16];
        System.arraycopy(encryptedData, 0, iv, 0, 16);
        System.arraycopy(encryptedData, 16, encrypted, 0, encrypted.length);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, "UTF-8");
    }
    
    private void quit() {
        System.out.println("\nGoodbye, " + username + "!");
        auditLogger.logEvent("CLIENT_DISCONNECT", username, "Client disconnecting");
        running = false;
        try {
            if (socket != null) {
                socket.close();
            }
            auditLogger.close();
        } catch (IOException e) {
            System.err.println("Error closing connection: " + e.getMessage());
        }
        System.exit(0);
    }
    
    // Main method - Essential for Eclipse to recognize this as a runnable class
   public static void main(String[] args) {
    Scanner scanner = new Scanner(System.in);

    String host = "localhost";
    int port = 8080;

    if (args.length >= 2) {
        host = args[0];
        try {
            port = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            System.out.println("Invalid port number, using default port 8080");
            port = 8080;
        }
    }

    while (true) {
        System.out.println("=".repeat(50));
        System.out.println("SECURE CHAT CLIENT");
        System.out.println("=".repeat(50));

        // Ask user to choose login or registration
        String mode = "";
        while (true) {
            System.out.println("1. Login to existing account");
            System.out.println("2. Register new account");
            System.out.print("Choose an option (1 or 2): ");
            mode = scanner.nextLine().trim();

            if (mode.equals("1") || mode.equals("2")) {
                break;
            } else {
                System.out.println("Invalid choice. Please enter 1 or 2.");
            }
        }

        // Ask for username
        String username;
        while (true) {
            System.out.print("Enter your username: ");
            username = scanner.nextLine().trim();

            if (username.isEmpty()) {
                System.out.println("Username cannot be empty!");
            } else if (username.contains(" ") || username.length() > 20) {
                System.out.println("Username must not contain spaces and must be under 20 characters!");
            } else {
                break;
            }
        }

        System.out.println("Hello " + username + "! Initializing secure client...");

        ChatClient client = new ChatClient(username);

        System.out.println("Attempting to connect to " + host + ":" + port);
        boolean connected = client.connect(host, port, mode.equals("2"));

        if (connected) {
            break; // exit loop if authentication succeeded
        } else {
            System.out.println("Returning to menu...");
        }
    }
}
}