package com.securechat;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

class ClientHandler implements Runnable {
    private Socket clientSocket;
    private ChatServer server;
    private ObjectInputStream input;
    private ObjectOutputStream output;
    private String username;
    private PublicKey clientPublicKey;
    private PrivateKey serverPrivateKey;
    private PublicKey serverPublicKey;
    private Set<Long> usedTimestamps;
    private AuditLogger auditLogger;
    
    public ClientHandler(Socket socket, ChatServer server) {
        this.clientSocket = socket;
        this.server = server;
        this.usedTimestamps = ConcurrentHashMap.newKeySet();
        this.auditLogger = server.getAuditLogger();
        generateKeyPair();
    }
    
    private void generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            this.serverPrivateKey = keyPair.getPrivate();
            this.serverPublicKey = keyPair.getPublic();
            auditLogger.logEvent("SERVER_KEYPAIR_GENERATED", "SERVER", "RSA key pair generated for client handler");
        } catch (Exception e) {
            auditLogger.logEvent("SERVER_KEYPAIR_ERROR", "SERVER", "Error generating key pair: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    @Override
    public void run() {
        try {
            output = new ObjectOutputStream(clientSocket.getOutputStream());
            input = new ObjectInputStream(clientSocket.getInputStream());
            
            // Send server's public key
            output.writeObject(serverPublicKey);
            output.flush();
            auditLogger.logEvent("SERVER_PUBKEY_SENT", "SERVER", "Server public key sent to client");
            
            // Handle user authentication (login/registration)
            if (handleUserAuthentication()) {
                // Perform mutual authentication
                if (performMutualAuthentication()) {
                    server.addClient(username, this, clientPublicKey);
                    auditLogger.logEvent("CLIENT_AUTHENTICATED", username, "Client successfully authenticated and added");
                    handleMessages();
                } else {
                    auditLogger.logEvent("MUTUAL_AUTH_FAILED", username, "Mutual authentication failed");
                }
            } else {
                auditLogger.logEvent("USER_AUTH_FAILED", "UNKNOWN", "User authentication failed");
            }
            
        } catch (Exception e) {
            System.err.println("Client handler error: " + e.getMessage());
            auditLogger.logEvent("CLIENT_HANDLER_ERROR", username != null ? username : "UNKNOWN", 
                "Client handler error: " + e.getMessage());
        } finally {
            cleanup();
        }
    }
    
    private boolean handleUserAuthentication() {
        try {
            // Receive authentication request
            AuthRequest authRequest = (AuthRequest) input.readObject();
            username = authRequest.username;
            clientPublicKey = authRequest.publicKey;
            
            auditLogger.logEvent("AUTH_REQUEST_RECEIVED", username, 
                "Authentication request received, isRegistration: " + authRequest.isRegistration);
            
            AuthResponse response;
            
            if (authRequest.isRegistration) {
                // Handle registration
                if (server.getUserDatabase().userExists(username)) {
                    response = new AuthResponse(false, "Username already exists");
                    auditLogger.logEvent("REGISTRATION_FAILED", username, "Username already exists");
                } else {
                    server.getUserDatabase().createUser(username, authRequest.passwordHash, clientPublicKey);
                    response = new AuthResponse(true, "Registration successful");
                    auditLogger.logEvent("REGISTRATION_SUCCESS", username, "User registered successfully");
                }
            } else {
                // Handle login
                if (server.getUserDatabase().authenticateUser(username, authRequest.passwordHash, clientPublicKey)) {
                    response = new AuthResponse(true, "Login successful");
                    auditLogger.logEvent("LOGIN_SUCCESS", username, "User logged in successfully");
                } else {
                    response = new AuthResponse(false, "Invalid credentials");
                    auditLogger.logEvent("LOGIN_FAILED", username, "Invalid credentials provided");
                }
            }
            
            // Send authentication response
            output.writeObject(response);
            output.flush();
            
            return response.success;
            
        } catch (Exception e) {
            auditLogger.logEvent("USER_AUTH_ERROR", username != null ? username : "UNKNOWN", 
                "User authentication error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    private boolean performMutualAuthentication() {
        try {
            auditLogger.logEvent("MUTUAL_AUTH_START", username, "Starting mutual authentication");
            
            // Challenge-response authentication
            String challenge = UUID.randomUUID().toString();
            output.writeObject(challenge);
            output.flush();
            auditLogger.logEvent("CHALLENGE_SENT", username, "Authentication challenge sent");
            
            // Receive signed challenge from client
            byte[] signedChallenge = (byte[]) input.readObject();
            
            // Verify client's signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(clientPublicKey);
            signature.update(challenge.getBytes());
            
            if (!signature.verify(signedChallenge)) {
                output.writeObject("AUTH_FAILED");
                auditLogger.logEvent("CLIENT_SIGNATURE_FAILED", username, "Client signature verification failed");
                return false;
            }
            
            auditLogger.logEvent("CLIENT_SIGNATURE_VERIFIED", username, "Client signature verified successfully");
            
            // Server signs client's challenge for mutual auth
            String clientChallenge = (String) input.readObject();
            signature.initSign(serverPrivateKey);
            signature.update(clientChallenge.getBytes());
            byte[] serverSignedChallenge = signature.sign();
            
            output.writeObject("AUTH_SUCCESS");
            output.writeObject(serverSignedChallenge);
            output.flush();
            
            auditLogger.logEvent("MUTUAL_AUTH_SUCCESS", username, "Mutual authentication completed successfully");
            return true;
            
        } catch (Exception e) {
            auditLogger.logEvent("MUTUAL_AUTH_ERROR", username, "Mutual authentication error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    private void handleMessages() {
        try {
            while (true) {
                Object message = input.readObject();
                
                if (message instanceof ChatMessage) {
                    ChatMessage chatMsg = (ChatMessage) message;
                    
                    // Check timestamp for replay attack prevention
                    long currentTime = System.currentTimeMillis();
                    if (Math.abs(currentTime - chatMsg.timestamp) > 300000 || // 5 minutes window
                        usedTimestamps.contains(chatMsg.timestamp)) {
                        auditLogger.logEvent("REPLAY_ATTACK_BLOCKED", username, 
                            "Blocked replay attack or old message, timestamp: " + chatMsg.timestamp);
                        continue; // Ignore replayed or old messages
                    }
                    usedTimestamps.add(chatMsg.timestamp);
                    
                    // Log message forwarding
                    auditLogger.logEvent("MESSAGE_FORWARDED", username, 
                        "Message forwarded from " + chatMsg.sender + " to " + chatMsg.recipient);
                    
                    // Forward message to recipient
                    ClientHandler recipient = server.getClient(chatMsg.recipient);
                    if (recipient != null) {
                        recipient.forwardMessage(chatMsg);
                    } else {
                        auditLogger.logEvent("MESSAGE_RECIPIENT_NOT_FOUND", username, 
                            "Recipient " + chatMsg.recipient + " not found");
                    }
                } else if (message instanceof KeyRotationMessage) {
                    KeyRotationMessage keyRotMsg = (KeyRotationMessage) message;
                    
                    // Log key rotation
                    auditLogger.logEvent("KEY_ROTATION_FORWARDED", username, 
                        "Key rotation message forwarded from " + keyRotMsg.sender + " to " + keyRotMsg.recipient);
                    
                    // Forward key rotation message to recipient
                    ClientHandler recipient = server.getClient(keyRotMsg.recipient);
                    if (recipient != null) {
                        recipient.forwardKeyRotation(keyRotMsg);
                    }
                } else if (message instanceof PublicKeyRequest) {
                    // Handle public key requests
                    handlePublicKeyRequest((PublicKeyRequest) message);
                }
                
            }
        } catch (Exception e) {
            System.err.println("Message handling error for " + username + ": " + e.getMessage());
            auditLogger.logEvent("MESSAGE_HANDLING_ERROR", username, "Message handling error: " + e.getMessage());
        }
    }
    
    private void handlePublicKeyRequest(PublicKeyRequest request) {
        try {
            auditLogger.logEvent("PUBKEY_REQUEST", request.requester, 
                "Requesting public key for user: " + request.targetUser);
            
            PublicKey targetPublicKey = server.getUserPublicKey(request.targetUser);
            PublicKeyResponse response = new PublicKeyResponse(request.targetUser, 
                targetPublicKey, targetPublicKey != null);
            
            output.writeObject(response);
            output.flush();
            
            auditLogger.logEvent("PUBKEY_RESPONSE", request.requester, 
                "Public key response sent for user: " + request.targetUser + 
                ", success: " + response.success);
                
        } catch (Exception e) {
            auditLogger.logEvent("PUBKEY_REQUEST_ERROR", request.requester, 
                "Error handling public key request: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public void forwardMessage(ChatMessage message) {
        try {
            output.writeObject(message);
            output.flush();
        } catch (IOException e) {
            auditLogger.logEvent("MESSAGE_FORWARD_ERROR", username, "Error forwarding message: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public void forwardKeyRotation(KeyRotationMessage message) {
        try {
            output.writeObject(message);
            output.flush();
        } catch (IOException e) {
            auditLogger.logEvent("KEY_ROTATION_FORWARD_ERROR", username, 
                "Error forwarding key rotation: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public void sendUserList(Set<String> users) {
        try {
            output.writeObject(new UserListMessage(users));
            output.flush();
        } catch (IOException e) {
            auditLogger.logEvent("USER_LIST_SEND_ERROR", username, "Error sending user list: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public String getUsername() {
        return username;
    }
    
    public PublicKey getPublicKey() {
        return clientPublicKey;
    }
    
    private void cleanup() {
        try {
            if (username != null) {
                server.removeClient(username);
                auditLogger.logEvent("CLIENT_CLEANUP", username, "Client handler cleanup completed");
            }
            clientSocket.close();
        } catch (IOException e) {
            auditLogger.logEvent("CLEANUP_ERROR", username != null ? username : "UNKNOWN", 
                "Error during cleanup: " + e.getMessage());
            e.printStackTrace();
        }
    }
}