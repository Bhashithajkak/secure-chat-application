package com.securechat;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class ChatServer {
    private ServerSocket serverSocket;
    private Map<String, ClientHandler> clients;
    private Map<String, PublicKey> publicKeys;
    private UserDatabase userDatabase;
    private AuditLogger auditLogger;
    private static final int PORT = 8080;

    public ChatServer() {
        clients = new ConcurrentHashMap<>();
        publicKeys = new ConcurrentHashMap<>();
        userDatabase = new UserDatabase();
        auditLogger = new AuditLogger("server_audit.log");
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("Chat Server started on port " + PORT);
        System.out.println("Waiting for clients to connect...");
        auditLogger.logEvent("SERVER_START", "SYSTEM", "Server started on port " + PORT);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            ClientHandler clientHandler = new ClientHandler(clientSocket, this);
            new Thread(clientHandler).start();
            auditLogger.logEvent("CLIENT_CONNECTION", "SYSTEM", "New client connection from " + clientSocket.getInetAddress());
        }
    }

    public synchronized void addClient(String username, ClientHandler handler, PublicKey publicKey) {
        clients.put(username, handler);
        publicKeys.put(username, publicKey);
        System.out.println("User '" + username + "' connected successfully");
        auditLogger.logEvent("USER_CONNECTED", username, "User connected successfully");
        broadcastUserList();
    }

    public synchronized void removeClient(String username) {
        clients.remove(username);
        publicKeys.remove(username);
        System.out.println("User '" + username + "' disconnected");
        auditLogger.logEvent("USER_DISCONNECTED", username, "User disconnected");
        broadcastUserList();
    }
    
    public synchronized PublicKey getUserPublicKey(String username) {
        UserDatabase.UserRecord user = userDatabase.getUser(username);
        return user != null ? user.publicKey : null;
    }

    public synchronized Set<String> getOnlineUsers() {
        return new HashSet<>(clients.keySet());
    }

    public synchronized ClientHandler getClient(String username) {
        return clients.get(username);
    }

    public synchronized PublicKey getPublicKey(String username) {
        return publicKeys.get(username);
    }

    public UserDatabase getUserDatabase() {
        return userDatabase;
    }

    public AuditLogger getAuditLogger() {
        return auditLogger;
    }

    private void broadcastUserList() {
        Set<String> users = getOnlineUsers();
        for (ClientHandler handler : clients.values()) {
            handler.sendUserList(users);
        }
    }

    public void stop() throws IOException {
        auditLogger.logEvent("SERVER_SHUTDOWN", "SYSTEM", "Server shutting down");
        if (serverSocket != null) {
            serverSocket.close();
        }
        auditLogger.close();
    }

    // Main method
    public static void main(String[] args) {
        System.out.println("=== Secure Chat Server ===");
        System.out.println("Starting server...");

        ChatServer server = new ChatServer();

        // Add shutdown hook for graceful shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                System.out.println("\nShutting down server...");
                server.stop();
            } catch (IOException e) {
                System.err.println("Error during shutdown: " + e.getMessage());
            }
        }));

        try {
            server.start();
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}