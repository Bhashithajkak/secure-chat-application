package com.securechat;

import java.io.*;
import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class UserDatabase {
    private Map<String, UserRecord> users;
    private final String DATABASE_FILE = "users.dat";
    
    public UserDatabase() {
        this.users = new ConcurrentHashMap<>();
        loadDatabase();
    }
    
    public synchronized boolean createUser(String username, String passwordHash, PublicKey publicKey) {
        if (users.containsKey(username)) {
            return false;
        }
        
        UserRecord user = new UserRecord(username, passwordHash, publicKey);
        users.put(username, user);
        saveDatabase();
        System.out.println("User '" + username + "' registered successfully");
        return true;
    }
    
    public synchronized boolean authenticateUser(String username, String passwordHash, PublicKey providedKey) {
        UserRecord user = users.get(username);
        if (user == null) {
            return false;
        }
        
        // Verify password hash and public key
        boolean passwordValid = user.passwordHash.equals(passwordHash);
        boolean keyValid = user.publicKey.equals(providedKey);
        
        if (passwordValid && keyValid) {
            System.out.println("User '" + username + "' authenticated successfully");
            return true;
        } else {
            System.out.println("Authentication failed for user '" + username + "'");
            if (!passwordValid) {
                System.out.println("  - Invalid password");
            }
            if (!keyValid) {
                System.out.println("  - Invalid public key");
            }
            return false;
        }
    }
    
    public synchronized boolean userExists(String username) {
        return users.containsKey(username);
    }
    
    public synchronized UserRecord getUser(String username) {
        return users.get(username);
    }
    
    private void saveDatabase() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(DATABASE_FILE))) {
            oos.writeObject(users);
            System.out.println("User database saved successfully");
        } catch (IOException e) {
            System.err.println("Error saving user database: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    @SuppressWarnings("unchecked")
    private void loadDatabase() {
        File dbFile = new File(DATABASE_FILE);
        if (!dbFile.exists()) {
            System.out.println("No existing user database found. Starting with empty database.");
            return;
        }
        
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(DATABASE_FILE))) {
            users = (Map<String, UserRecord>) ois.readObject();
            System.out.println("User database loaded successfully. Users: " + users.size());
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error loading user database: " + e.getMessage());
            System.out.println("Starting with empty database.");
            users = new ConcurrentHashMap<>();
        }
    }
    
    // Inner class to represent user records
    public static class UserRecord implements Serializable {
        private static final long serialVersionUID = 1L;
        
        public String username;
        public String passwordHash;
        public PublicKey publicKey;
        public long registrationTime;
        
        public UserRecord(String username, String passwordHash, PublicKey publicKey) {
            this.username = username;
            this.passwordHash = passwordHash;
            this.publicKey = publicKey;
            this.registrationTime = System.currentTimeMillis();
        }
        
        @Override
        public String toString() {
            return "UserRecord{username='" + username + "', registrationTime=" + 
                   new java.util.Date(registrationTime) + "}";
        }
    }
}