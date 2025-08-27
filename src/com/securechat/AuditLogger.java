package com.securechat;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class AuditLogger {
    private PrintWriter logWriter;
    private String logFileName;
    private SimpleDateFormat dateFormat;
    
    public AuditLogger(String logFileName) {
        this.logFileName = logFileName;
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        initializeLogger();
    }
    
    private void initializeLogger() {
        try {
            // Create log file if it doesn't exist
            File logFile = new File(logFileName);
            boolean isNewFile = !logFile.exists();
            
            // Open file in append mode
            FileWriter fileWriter = new FileWriter(logFile, true);
            logWriter = new PrintWriter(fileWriter, true); // Auto-flush enabled
            
            if (isNewFile) {
                writeHeader();
            }
            
            System.out.println("Audit logging initialized: " + logFileName);
            
        } catch (IOException e) {
            System.err.println("Failed to initialize audit logger: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void writeHeader() {
        logWriter.println("=".repeat(80));
        logWriter.println("SECURE CHAT APPLICATION - AUDIT LOG");
        logWriter.println("Log started: " + dateFormat.format(new Date()));
        logWriter.println("=".repeat(80));
        logWriter.println("FORMAT: [TIMESTAMP] [EVENT_TYPE] [USER] [DESCRIPTION]");
        logWriter.println("=".repeat(80));
    }
    
    public synchronized void logEvent(String eventType, String username, String description) {
        if (logWriter == null) {
            System.err.println("Audit logger not initialized. Cannot log event.");
            return;
        }
        
        try {
            String timestamp = dateFormat.format(new Date());
            String logEntry = String.format("[%s] [%s] [%s] %s", 
                timestamp, eventType, username != null ? username : "UNKNOWN", description);
            
            logWriter.println(logEntry);
            logWriter.flush(); // Ensure immediate write to file
            
            // Also print critical events to console
            if (isCriticalEvent(eventType)) {
                System.out.println("AUDIT: " + logEntry);
            }
            
        } catch (Exception e) {
            System.err.println("Error writing to audit log: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private boolean isCriticalEvent(String eventType) {
        return eventType.contains("FAILED") || 
               eventType.contains("ERROR") || 
               eventType.contains("ATTACK") ||
               eventType.equals("AUTHENTICATION_SUCCESS") ||
               eventType.equals("REGISTRATION_SUCCESS") ||
               eventType.equals("LOGIN_SUCCESS") ||
               eventType.equals("SERVER_START") ||
               eventType.equals("SERVER_SHUTDOWN");
    }
    
    public void logSecurityEvent(String eventType, String username, String description, String severity) {
        String securityLogEntry = String.format("[SECURITY-%s] %s", severity, description);
        logEvent(eventType, username, securityLogEntry);
        
        // Always print security events to console
        System.out.println("SECURITY ALERT [" + severity + "]: " + eventType + " - " + username + " - " + description);
    }
    
    public void logAuthenticationAttempt(String username, String result, String details) {
        String eventType = "AUTH_ATTEMPT_" + result.toUpperCase();
        logEvent(eventType, username, "Authentication attempt: " + result + " - " + details);
    }
    
    public void logKeyExchange(String user1, String user2, String result) {
        String eventType = "KEY_EXCHANGE_" + result.toUpperCase();
        String description = String.format("Key exchange between %s and %s: %s", user1, user2, result);
        logEvent(eventType, user1, description);
    }
    
    public void logMessageTransfer(String sender, String recipient, boolean encrypted) {
        String eventType = encrypted ? "ENCRYPTED_MESSAGE_SENT" : "PLAIN_MESSAGE_SENT";
        String description = String.format("Message from %s to %s (encrypted: %s)", sender, recipient, encrypted);
        logEvent(eventType, sender, description);
    }
    
    public void close() {
        if (logWriter != null) {
            logEvent("AUDIT_LOG_CLOSED", "SYSTEM", "Audit logging session ended");
            logWriter.println("=".repeat(80));
            logWriter.println("Log ended: " + dateFormat.format(new Date()));
            logWriter.println("=".repeat(80));
            logWriter.close();
            System.out.println("Audit log closed: " + logFileName);
        }
    }
    
    // Method to get log file statistics
    public String getLogStats() {
        try {
            File logFile = new File(logFileName);
            if (logFile.exists()) {
                long fileSize = logFile.length();
                long lastModified = logFile.lastModified();
                return String.format("Log file: %s, Size: %d bytes, Last modified: %s", 
                    logFileName, fileSize, new Date(lastModified));
            } else {
                return "Log file does not exist: " + logFileName;
            }
        } catch (Exception e) {
            return "Error getting log stats: " + e.getMessage();
        }
    }
}