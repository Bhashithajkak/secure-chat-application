package com.securechat;

import java.io.Serializable;

public class KeyRotationMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    public String sender;
    public String recipient;
    public byte[] newDHPublicKey;
    public long timestamp;
    public boolean isEncrypted; 

    // Original constructor (unencrypted)
    public KeyRotationMessage(String sender, String recipient, byte[] newDHPublicKey, long timestamp) {
        this.sender = sender;
        this.recipient = recipient;
        this.newDHPublicKey = newDHPublicKey;
        this.timestamp = timestamp;
        this.isEncrypted = false;
    }

    // Constructor with encryption option
    public KeyRotationMessage(String sender, String recipient, byte[] newDHPublicKey, 
                             long timestamp, boolean isEncrypted) {
        this.sender = sender;
        this.recipient = recipient;
        this.newDHPublicKey = newDHPublicKey;
        this.timestamp = timestamp;
        this.isEncrypted = isEncrypted;
    }
}