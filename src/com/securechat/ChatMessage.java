package com.securechat;

import java.io.*;
;

// ChatMessage class for encrypted messages
public class ChatMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    public String sender;
    public String recipient;
    public byte[] encryptedMessage;
    public long timestamp;
    public byte[] dhPublicKey;
    public boolean isKeyExchange;
    public boolean isDHEncrypted;

    public ChatMessage(String sender, String recipient, byte[] encryptedMessage, long timestamp) {
        this.sender = sender;
        this.recipient = recipient;
        this.encryptedMessage = encryptedMessage;
        this.timestamp = timestamp;
        this.isKeyExchange = false;
        this.isDHEncrypted = false;
    }

    public ChatMessage(String sender, String recipient, byte[] dhPublicKey, long timestamp, boolean isKeyExchange) {
        this.sender = sender;
        this.recipient = recipient;
        this.dhPublicKey = dhPublicKey;
        this.timestamp = timestamp;
        this.isKeyExchange = isKeyExchange;
        this.isDHEncrypted = false;
    }
    
    public ChatMessage(String sender, String recipient, byte[] dhPublicKey, long timestamp, 
            boolean isKeyExchange, boolean isDHEncrypted) {
		this.sender = sender;
		this.recipient = recipient;
		this.dhPublicKey = dhPublicKey;
		this.timestamp = timestamp;
		this.isKeyExchange = isKeyExchange;
		this.isDHEncrypted = isDHEncrypted;
	}
}


