package com.securechat;

import java.io.Serializable;
import java.security.PublicKey;

public class PublicKeyRequest implements Serializable {
    private static final long serialVersionUID = 1L;
    
    public String requester;
    public String targetUser;
    
    public PublicKeyRequest(String requester, String targetUser) {
        this.requester = requester;
        this.targetUser = targetUser;
    }
}

class PublicKeyResponse implements Serializable {
    private static final long serialVersionUID = 1L;
    
    public String targetUser;
    public PublicKey publicKey;
    public boolean success;
    
    public PublicKeyResponse(String targetUser, PublicKey publicKey, boolean success) {
        this.targetUser = targetUser;
        this.publicKey = publicKey;
        this.success = success;
    }
}