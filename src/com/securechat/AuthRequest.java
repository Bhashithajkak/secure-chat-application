package com.securechat;

import java.io.Serializable;
import java.security.PublicKey;

//AuthRequest class for login/registration
public class AuthRequest implements Serializable {
 private static final long serialVersionUID = 1L;
 
 public String username;
 public String passwordHash;
 public PublicKey publicKey;
 public boolean isRegistration;
 
 public AuthRequest(String username, String passwordHash, PublicKey publicKey, boolean isRegistration) {
     this.username = username;
     this.passwordHash = passwordHash;
     this.publicKey = publicKey;
     this.isRegistration = isRegistration;
 }
}
