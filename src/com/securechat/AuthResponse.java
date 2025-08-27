package com.securechat;

import java.io.Serializable;

public class AuthResponse implements Serializable {
 private static final long serialVersionUID = 1L;
 
 public boolean success;
 public String message;
 
 public AuthResponse(boolean success, String message) {
     this.success = success;
     this.message = message;
 }
}