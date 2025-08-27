package com.securechat;

import java.io.Serializable;
import java.util.Set;

public class UserListMessage implements Serializable {
    private static final long serialVersionUID = 1L;
    
    public Set<String> users;
    
    public UserListMessage(Set<String> users) {
        this.users = users;
    }
}
