package com.netrork.pine.security.auth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String username;
    private String password;
    private String email;

}
