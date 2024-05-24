package com.netrork.pine.security.auth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {
    private String access_token;
    private String refresh_token;
}
