package com.netrork.pine.security.auth;


import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NewAccessTokenResponse {
    private String access_token;
}
