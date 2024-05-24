package com.netrork.pine.security.logoututils;


import com.netrork.pine.security.refreshtokens.RefreshTokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler {

    private final RefreshTokenService refreshTokenService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = request.getHeader("refresh_token");
        //1 - Check if token exists in database
        if(refreshTokenService.findTokenByValue(token).isPresent()){
            refreshTokenService.deleteTokenByTokenValue(token);
        }
        else if(refreshTokenService.findTokenByValue(token).isPresent()){
            throw new RuntimeException("The token mismatch detected");
        }
    }

}
