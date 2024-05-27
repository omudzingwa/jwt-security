package com.netrork.pine.security.logoututils;


import com.netrork.pine.security.refreshtokens.RefreshTokenService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class CustomLogoutHandler implements LogoutHandler {

    private final RefreshTokenService refreshTokenService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        String token = request.getHeader("refresh_token");
        log.info("Length for Token is : " + token.length());

        log.info("Fetching token from Database");
        String tokenFromDatabase = refreshTokenService.findTokenByValue(token)
                .orElseThrow(()-> new RuntimeException("Token not found"));
        log.info("Token from Database is : " + tokenFromDatabase);
        log.info("Token from Request  is : " + token);

        //1 - Check if token exists in database
        if(token.equals(tokenFromDatabase)){

            long userId=refreshTokenService.findUserIdFromTokenByTokenValue(token);

            String username= refreshTokenService.getUsernameForTokenByUserId(userId);

            refreshTokenService.deleteTokenByTokenValue(token);
            log.info("Deleted Refresh token for user : " + username);

            SecurityContextHolder.clearContext();

            try {
                request.logout();
                log.info("Logged out User : " + username);

            } catch (ServletException e) {
                throw new RuntimeException(e);
            }
        }
        else if(refreshTokenService.findTokenByValue(token).isEmpty()){
            throw new RuntimeException("The token mismatch detected");
        }
    }

}
