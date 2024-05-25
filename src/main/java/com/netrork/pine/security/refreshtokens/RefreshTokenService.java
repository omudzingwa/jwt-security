package com.netrork.pine.security.refreshtokens;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public Optional<String> findTokenByValue(String token){
        return refreshTokenRepository.findTokenByTokenValue(token);
    }

    public Optional<String> findTokenByUserId(Optional<Long> user_id){
        return refreshTokenRepository.findTokenByUserId(user_id);
    }

    public long findUserIdFromTokenByTokenValue(String token){
        return refreshTokenRepository.findUserIdFromTokenByTokenValue(token);
    }

    public String getUsernameForTokenByUserId(long user_id){
        return refreshTokenRepository.getUsernameForTokenByUserId(user_id);
    }

    public Date getExpiryDateFromRefreshToken(String token){
        return refreshTokenRepository.getExpiryDateFromRefreshToken(token);
    }

    public void deleteTokenByTokenValue(String token){
        refreshTokenRepository.deleteTokenByTokenValue(token);
    }

    public void deleteTokenByUserId(long user_id){
        refreshTokenRepository.deleteTokenByUserId(user_id);
    }

}
