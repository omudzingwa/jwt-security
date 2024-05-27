package com.netrork.pine.security.jwtutils;

import com.netrork.pine.security.refreshtokens.RefreshToken;
import com.netrork.pine.security.refreshtokens.RefreshTokenRepository;
import com.netrork.pine.security.refreshtokens.RefreshTokenService;
import com.netrork.pine.security.roles.Role;
import com.netrork.pine.security.users.UserService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Duration;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String encodedString;
    private final long accessTokenValidityTime = Duration.ofMinutes(10).toMillis();
    private final long refreshTokenValidityTime = Duration.ofMinutes(30).toMillis();

    private final UserService userService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenService refreshTokenService;

    private SecretKey getSigningKey(){
        byte[] keyBytes = Decoders.BASE64.decode(encodedString);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(long id, String username, Role role){
        Claims claims = Jwts.claims().subject(username)
                .add("id",id)
                .add("scope","access")
                .add("role",role.name())
                .build();

        Date now = new Date();

        return Jwts.builder()
                .header()
                .add("typ","JWT")
                .and()
                .issuer("Netrork")
                .claims(claims)
                .issuedAt(new Date(now.getTime()))
                .expiration(new Date(System.currentTimeMillis()+accessTokenValidityTime))
                .signWith(getSigningKey())
                .compact();
    }

    public RefreshToken createRefreshToken(long user_id){

        //Validate user_id by checking if the user_id exists in the database
        boolean useExists = userExists(user_id);

        if (!useExists){
            throw new RuntimeException("User not found");
        }

        var refresh_token = RefreshToken.builder()
                .user_id(user_id)
                .refresh_token(UUID.randomUUID().toString())
                .expiry_date(new Date(System.currentTimeMillis()+refreshTokenValidityTime))
                .build();

        refreshTokenRepository.save(refresh_token);

        return refresh_token;

    }

    private boolean userExists(long user_id){
        Optional<Long> userId = Optional.of(userService.findUserIdById(user_id));
        if(userId.isPresent()){
            return true;
        }
        return false;
    }

    public String regenerateAccessToken(String refresh_token, UserDetails userDetails){
        //Validate the Refresh Token by checking if the token belongs to user, if the token exists and if the token has not expired

        //1 - Get user_id from refresh_token
        Long userId = refreshTokenService.findUserIdFromTokenByTokenValue(refresh_token);
        if(userId==null){
            throw new RuntimeException("User Id for token supplied refresh token not found");
        }

        //2 - get username from token and compare it with username from userdetails
        String usernameToCheck = refreshTokenService.getUsernameForTokenByUserId(userId);

        //3 - check if username return is the same as UserDetails username
        if(!usernameToCheck.equals(userDetails.getUsername())){
            throw new RuntimeException("The supplied token doesn't belong to the user");
        }

        //4 - Check to see if the token as expired or not.

        Date expiryDate = refreshTokenService.getExpiryDateFromRefreshToken(refresh_token);
        if(expiryDate.before(new Date(System.currentTimeMillis()))){
            refreshTokenService.deleteTokenByTokenValue(refresh_token);
            throw new RuntimeException("Refresh Token has expired, login again to generate new refresh_token");
        }

        //5 - Get User role based on user_id in refresh token
        String role = userService.findUserRoleByUserId(userId);
        return createAccessToken(userId,usernameToCheck, Role.valueOf(role));

    }

    public String getUsernameFromToken(String token){
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    Date getExpiryDateFromToken(String token){
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        String username = getUsernameFromToken(token);
        log.info("JwtTokenProvider: IsTokenValid Method username is : " + username);
        log.info("JwtTokenProvider: IsTokenValid Method userDetails username is : "+ userDetails.getUsername());
        log.info("The statement that isTokenExpired =" + isTokenExpired(token));
        //return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        if(username.equals(userDetails.getUsername()) && !isTokenExpired(token)){
            return true;
        }
        return false;
    }

    public boolean isTokenExpired(String token){
        Date expirydate = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();

        if(expirydate.after(new Date(System.currentTimeMillis()))){
            return false;
        }
        else return true;
    }

    public long getUserIdFromToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("user_id", Long.class);
    }


    public boolean isAccessTokenValid(String token) throws Exception {
        try {
            Jwts.parser()
                    .verifyWith((SecretKey) getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return true;
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException("Invalid JWT token.");
        } catch (ExpiredJwtException e) {
            throw new Exception("Expired JWT token");
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtException("Unsupported JWT token.");
        } catch (NullPointerException e) {
            throw new NullPointerException("JWT Token is empty.");
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("JWT claims string is empty,  CharSequence cannot be null or empty");
        }

    }
}
