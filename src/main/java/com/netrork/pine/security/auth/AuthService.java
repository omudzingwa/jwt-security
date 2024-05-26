package com.netrork.pine.security.auth;

import com.netrork.pine.security.departments.Department;
import com.netrork.pine.security.jwtutils.JwtTokenProvider;
import com.netrork.pine.security.refreshtokens.RefreshToken;
import com.netrork.pine.security.refreshtokens.RefreshTokenService;
import com.netrork.pine.security.roles.Role;
import com.netrork.pine.security.userdetails.OurUserDetailsService;
import com.netrork.pine.security.users.User;
import com.netrork.pine.security.users.UserRepository;
import com.netrork.pine.security.users.UserService;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final OurUserDetailsService ourUserDetailsService;

    public void registerUser(RegisterRequest registerRequest){

        //1 - Check if username already exists or not
        Optional<User> userToCheck = userRepository.findByUsername(registerRequest.getUsername());

        if(userToCheck.isPresent()){
            throw new RuntimeException(userToCheck + " : Username already exists, kindly find another name to use");
        }

        var user = User.builder()
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                .username(registerRequest.getUsername())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .email(registerRequest.getEmail())
                .department(Department.GENERAL)
                .role(Role.USER)
                .build();

        userRepository.save(user);



    }

    public LoginResponse login(LoginRequest loginRequest) throws Exception {
        //1 - Check if username exists or not
        validateLoginRequest(loginRequest.getUsername());

        //2 - Check if the user already has Refresh Tokens and if yes delete.
        long userId = userService.findUserIdByUsername(loginRequest.getUsername());

        String oldRefreshToken = String.valueOf(refreshTokenService.findTokenByUserId(Optional.of(userId)));
        //If the user already has an existing refresh token, proceed to delete it
        if(oldRefreshToken!=null){
            refreshTokenService.deleteTokenByTokenValue(oldRefreshToken);
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
        );

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String username = userRepository.findAndReturnUsernameOnly(loginRequest.getUsername());
        long user_id = userService.findUserIdByUsername(username);
        log.info("User_id at login is : " + user_id);

        String role = userService.findUserRoleByUserId(userId);


        String access_token = jwtTokenProvider.createAccessToken(user_id,username,Role.valueOf(role));
        //String access_token = jwtTokenProvider.createAccessToken(Optional.of(user_id),username, Role.valueOf(role));
        String refresh_token = jwtTokenProvider.createRefreshToken(user_id).getRefresh_token();

        return LoginResponse.builder()
                .access_token(access_token)
                .refresh_token(refresh_token)
                .build();
    }

    private void validateLoginRequest(String username) throws Exception {
        String user_name = userService.findAndReturnUsernameOnly(username);
        if(user_name==null){
            throw new UsernameNotFoundException("Username not found");
        }
    }

    public NewAccessTokenResponse generateNewAccessToken(NewAccessTokenRequest newAccessTokenRequest){

        String refresh_token = newAccessTokenRequest.getRefresh_token();
        //Get user_id from refresh token
        long refreshTokenUserId = refreshTokenService.findUserIdFromTokenByTokenValue(refresh_token);
        if(refreshTokenUserId>0){
            //Use the user_id to get the matching username
            String username = userService.findUsernameById(refreshTokenUserId);
            //Create the user details object to be used to check if the token belong to the user during creating of new AccessToken
            UserDetails userDetails = ourUserDetailsService.loadUserByUsername(username);
            //With all details set proceed to create the new AccessToken
            String access_token = jwtTokenProvider.regenerateAccessToken(newAccessTokenRequest.getRefresh_token(),userDetails);

            return NewAccessTokenResponse.builder()
                    .access_token(access_token)
                    .build();
        }
        else
            throw new RuntimeException("An issue has been encountered with the supplied Refresh token");
    }

}
