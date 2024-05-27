package com.netrork.pine.security.userdetails;

import com.netrork.pine.security.roles.Role;
import com.netrork.pine.security.users.User;
import com.netrork.pine.security.users.UserRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class OurUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
/*
        User user = userRepository.findByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("OurUserDetailsService-: Username not found"));

        Set<GrantedAuthority> authorities = new HashSet<>();

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities);*/

        return userRepository.findByUsername(username)
                .map(this::createUserDetails)
                .orElseThrow(()->new UsernameNotFoundException("Username not found"));

    }

    private UserDetails createUserDetails(User user) {
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities());
    }

}
