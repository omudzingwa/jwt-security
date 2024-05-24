package com.netrork.pine.security.users;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public void saveUser(User user){
        userRepository.save( user);
    }
    public String findAndReturnUsernameOnly(String username){
        return userRepository.findAndReturnUsernameOnly(username)
                .orElseThrow(()-> new UsernameNotFoundException("Username not found"));
    }

    public long findUserIdByUsername(String username){
        return userRepository.findUserIdByUsername(username);
    }

    public String findUsernameById(Optional<Long> id){
        return userRepository.findUsernameById(id);
    }

    public String findUserRoleByUsername(String username){
        return userRepository.findUserRoleByUsername(username);
    }

    public String findUserRoleByUserId(Optional<Long> id){
        return userRepository.findUserRoleByUserId(id);
    }

    public long findUserIdById(long id){
        return userRepository.findUserIdById(id).orElseThrow(()->new RuntimeException("User Id not found"));
    }

}
