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
    public Optional<User> findByUsername(String username){
        return userRepository.findByUsername(username);
    }

    public String findAndReturnUsernameOnly(String username){
        return userRepository.findAndReturnUsernameOnly(username);
    }

    public long findUserIdByUsername(String username){
        return userRepository.findUserIdByUsername(username);
    }

    public String findUsernameById(long id){
        return userRepository.findUsernameById(id);
    }

    public String findUserRoleByUsername(String username){
        return userRepository.findUserRoleByUsername(username);
    }

    public String findUserRoleByUserId(long id){
        return userRepository.findUserRoleByUserId(id);
    }

    public long findUserIdById(long id){
        return userRepository.findUserIdById(id).orElseThrow(()->new RuntimeException("User Id not found"));
    }

}
