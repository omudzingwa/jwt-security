package com.netrork.pine.security.endpoints;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/endpoints")
public class EndPoints {

    @PreAuthorize("hasAuthority('USER')")
    @GetMapping("/user")
    public String ordinaryUsersOnly(){
        return "Ordinary users only";
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/admin")
    public String adminUsersOnly(){
        return "Admin users only";
    }

    @PreAuthorize("hasAuthority('EXECUTIVE')")
    @GetMapping("/executive")
    public String executiveUsersOnly(){
        return "Admin users only";
    }


}
