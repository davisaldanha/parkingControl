package com.example.parkingcontrol.models;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.stream.Collectors;

public class UserPrincipal {

    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    private UserPrincipal(UserModel user){
        this.username = user.getUsername();
        this.password  = user.getPassword();

        this.authorities = user.getRoles().stream()
                .map(role -> {
                    return new SimpleGrantedAuthority("ROLE_".concat(role.getName()));
                }).collect(Collectors.toList());
    }

    public static UserPrincipal create(UserModel user){
        return new UserPrincipal(user);
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
