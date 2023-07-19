package com.test.security.authentication.service;

import com.test.security.domain.Account;
import lombok.Data;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;
import java.util.stream.Collectors;

public class CustomUserDetail extends User {
    private Account account;
    private List<String> roles;

    public CustomUserDetail(Account account, List<String> roles) {
        super(account.getUsername(), account.getPassword(), roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        this.account = account;
        this.roles = roles;
    }
}
