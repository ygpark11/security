package com.test.security.authentication.service;

import com.test.security.domain.Account;
import com.test.security.dto.UserDto;
import com.test.security.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;

@Slf4j
@Service
public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HttpServletRequest request;

    @Override
    public UserDto loadUserByUsername(String username) throws UsernameNotFoundException {
        //IP 제한할 때 여기서 제한
        /*String ip = request.getRemoteAddr();
        if (loginAttemptService.isBlocked(ip)) {
            throw new RuntimeException("blocked");
        }*/
        Account account = userRepository.findByEmailAndUseYn(username, "Y");
        if (account == null) {
            throw new UsernameNotFoundException("No user found with username: " + username);
        }

        return new UserDto(account, new ArrayList<String>(Arrays.asList("ROLE_USER")));
    }
}
