package com.test.security.authentication.provider;

import com.test.security.authentication.service.CustomUserDetailService;
import com.test.security.dto.UserDto;
import com.test.security.token.AjaxAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
public class AjaxAuthenticationProvider implements AuthenticationProvider {

    private CustomUserDetailService userDetailsService;

    private PasswordEncoder passwordEncoder;

    public AjaxAuthenticationProvider(CustomUserDetailService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public Authentication authenticate(Authentication auth) throws AuthenticationException {

        String loginId = auth.getName();
        String passwd = (String) auth.getCredentials();

        UserDto userDetails = null;
        try {
            // 사용자 조회
            userDetails = userDetailsService.loadUserByUsername(loginId);

            if (userDetails == null || !passwordEncoder.matches(passwd, userDetails.getPassword())) {
                throw new BadCredentialsException("Invalid password");
            }

        } catch(UsernameNotFoundException e) {
            log.info(e.toString());
            throw new UsernameNotFoundException(e.getMessage());
        } catch(BadCredentialsException e) {
            log.info(e.toString());
            throw new BadCredentialsException(e.getMessage());
        } catch(Exception e) {
            log.info(e.toString());
            throw new RuntimeException(e.getMessage());
        }

        return AjaxAuthenticationToken.getTokenFromAccountContext(userDetails);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
