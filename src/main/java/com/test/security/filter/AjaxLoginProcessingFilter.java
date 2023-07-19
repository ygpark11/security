package com.test.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.security.dto.AuthenticationRequest;
import com.test.security.dto.UserDto;
import com.test.security.exception.AuthMethodNotSupportedException;
import com.test.security.token.AjaxAuthenticationToken;
import com.test.util.WebUtil;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import static org.springframework.util.StringUtils.*;

@Slf4j
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private static Logger logger = LoggerFactory.getLogger(AjaxLoginProcessingFilter.class);

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {

        ObjectMapper objectMapper = new ObjectMapper();

        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            throw new AuthMethodNotSupportedException("Authentication method not supported");
        }

        AuthenticationRequest user = objectMapper.readValue(request.getReader(), AuthenticationRequest.class);

        if (isEmpty(user.getUsername()) || isEmpty(user.getPassword())) {
            throw new AuthenticationServiceException("Username or Password not provided");
        }

        Collection<GrantedAuthority> authorities = new ArrayList<>();

        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");

        authorities.add(authority);

        AjaxAuthenticationToken token = new AjaxAuthenticationToken(user.getUsername(), user.getPassword(), authorities);

        return this.getAuthenticationManager().authenticate(token);
    }

}
