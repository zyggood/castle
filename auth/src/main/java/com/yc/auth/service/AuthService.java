package com.yc.auth.service;

import com.yc.auth.config.JwtProperties;
import com.yc.auth.model.AuthResponse;
import com.yc.auth.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    public AuthService(AuthenticationManager authenticationManager,
                       UserDetailsService userDetailsService,
                       JwtService jwtService,
                       JwtProperties jwtProperties) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
    }

    public AuthResponse login(String username, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (BadCredentialsException ex) {
            throw new BadCredentialsException("invalid username or password");
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return issueTokens(userDetails);
    }

    public AuthResponse refresh(String refreshToken) {
        String username = jwtService.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (!jwtService.isValidRefreshToken(refreshToken, userDetails)) {
            throw new BadCredentialsException("invalid refresh token");
        }
        return issueTokens(userDetails);
    }

    private AuthResponse issueTokens(UserDetails userDetails) {
        AuthResponse response = new AuthResponse();
        response.setTokenType("Bearer");
        response.setAccessToken(jwtService.generateAccessToken(userDetails));
        response.setRefreshToken(jwtService.generateRefreshToken(userDetails));
        response.setExpiresIn(jwtProperties.getAccessTokenExpirationSeconds());
        return response;
    }
}
