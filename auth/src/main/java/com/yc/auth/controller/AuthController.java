package com.yc.auth.controller;

import com.yc.auth.model.AuthResponse;
import com.yc.auth.model.LoginRequest;
import com.yc.auth.model.MeResponse;
import com.yc.auth.model.RefreshRequest;
import com.yc.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody @Valid LoginRequest request) {
        return authService.login(request.getUsername(), request.getPassword());
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody @Valid RefreshRequest request) {
        return authService.refresh(request.getRefreshToken());
    }

    @GetMapping("/me")
    public MeResponse me(Authentication authentication) {
        MeResponse meResponse = new MeResponse();
        meResponse.setUsername(authentication.getName());
        meResponse.setRoles(authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        return meResponse;
    }
}
