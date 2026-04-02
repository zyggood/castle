package com.yc.auth.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponse {

    private String tokenType;
    private String accessToken;
    private String refreshToken;
    private long expiresIn;

}
