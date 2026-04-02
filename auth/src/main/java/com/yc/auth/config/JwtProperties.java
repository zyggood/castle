package com.yc.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Setter
@Getter
@ConfigurationProperties(prefix = "auth.jwt")
public class JwtProperties {

    private String secret;
    private long accessTokenExpirationSeconds;
    private long refreshTokenExpirationSeconds;

}
