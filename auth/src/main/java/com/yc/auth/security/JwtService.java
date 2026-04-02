package com.yc.auth.security;

import com.yc.auth.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
public class JwtService {

    private static final String TOKEN_TYPE = "type";
    private static final String ROLES = "roles";
    private static final String ACCESS = "access";
    private static final String REFRESH = "refresh";

    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String generateAccessToken(UserDetails userDetails) {
        return buildToken(userDetails, ACCESS, jwtProperties.getAccessTokenExpirationSeconds());
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(userDetails, REFRESH, jwtProperties.getRefreshTokenExpirationSeconds());
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isValidAccessToken(String token, UserDetails userDetails) {
        return isValid(token, userDetails, ACCESS);
    }

    public boolean isValidRefreshToken(String token, UserDetails userDetails) {
        return isValid(token, userDetails, REFRESH);
    }

    private boolean isValid(String token, UserDetails userDetails, String expectedType) {
        Claims claims = parseClaims(token);
        String tokenType = claims.get(TOKEN_TYPE, String.class);
        String username = claims.getSubject();
        Date expiration = claims.getExpiration();
        return expectedType.equals(tokenType)
                && userDetails.getUsername().equals(username)
                && expiration.after(new Date());
    }

    private String buildToken(UserDetails userDetails, String type, long expirationSeconds) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(expirationSeconds);
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim(TOKEN_TYPE, type)
                .claim(ROLES, toRoleList(userDetails.getAuthorities()))
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(signingKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private SecretKey signingKey() {
        byte[] bytes;
        try {
            bytes = Decoders.BASE64.decode(jwtProperties.getSecret());
        } catch (IllegalArgumentException ex) {
            bytes = jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8);
        }
        return Keys.hmacShaKeyFor(bytes);
    }

    private List<String> toRoleList(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }
}
