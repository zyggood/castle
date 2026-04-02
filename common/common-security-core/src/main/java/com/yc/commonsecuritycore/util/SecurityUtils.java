package com.yc.commonsecuritycore.util;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;

/**
 * 用户上下文工具类，用于在业务代码中获取当前用户信息
 */
public class SecurityUtils {

    /**
     * 获取当前认证信息
     */
    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * 获取当前用户ID（从 JWT 的 sub 字段）
     */
    public static String getCurrentUserId() {
        Jwt jwt = getJwt();
        if (jwt != null) {
            return jwt.getSubject();
        }
        return null;
    }

    /**
     * 获取当前用户名
     */
    public static String getCurrentUsername() {
        Authentication auth = getAuthentication();
        if (auth != null) {
            return auth.getName();
        }
        return null;
    }

    /**
     * 获取当前用户的所有角色
     */
    public static List<String> getCurrentUserRoles() {
        Jwt jwt = getJwt();
        if (jwt != null) {
            // 根据你在 JWT 中的角色字段名调整
            return jwt.getClaimAsStringList("authorities");
        }
        return List.of();
    }

    /**
     * 获取完整的 JWT 对象
     */
    public static Jwt getJwt() {
        Authentication auth = getAuthentication();
        if (auth instanceof JwtAuthenticationToken) {
            return ((JwtAuthenticationToken) auth).getToken();
        }
        return null;
    }

    /**
     * 获取 JWT 中的自定义字段
     */
    public static Object getClaim(String claimName) {
        Jwt jwt = getJwt();
        if (jwt != null) {
            return jwt.getClaims().get(claimName);
        }
        return null;
    }

    /**
     * 检查当前用户是否拥有指定角色
     */
    public static boolean hasRole(String role) {
        List<String> roles = getCurrentUserRoles();
        return roles != null && roles.contains(role);
    }
}
