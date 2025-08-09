package com.cognito.virtual.util;

import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.cognito.virtual.entity.*;

@org.springframework.stereotype.Component
@lombok.extern.slf4j.Slf4j
public class JwtUtil {

    @org.springframework.beans.factory.annotation.Value("${cognito.jwt.secret}")
    private String secret;

    @org.springframework.beans.factory.annotation.Value("${cognito.jwt.expiration}")
    private Long jwtExpiration;

    public String generateAccessToken(UserEntity user) {
        java.util.Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("sub", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("email_verified", user.getEmailVerified());
        claims.put("phone_number", user.getPhoneNumber());
        claims.put("phone_number_verified", user.getPhoneVerified());
        claims.put("given_name", user.getFirstName());
        claims.put("family_name", user.getLastName());

        java.util.Set<String> roles = user.getRoles().stream()
                .map(RoleEntity::getName)
                .collect(java.util.stream.Collectors.toSet());
        claims.put("cognito:roles", roles);

        java.util.Set<String> permissions = user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(PermissionEntity::getName)
                .collect(java.util.stream.Collectors.toSet());
        claims.put("cognito:permissions", permissions);

        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuedAt(new java.util.Date())
                .withExpiresAt(new java.util.Date(System.currentTimeMillis() + jwtExpiration))
                .withClaim("email", user.getEmail())
                .withClaim("email_verified", user.getEmailVerified())
                .withClaim("phone_number", user.getPhoneNumber())
                .withClaim("phone_number_verified", user.getPhoneVerified())
                .withClaim("given_name", user.getFirstName())
                .withClaim("family_name", user.getLastName())
                .withClaim("cognito:roles", new java.util.ArrayList<>(roles))
                .withClaim("cognito:permissions", new java.util.ArrayList<>(permissions))
                .sign(Algorithm.HMAC512(secret));
    }

    public String generateRefreshToken() {
        return java.util.UUID.randomUUID().toString();
    }

    public String getUsernameFromToken(String token) {
        return JWT.require(Algorithm.HMAC512(secret))
                .build()
                .verify(token)
                .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            JWT.require(Algorithm.HMAC512(secret))
                    .build()
                    .verify(token);
            return true;
        } catch (Exception e) {
            log.error("Error validando token JWT: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(secret))
                    .build()
                    .verify(token);
            return decodedJWT.getExpiresAt().before(new java.util.Date());
        } catch (Exception e) {
            return true;
        }
    }

    public java.util.List<String> getRolesFromToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(secret))
                    .build()
                    .verify(token);
            return decodedJWT.getClaim("cognito:roles").asList(String.class);
        } catch (Exception e) {
            return new java.util.ArrayList<>();
        }
    }

    public java.util.List<String> getPermissionsFromToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(secret))
                    .build()
                    .verify(token);
            return decodedJWT.getClaim("cognito:permissions").asList(String.class);
        } catch (Exception e) {
            return new java.util.ArrayList<>();
        }
    }
}