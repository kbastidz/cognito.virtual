package com.cognito.virtual.dto;

import jakarta.validation.constraints.NotBlank;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class RefreshTokenRequest {
    @NotBlank(message = "Refresh token es requerido")
    private String refreshToken;
}