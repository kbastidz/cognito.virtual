package com.cognito.virtual.dto;

import jakarta.validation.constraints.NotBlank;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class AuthRequest {
    @NotBlank(message = "Username es requerido")
    private String username;

    @NotBlank(message = "Password es requerida")
    private String password;
}