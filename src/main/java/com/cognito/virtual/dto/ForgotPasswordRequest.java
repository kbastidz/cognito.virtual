package com.cognito.virtual.dto;

import jakarta.validation.constraints.NotBlank;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class ForgotPasswordRequest {
    @NotBlank(message = "Username es requerido")
    private String username;
}