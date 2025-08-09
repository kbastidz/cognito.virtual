package com.cognito.virtual.dto;

import jakarta.validation.constraints.*;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class ConfirmForgotPasswordRequest {
    @NotBlank(message = "Username es requerido")
    private String username;

    @NotBlank(message = "Código de confirmación es requerido")
    private String confirmationCode;

    @NotBlank(message = "Nueva password es requerida")
    @Size(min = 8, message = "Password debe tener al menos 8 caracteres")
    private String password;
}