package com.cognito.virtual.dto;

import jakarta.validation.constraints.NotBlank;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class ConfirmSignUpRequest {
    @NotBlank(message = "Username es requerido")
    private String username;

    @NotBlank(message = "Código de confirmación es requerido")
    private String confirmationCode;
}