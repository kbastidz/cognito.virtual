package com.cognito.virtual.dto;

import jakarta.validation.constraints.*;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class ChangePasswordRequest {
    @NotBlank(message = "Access token es requerido")
    private String accessToken;

    @NotBlank(message = "Password anterior es requerida")
    private String previousPassword;

    @NotBlank(message = "Nueva password es requerida")
    @Size(min = 8, message = "Password debe tener al menos 8 caracteres")
    private String proposedPassword;
}