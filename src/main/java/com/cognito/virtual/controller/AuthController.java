package com.cognito.virtual.controller;

import com.cognito.virtual.dto.*;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/v1/auth")
@lombok.RequiredArgsConstructor
@lombok.extern.slf4j.Slf4j
public class AuthController {

    private final com.cognito.virtual.service.CognitoService cognitoService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<AuthResponse>> signUp(
            @Valid @RequestBody SignUpRequest request) {

        ApiResponse<AuthResponse> response = cognitoService.signUp(request);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/confirm-signup")
    public ResponseEntity<ApiResponse<String>> confirmSignUp(
            @Valid @RequestBody ConfirmSignUpRequest request) {

        ApiResponse<String> response = cognitoService.confirmSignUp(request);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<ApiResponse<AuthResponse>> signIn(
            @Valid @RequestBody AuthRequest request) {

        ApiResponse<AuthResponse> response = cognitoService.signIn(request);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {

        ApiResponse<AuthResponse> response = cognitoService.refreshToken(request);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request) {

        ApiResponse<String> response = cognitoService.changePassword(request);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {

        ApiResponse<String> response = cognitoService.forgotPassword(request);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/confirm-forgot-password")
    public ResponseEntity<ApiResponse<String>> confirmForgotPassword(
            @Valid @RequestBody ConfirmForgotPasswordRequest request) {

        ApiResponse<String> response = cognitoService.confirmForgotPassword(request);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }
}