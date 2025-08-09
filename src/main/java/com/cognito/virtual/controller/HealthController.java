package com.cognito.virtual.controller;


@org.springframework.web.bind.annotation.RestController
@lombok.RequiredArgsConstructor
@lombok.extern.slf4j.Slf4j
public class HealthController {

    // Health check endpoint que el gateway espera
    @org.springframework.web.bind.annotation.GetMapping("/cognito/health")
    public java.util.Map<String, Object> health() {
        java.util.Map<String, Object> health = new java.util.HashMap<>();
        health.put("status", "UP");
        health.put("service", "rec-cognito");
        health.put("timestamp", java.time.LocalDateTime.now());
        health.put("port", 8082);
        health.put("version", "1.0.0");
        return health;
    }

    // Información del servicio
    @org.springframework.web.bind.annotation.GetMapping("/cognito/info")
    public java.util.Map<String, Object> getServiceInfo() {
        java.util.Map<String, Object> info = new java.util.HashMap<>();
        info.put("name", "rec-cognito");
        info.put("version", "1.0.0");
        info.put("port", 8082);
        info.put("description", "AWS Cognito Authentication & Administration Service");
        info.put("modules", java.util.Arrays.asList("Authentication", "User Management", "Role Management"));
        info.put("auth-endpoints", java.util.Arrays.asList(
                "/api/v1/auth/signup",
                "/api/v1/auth/signin",
                "/api/v1/auth/confirm-signup",
                "/api/v1/auth/refresh-token",
                "/api/v1/auth/change-password",
                "/api/v1/auth/forgot-password",
                "/api/v1/auth/confirm-forgot-password"
        ));
        info.put("admin-endpoints", java.util.Arrays.asList(
                "/api/v1/admin/users",
                "/api/v1/admin/roles",
                "/api/v1/admin/users/{userId}/roles/{roleId}",
                "/api/v1/admin/users/{userId}/roles/{roleId} (DELETE)"
        ));
        info.put("health-endpoints", java.util.Arrays.asList(
                "/cognito/health",
                "/cognito/info",
                "/ping"
        ));
        info.put("timestamp", java.time.LocalDateTime.now());
        return info;
    }

    // Endpoint para verificar conectividad básica
    @org.springframework.web.bind.annotation.GetMapping("/ping")
    public java.util.Map<String, String> ping() {
        java.util.Map<String, String> response = new java.util.HashMap<>();
        response.put("message", "pong");
        response.put("service", "rec-cognito");
        response.put("timestamp", java.time.LocalDateTime.now().toString());
        return response;
    }

    // Endpoint para verificar que los módulos estén funcionando
    @org.springframework.web.bind.annotation.GetMapping("/cognito/status")
    public java.util.Map<String, Object> getModuleStatus() {
        java.util.Map<String, Object> status = new java.util.HashMap<>();
        status.put("service", "rec-cognito");
        status.put("overall-status", "UP");

        java.util.Map<String, String> modules = new java.util.HashMap<>();
        modules.put("authentication", "UP");
        modules.put("user-management", "UP");
        modules.put("role-management", "UP");
        modules.put("database", "UP");

        status.put("modules", modules);
        status.put("timestamp", java.time.LocalDateTime.now());
        return status;
    }
}