package com.cognito.virtual.service;


@org.springframework.stereotype.Service
@lombok.extern.slf4j.Slf4j
public class EmailService {

    public void sendConfirmationEmail(String email, String confirmationCode) {
        log.info("Enviando email de confirmación a: {} con código: {}", email, confirmationCode);
        // Aquí implementarías la integración con tu proveedor de email (SES, SendGrid, etc.)
    }

    public void sendPasswordResetEmail(String email, String resetCode) {
        log.info("Enviando email de reset de password a: {} con código: {}", email, resetCode);
        // Aquí implementarías la integración con tu proveedor de email
    }

    public void sendPasswordChangeNotification(String email) {
        log.info("Enviando notificación de cambio de password a: {}", email);
        // Aquí implementarías la notificación de cambio de password
    }
}