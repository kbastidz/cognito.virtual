package com.cognito.virtual.entity;

import jakarta.persistence.*;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
@lombok.Builder
@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String token;

    @Column(name = "expires_at", nullable = false)
    private java.time.Instant expiresAt;

    @Column(name = "created_at")
    @lombok.Builder.Default
    private java.time.Instant createdAt = java.time.Instant.now();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "is_revoked")
    @lombok.Builder.Default
    private Boolean revoked = false;

    public boolean isExpired() {
        return java.time.Instant.now().isAfter(this.expiresAt);
    }
} 