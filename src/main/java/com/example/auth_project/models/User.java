package com.example.auth_project.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email", unique = true),
        @Index(name = "idx_user_enabled", columnList = "enabled")
})
@Builder
@Getter
@Setter(AccessLevel.PACKAGE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE )
public class User {

    @Id
    @UuidGenerator
    @Column(updatable = false, nullable = false)
    private UUID id;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false, length = 100)
    private String password;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(nullable = false, name = "email_verified")
    @Builder.Default
    private boolean emailVerified = false;

    @Column(nullable = false, name = "account_non_locked")
    @Builder.Default
    private boolean accountNonLocked = true;

    @Column(name = "failed_attempts")
    @Builder.Default
    private int failedAttempts = 0;

    @Column(name = "lock_time")
    private Instant lockTime;

    @CreationTimestamp
    @Column(name = "createdAt", updatable = false, nullable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updatedAt", nullable = false)
    private Instant updatedAt;

    public void verifyEmail() {
        this.emailVerified = true;
    }

    public void incrementFailedAttempts() {
        this.failedAttempts++;
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
        this.lockTime = null;
    }

    public void lockAccount(Instant lockTime) {
        this.accountNonLocked = false;
        this.lockTime = lockTime;
    }

    public void unlockAccount() {
        this.accountNonLocked = true;
        this.failedAttempts = 0;
        this.lockTime = null;
    }

}
