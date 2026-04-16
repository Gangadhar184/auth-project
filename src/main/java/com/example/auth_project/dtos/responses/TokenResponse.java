package com.example.auth_project.dtos.responses;

import lombok.Builder;

import java.time.Instant;

@Builder
public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        Long expiresIn,
        Instant issuedAt
) {
}
