package com.example.auth_project.dtos.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record RefreshRequest(
        @NotBlank(message = "Refresh token is required")
        String refreshToken
) {
}
