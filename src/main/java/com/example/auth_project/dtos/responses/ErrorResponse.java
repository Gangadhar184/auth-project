package com.example.auth_project.dtos.responses;

import lombok.Builder;

import java.time.Instant;

@Builder
public record ErrorResponse(
        Instant timestamp,
        int status,
        String message,
        String path
) {
}
