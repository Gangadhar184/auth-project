package com.example.auth_project.dtos.requests;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record PasswordResetRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email
) {
}
