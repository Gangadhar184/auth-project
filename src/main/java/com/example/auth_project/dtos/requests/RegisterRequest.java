package com.example.auth_project.dtos.requests;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record RegisterRequest (
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        @Size(max = 100, message = "Email too long")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 12, max = 128, message = "Password must be between 12 and 128 characters")
        @Pattern(
                regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$",
                message = "Password must contain digit, lowercase, uppercase, and special character"
        )
        String password
){
}
