package com.example.auth_project.services;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Async("taskExecutor")
    @Retryable(
            retryFor = {MailException.class, MessagingException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 1000, multiplier = 2)
    )
    public void sendVerificationEmail(String to, String token) {

        String subject = "Verification Email";

        String verificationUrl = "http://localhost:8080/api/auth/verify?token=" + token;

        String htmlContent = String.format("""
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2>Email Verification</h2>
                    <p>Please click the link below to verify your email address:</p>
                    <a href="%s"
                       style="padding: 10px 20px; background-color: #4CAF50;
                              color: white; text-decoration: none; border-radius: 5px;">
                       Verify Email
                    </a>
                    <p>This link will expire in 24 hours.</p>
                </body>
            </html>
        """, verificationUrl);

        sendHtmlEmail(to, subject, htmlContent);
    }

    public void sendPasswordResetEmail(String to, String token) {

        String subject = "Reset Password";

        String resetUrl = "http://localhost:8080/api/auth/reset?token=" + token;

        String htmlContent = String.format("""
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2>Password Reset</h2>
                    <p>Click below to reset your password:</p>
                    <a href="%s"
                       style="padding: 10px 20px; background-color: #f44336;
                              color: white; text-decoration: none; border-radius: 5px;">
                       Reset Password
                    </a>
                    <p>This link will expire in 30 minutes.</p>
                </body>
            </html>
        """, resetUrl);

        sendHtmlEmail(to, subject, htmlContent);
    }

    private void sendHtmlEmail(String to, String subject, String htmlContent) {

        try {
            MimeMessage message = mailSender.createMimeMessage();

            MimeMessageHelper helper =
                    new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);

            log.info("Email sent to {}", to);

        } catch (MessagingException e) {
            log.error("Message creation failed", e);
            throw new RuntimeException(e);
        } catch (MailException e) {
            log.error("Mail send failed", e);
            throw e;
        }
    }
}
