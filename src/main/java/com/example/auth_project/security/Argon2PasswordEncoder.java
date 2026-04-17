package com.example.auth_project.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;
import java.util.Base64;

public class Argon2PasswordEncoder implements PasswordEncoder {

    private final int saltLength;
    private final int hashLength;
    private final int parallelism;
    private final int memory;
    private final int iterations;
    private final SecureRandom secureRandom;

    public Argon2PasswordEncoder(int saltLength, int hashLength, int parallelism, int memory, int iterations) {
        this.saltLength = saltLength;
        this.hashLength = hashLength;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
        this.secureRandom = new SecureRandom();
    }

    @Override
    public String encode(CharSequence rawPassword) {
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);

        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(parallelism)
                .withMemoryAsKB(memory)
                .withIterations(iterations)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] result = new byte[hashLength];
        generator.generateBytes(rawPassword.toString().toCharArray(), result);
        String saltB64 = Base64.getEncoder().encodeToString(salt);
        String hashB64 = Base64.getEncoder().encodeToString(result);
        return String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
                memory, iterations, parallelism, saltB64, hashB64);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (encodedPassword == null || !encodedPassword.startsWith("$argon2id$")) {
            return false;
        }

        try {
            String[] parts = encodedPassword.split("\\$");
            if (parts.length != 6) return false;

            //parse parameters
            String[] params = parts[3].split(",");
            int mem = Integer.parseInt(params[0].substring(2));
            int iter = Integer.parseInt(params[1].substring(2));
            int para = Integer.parseInt(params[2].substring(2));

            byte[] salt = Base64.getDecoder().decode(parts[4]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[5]);

            Argon2Parameters argonParams = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withSalt(salt)
                    .withParallelism(para)
                    .withMemoryAsKB(mem)
                    .withIterations(iter)
                    .build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(argonParams);

            byte[] actualHash = new byte[hashLength];
            generator.generateBytes(rawPassword.toString().toCharArray(), actualHash);

            // constant-time comparison
            return constantTimeEquals(expectedHash, actualHash);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {return false;}
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
