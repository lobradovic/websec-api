package com.example.websecurity.service;

import com.example.websecurity.exception.AccountLockedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@Service
@Slf4j
public class LoginAttemptService {

    @Value("${websec.login.max-attempts:3}")
    private int maxAttempts;

    @Value("${websec.login.lockout-duration-minutes:1}")
    private long lockoutDurationMinutes;

    private final Map<String, LoginAttemptData> attemptsCache = new ConcurrentHashMap<>();


    public void loginSucceeded(String email) {
        attemptsCache.remove(email.toLowerCase());
        log.info("Cleared failed attempts for {}", email);
    }

    public void loginFailed(String email) {
        String key = email.toLowerCase();
        LoginAttemptData existing = attemptsCache.getOrDefault(key, new LoginAttemptData(0, null));

        if (existing.lockedUntil != null && LocalDateTime.now().isAfter(existing.lockedUntil)) {
            existing = new LoginAttemptData(0, null);
        }

        int newCount = existing.failedAttempts + 1;
        LocalDateTime lockUntil = existing.lockedUntil;

        if (newCount >= maxAttempts) {
            lockUntil = LocalDateTime.now().plusMinutes(lockoutDurationMinutes);
            log.warn("Account {} locked until {} after {} failed attempts",
                    email, lockUntil, newCount);
        } else {
            log.info("Failed attempt {} of {} for {}", newCount, maxAttempts, email);
        }

        attemptsCache.put(key, new LoginAttemptData(newCount, lockUntil));
    }

    /**
     * Checks if the given email is currently locked out.
     * If the lockout period has expired, the record is automatically cleared.
     *
     * @throws AccountLockedException if the account is still locked
     */
    public void checkNotBlocked(String email) {
        String key = email.toLowerCase();
        LoginAttemptData data = attemptsCache.get(key);

        if (data == null || data.lockedUntil == null) {
            return;
        }

        long remaining = ChronoUnit.SECONDS.between(LocalDateTime.now(), data.lockedUntil);

        if (remaining <= 0) {
            attemptsCache.remove(key);
            log.info("Timeout expired for {}", email);
            return;
        }

        log.info("Login blocked for {} — {} seconds remaining", email, remaining);
        throw new AccountLockedException(remaining);
    }
    public int getRemainingAttempts(String email) {
        String key = email.toLowerCase();
        LoginAttemptData data = attemptsCache.get(key);

        if (data == null) return maxAttempts;

        return Math.max(0, maxAttempts - data.failedAttempts);
    }

    private record LoginAttemptData(int failedAttempts, LocalDateTime lockedUntil) {
    }
}