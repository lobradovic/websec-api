package com.example.websecurity.exception;

public class AccountLockedException extends RuntimeException {

    private final long remainingSeconds;

    public AccountLockedException(long remainingSeconds) {
        super("Locked. Try again in " + remainingSeconds + " seconds.");
        this.remainingSeconds = remainingSeconds;
    }
    

    public long getRemainingSeconds() {
        return remainingSeconds;
    }
}