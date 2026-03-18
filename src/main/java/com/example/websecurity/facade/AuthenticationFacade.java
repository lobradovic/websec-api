package com.example.websecurity.facade;

import com.example.websecurity.api.dto.AuthenticationRequest;
import com.example.websecurity.api.dto.AuthenticationResponse;
import com.example.websecurity.security.JwtService;
import com.example.websecurity.service.LoginAttemptService;
import com.example.websecurity.service.UserService;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFacade {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserService userService;
    private final LoginAttemptService loginAttemptService;

    @Transactional
    public AuthenticationResponse authenticate(@NotNull AuthenticationRequest request) {
        log.info("Authentication Facade: Authenticating user with email: {}", request.getEmail());
        loginAttemptService.checkNotBlocked(request.getEmail());

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        }
        catch (BadCredentialsException ex) {
        loginAttemptService.loginFailed(request.getEmail());

        int remaining = loginAttemptService.getRemainingAttempts(request.getEmail());

        throw new BadCredentialsException("Invalid credentials. Remaining attempts: " + remaining);
        }

        loginAttemptService.loginSucceeded(request.getEmail());

        var user = userService.getUserByEmail(request.getEmail());
        var accessToken = jwtService.generateAccessToken(user);
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .build();
    }
}