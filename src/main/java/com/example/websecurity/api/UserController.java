package com.example.websecurity.api;

import com.example.websecurity.api.dto.AuthenticationRequest;
import com.example.websecurity.api.dto.AuthenticationResponse;
import com.example.websecurity.exception.AccountLockedException;
import com.example.websecurity.facade.AuthenticationFacade;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final AuthenticationFacade authenticationFacade;

    @Operation(summary = "Authenticate User", description = "Authenticate user")
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody AuthenticationRequest request
    ) {
        log.info("User Controller: Received login request for: {}", request.getEmail());
        try {
            AuthenticationResponse response = authenticationFacade.authenticate(request);
            return ResponseEntity.ok(response);
        } catch (AccountLockedException ex) {
            log.warn("User Controller: Login blocked for {} — {}", request.getEmail(), ex.getMessage());
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of(
                            "error", "Account temporarily locked",
                            "message", ex.getMessage(),
                            "remainingSeconds", ex.getRemainingSeconds()
                    ));
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid email or password"));
        }
    }

}