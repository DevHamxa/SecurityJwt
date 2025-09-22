package org.example.exception;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.AuthenticationException;

public class UnAuthorizedException extends AuthenticationException {

    public UnAuthorizedException(String message) {
        super(message);
    }
}

