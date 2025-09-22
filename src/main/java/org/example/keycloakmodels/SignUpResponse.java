package org.example.keycloakmodels;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignUpResponse {
    private boolean success;
    private int statusCode;
    private String message;
}

