package org.example.keycloakmodels;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class SignupErrorResponse {

    @JsonProperty("errorMessage")
    private String errorDescription;
}