package org.example.keycloakmodels;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KcUser {

    private String id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private Boolean emailVerified;
    private Boolean enabled;
    private Long createdTimestamp;
    private Boolean totp;
    private List<String> disableableCredentialTypes;
    private List<String> requiredActions;
    private Integer notBefore;
    private Map<String, Object> access;
}

