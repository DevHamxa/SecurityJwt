package org.example.keycloakmodels;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UserModel {

    private String id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private boolean emailVerified;
    private UserProfileMetadata userProfileMetadata;
    private boolean enabled;
    private long createdTimestamp;
    private boolean totp;
    @JsonProperty("disableableCredentialTypes")
    private List<String> disableAbleCredentialTypes;
    private List<String> requiredActions;
    private int notBefore;
    private Access access;

}

