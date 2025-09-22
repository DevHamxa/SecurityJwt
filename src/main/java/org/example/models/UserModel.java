package org.example.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.example.keycloakmodels.Access;
import org.example.keycloakmodels.UserProfileMetadata;

import java.util.List;

@Data
@AllArgsConstructor
public class UserModel {

    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private boolean enabled;
    private List<Credentials> credentials;
}

