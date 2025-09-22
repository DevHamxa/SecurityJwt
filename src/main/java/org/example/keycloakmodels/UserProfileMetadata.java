package org.example.keycloakmodels;

import lombok.Data;

import java.util.List;

@Data
public class UserProfileMetadata {
    private List<UserAttribute> attributes;
    private List<UserGroup> groups;
}
