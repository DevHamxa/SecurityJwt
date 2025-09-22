package org.example.keycloakmodels;

import lombok.Data;

import java.util.Map;

@Data
public class UserAttribute {
    private String name;
    private String displayName;
    private boolean required;
    private boolean readOnly;
    private Map<String, Map<String, String>> validators;
    private boolean multivalued;

}
