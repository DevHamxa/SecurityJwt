package org.example.roles;

public enum Roles {
    ADMIN("ADMIN"),
    CSR("CSR"),
    SIGNED_UP_NOT_AUTHORIZED("SignedUp_NotAuthorized");

    private final String value;

    Roles(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
