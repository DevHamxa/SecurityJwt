package org.example.roles;

import org.example.exception.UnAuthorizedException;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RoleValidator {

    public void validateRoles(List<String> roles) {
        if (roles.isEmpty()) {
            throwUnAuthorizedException("You are not authorized to login");
        }
        if (roles.contains(Roles.ADMIN.getValue()) || roles.contains(Roles.CSR.getValue())) {
            return;
        }
        if (roles.contains(Roles.SIGNED_UP_NOT_AUTHORIZED.getValue())) {
            throwUnAuthorizedException("Your account is pending admin approval");
        }
        throwUnAuthorizedException("You are not authorized to login");
    }

    private void throwUnAuthorizedException(String message) {
        throw new UnAuthorizedException(message);
    }
}
