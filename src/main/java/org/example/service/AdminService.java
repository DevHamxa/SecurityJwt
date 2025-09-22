package org.example.service;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.AllArgsConstructor;
import org.example.keycloakmodels.KeycloakTokenResponse;
import org.example.keycloakmodels.LoginResponse;
import org.example.keycloakmodels.Role;
import org.example.models.SuccessResponse;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AdminService {

    private KeycloakService keycloakService;

    public SuccessResponse assignNewRole(String username, String roleName) {
        KeycloakTokenResponse keycloakTokenResponse = keycloakService.getAdminAccessToken();
        String userId = keycloakService.getUserIdByUsername(keycloakTokenResponse.getAccessToken(), username);
        Role role =  keycloakService.getRealmRole(keycloakTokenResponse.getAccessToken(), roleName);
        return keycloakService.assignRoleToUser(keycloakTokenResponse.getAccessToken(), username, role);
    }
}
