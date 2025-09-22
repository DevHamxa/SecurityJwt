package org.example.service;

import lombok.AllArgsConstructor;
import org.example.keycloakmodels.KeycloakTokenResponse;
import org.example.keycloakmodels.LoginResponse;
import org.example.keycloakmodels.SignUpResponse;
import org.example.models.UserModel;
import org.springframework.stereotype.Service;

import java.text.ParseException;

@Service
@AllArgsConstructor
public class UserService {

    private KeycloakService keycloakService;

    public LoginResponse login(String username, String password) throws ParseException {
        KeycloakTokenResponse keycloakTokenResponse = keycloakService.login(username, password);
        keycloakService.validateUserToken(keycloakTokenResponse.getAccessToken());
        return new LoginResponse(keycloakTokenResponse.getAccessToken());
    }

    public SignUpResponse signUp(UserModel userModel) {
        KeycloakTokenResponse keycloakTokenResponse = keycloakService.getAdminAccessToken();
        // Create disabled user
        return keycloakService.createUser(keycloakTokenResponse.getAccessToken(), userModel);
    }
}

