package org.example.service;

import lombok.AllArgsConstructor;
import org.example.keycloakmodels.KeycloakTokenResponse;
import org.example.keycloakmodels.LoginResponse;
import org.example.models.SuccessResponse;
import org.example.models.UserModel;
import org.springframework.stereotype.Service;

import java.text.ParseException;

@Service
@AllArgsConstructor
public class UserService {

    private KeycloakService keycloakService;

    public LoginResponse login(String username, String password) {
        KeycloakTokenResponse keycloakTokenResponse = keycloakService.login(username, password);
        try {
            keycloakService.validateUserToken(keycloakTokenResponse.getAccessToken());
        } catch (ParseException e) {
            throw new RuntimeException("Unable to login the User, please try again later");
        }
        return new LoginResponse(keycloakTokenResponse.getAccessToken());
    }

    public SuccessResponse signUp(UserModel userModel) {
        KeycloakTokenResponse keycloakTokenResponse = keycloakService.getAdminAccessToken();
        return keycloakService.createUser(keycloakTokenResponse.getAccessToken(), userModel);
    }
}

