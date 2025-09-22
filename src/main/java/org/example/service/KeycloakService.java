package org.example.service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.example.exception.UnAuthorizedException;
import org.example.keycloakmodels.KeycloakTokenResponse;
import org.example.keycloakmodels.SignUpResponse;
import org.example.models.UserModel;
import org.example.roles.RoleValidator;
import org.example.securitydemo.CustomJwtParser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakService {

    private final WebClient webClient;

    private final CustomJwtParser customJwtParser;

    private final RoleValidator roleValidator;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.realm-admin-api}")
    private String realmAdminApi;

    @Value("${keycloak.client}")
    private String client;

    @Value("${keycloak.admin-username}")
    private String adminUsername;

    @Value("${keycloak.admin-password}")
    private String adminPassword;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    public KeycloakService(WebClient webClient, CustomJwtParser jwtParser, RoleValidator roleValidator) {
        this.webClient = webClient;
        this.customJwtParser = jwtParser;
        this.roleValidator = roleValidator;
    }

    public KeycloakTokenResponse login(String username, String password) {
        return webClient.post()
            .uri(realm + "/protocol/openid-connect/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .bodyValue("grant_type=password&client_id=" + client + "&username="
                    + username + "&password=" + password)
            .retrieve()
            .bodyToMono(KeycloakTokenResponse.class)
            .block();
    }

    public void validateUserToken(String token) throws ParseException {
        JWT jwt = customJwtParser.parseJwt(token);
        Map<String, Object> claims = customJwtParser.extractClaims(jwt);
        List<String> roles = customJwtParser.extractRolesFromClaims(claims, resourceId);

        roleValidator.validateRoles(roles);
    }

    public KeycloakTokenResponse getAdminAccessToken() {
        return login(adminUsername, adminPassword);
    }

    public SignUpResponse createUser(String token, UserModel userModel) {
        return webClient.post()
            .uri(realmAdminApi + "/users")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue(userModel)
            .exchangeToMono(KeycloakService::validateResponse)
            .block();
    }

    private static Mono<SignUpResponse> validateResponse(ClientResponse clientResponse) {
        int status = clientResponse.statusCode().value();

        if (clientResponse.statusCode().is2xxSuccessful()) {
            return Mono.just(new SignUpResponse(true, status, "User created successfully"));
        } else {
            throw new RuntimeException("Failed to create user. please try again.");
        }
    }

    public String getUserIdByUsername(String token, String username) {
        List<UserModel> users = webClient.get()
            .uri(realmAdminApi + "/users?username=" + username)
            .header("Authorization", "Bearer " + token)
            .retrieve()
            .bodyToMono(new ParameterizedTypeReference<List<UserModel>>() {})
            .block();

        /*if (users != null && !users.isEmpty()) {
            return users.get(0).getId();
        }*/
        return null;
    }

}

