package org.example.service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.example.keycloakmodels.KeycloakTokenResponse;
import org.example.keycloakmodels.SignUpResponse;
import org.example.models.UserModel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakService {

    private final WebClient webClient;

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

    public KeycloakService(WebClient webClient) {
        this.webClient = webClient;
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
        // Parse JWT
        JWT jwt = JWTParser.parse(token);

        // Extract claims as Map
        Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

        // Extract resource_access
        Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
        if (resourceAccess != null && resourceAccess.containsKey(resourceId)) {
            Map<String, Object> clientRoles = (Map<String, Object>) resourceAccess.get(resourceId);
            List<String> roles = (List<String>) clientRoles.get("roles");

            if (roles.contains("ADMIN") || roles.contains("CSR")) {
                // User is authorized, proceed
                return;
            } else if (roles.contains("SignedUp_NotAuthorized")) {
                // User is not yet approved
                throw new InsufficientAuthenticationException("Your account is pending admin approval");
            } else {
                // Any other role or no role
                throw new InsufficientAuthenticationException("You are not authorized to login");
            }
        }
    }

    public KeycloakTokenResponse getAdminAccessToken() {
        return login(adminUsername, adminPassword);
    }

    public SignUpResponse createUser(String token, UserModel userModel) {

        /*webClient.post()
                .uri(realmAdminApi + "/users")
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .bodyValue(user)
                .retrieve()
                .toBodilessEntity()
                .block();*/

        try {
            return webClient.post()
                    .uri(realmAdminApi + "/users")
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json")
                    .bodyValue(userModel)
                    .exchangeToMono(clientResponse -> {
                        int status = clientResponse.statusCode().value();

                        if (clientResponse.statusCode().is2xxSuccessful()) {
                            return Mono.just(new SignUpResponse(true, status, "User created successfully"));
                        } else {
                            return clientResponse.bodyToMono(String.class)
                                    .defaultIfEmpty("Unknown error")
                                    .map(body -> new SignUpResponse(false, status,
                                            "Failed to create user. Response: " + body));
                        }
                    })
                    .block();

        } catch (Exception e) {
            return new SignUpResponse(false, 500, "Exception while creating user: " + e.getMessage());
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

