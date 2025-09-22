package org.example.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.keycloakmodels.KeycloakTokenResponse;
import org.example.keycloakmodels.SignUpResponse;
import org.example.models.UserModel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakService {

    private final WebClient webClient;

    @Value("${keycloak.server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client}")
    private String client;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    @Value("${keycloak.realm-admin-api}")
    private String realmAdminApi;

    @Value("${keycloak.admin-client-id}")
    private String adminClientId;

    @Value("${keycloak.admin-username}")
    private String adminUsername;

    @Value("${keycloak.admin-password}")
    private String adminPassword;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    public KeycloakTokenResponse login(String username, String password) {
        return webClient.post()
                .uri(keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue("grant_type=password" +
                        "&client_id=" + client +
                        "&client_secret=" + clientSecret +
                        "&username=" + username +
                        "&password=" + password)
                .retrieve()
                .bodyToMono(KeycloakTokenResponse.class)
                .block();
    }

    public void validateUserToken(String token) throws ParseException {
        JWT jwt = JWTParser.parse(token);
        Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

        Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
        if (resourceAccess != null && resourceAccess.containsKey(resourceId)) {
            Map<String, Object> clientRoles = (Map<String, Object>) resourceAccess.get(resourceId);
            List<String> roles = (List<String>) clientRoles.get("roles");

            if (roles.contains("ADMIN") || roles.contains("CSR")) {
                return; // ✅ authorized
            } else if (roles.contains("SignedUp_NotAuthorized")) {
                throw new InsufficientAuthenticationException("Your account is pending admin approval");
            } else {
                throw new InsufficientAuthenticationException("You are not authorized to login");
            }
        }
    }

    public void assignRoleToUser(String username, String roleName) {
        try {
            String accessToken = getAdminAccessToken().getAccessToken();

            List<org.example.keycloakmodels.UserModel> users = webClient.get()
                    .uri(realmAdminApi + "/users?username=" + username)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<List<org.example.keycloakmodels.UserModel>>() {})
                    .block();

            if (users == null || users.isEmpty()) {
                throw new RuntimeException("User not found in Keycloak: " + username);
            }
            String userId = users.get(0).getId();

            JsonNode role = webClient.get()
                    .uri(keycloakServerUrl + "/admin/realms/" + realm + "/roles/" + roleName)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();

            if (role == null) {
                throw new RuntimeException("Role not found in Keycloak: " + roleName);
            }

            webClient.post()
                    .uri(keycloakServerUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .bodyValue(Collections.singletonList(role))
                    .retrieve()
                    .toBodilessEntity()
                    .block();

            log.info("Keycloak: Role {} assigned to user {} (id={})", roleName, username, userId);

        } catch (Exception e) {
            log.error("Failed to assign role {} to {}: {}", roleName, username, e.getMessage());
            throw new RuntimeException("Role assignment failed", e);
        }
    }

    public KeycloakTokenResponse getAdminAccessToken() {
        return webClient.post()
                .uri(keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue("grant_type=password" +
                        "&client_id=" + adminClientId +
                        "&client_secret=" + clientSecret +
                        "&username=" + adminUsername +
                        "&password=" + adminPassword)
                .retrieve()
                .bodyToMono(KeycloakTokenResponse.class)
                .block();
    }

    // --- Create user ---
    public SignUpResponse createUser(String token, UserModel userModel) {
        try {
            return webClient.post()
                    .uri(realmAdminApi + "/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header(HttpHeaders.CONTENT_TYPE, "application/json")
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
        List<org.example.keycloakmodels.UserModel> users = webClient.get()
                .uri(realmAdminApi + "/users?username=" + username)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<org.example.keycloakmodels.UserModel>>() {})
                .block();

        return (users != null && !users.isEmpty()) ? users.get(0).getId() : null;
    }
}
