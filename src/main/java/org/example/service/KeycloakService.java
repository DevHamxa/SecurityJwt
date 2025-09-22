package org.example.service;

import com.nimbusds.jwt.JWT;
import org.example.exception.CustomException;
import org.example.keycloakmodels.KeycloakErrorResponse;
import org.example.keycloakmodels.KeycloakTokenResponse;
import org.example.keycloakmodels.Role;
import org.example.keycloakmodels.SignupErrorResponse;
import org.example.models.SuccessResponse;
import org.example.models.UserModel;
import org.example.roles.RoleValidator;
import org.example.securitydemo.CustomJwtParser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Collections;
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

    @Value("${jwt.auth.converter.realm-access}")
    private String realmAccess;

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
            .onStatus(
                status -> status.is4xxClientError() || status.is5xxServerError(),
                clientResponse -> clientResponse.bodyToMono(KeycloakErrorResponse.class)
                    .flatMap(error -> Mono.error(new CustomException(error.getErrorDescription())))
            )
            .bodyToMono(KeycloakTokenResponse.class)
            .block();
    }

    public void validateUserToken(String token) throws ParseException {
        JWT jwt = customJwtParser.parseJwt(token);
        Map<String, Object> claims = customJwtParser.extractClaims(jwt);
        List<String> roles = customJwtParser.extractRolesFromClaims(claims, realmAccess);

        roleValidator.validateRoles(roles);
    }

    public KeycloakTokenResponse getAdminAccessToken() {
        return login(adminUsername, adminPassword);
    }

    public SuccessResponse createUser(String token, UserModel userModel) {
        return webClient.post()
            .uri(realmAdminApi + "/users")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue(userModel)
            .exchangeToMono(KeycloakService::validateCreateUserResponse)
            .block();
    }

    private static Mono<SuccessResponse> validateCreateUserResponse(ClientResponse clientResponse) {
        if (clientResponse.statusCode().is2xxSuccessful()) {
            return Mono.just(new SuccessResponse(true, HttpStatus.OK.value(), "User created successfully"));
        } else {
            return clientResponse.bodyToMono(SignupErrorResponse.class)
                .flatMap(errorBody -> Mono.error(
                        new CustomException(errorBody.getErrorDescription())
                ));
        }
    }

    public String getUserIdByUsername(String token, String username) {
        List<org.example.keycloakmodels.UserModel> users = webClient.get()
            .uri(realmAdminApi + "/users?username=" + username)
            .header("Authorization", "Bearer " + token)
            .retrieve()
            .bodyToMono(new ParameterizedTypeReference<List<org.example.keycloakmodels.UserModel>>() {})
            .block();

        if (users != null && !users.isEmpty()) {
            return users.get(0).getId();
        }
        throw new CustomException("No such user exists. User not found");
    }

    public Role getRealmRole(String token, String roleName) {
        Role role = webClient.get()
            .uri(realmAdminApi + "/roles/" + roleName)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .retrieve()
            .bodyToMono(Role.class)
            .block();

        if (role == null) {
            throw new CustomException("Invalid Role Selected. Role not found");
        }

        return role;
    }

    public SuccessResponse assignRoleToUser(String token, String userId, Role role) {
        return webClient.post()
            .uri(realmAdminApi + "/users/" + userId + "/role-mappings/realm")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .bodyValue(Collections.singletonList(role))
            .exchangeToMono(KeycloakService::validateRoleAssigned)
            .block();
    }

    private static Mono<SuccessResponse> validateRoleAssigned(ClientResponse clientResponse) {
        if (clientResponse.statusCode().is2xxSuccessful()) {
            return Mono.just(new SuccessResponse(true, HttpStatus.OK.value(), "Role CSR Assigned successfully."));
        } else {
            return clientResponse.bodyToMono(KeycloakErrorResponse.class)
                .flatMap(errorBody -> Mono.error(
                        new CustomException(errorBody.getErrorDescription())
                ));
        }
    }

}

