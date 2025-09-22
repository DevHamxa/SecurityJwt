package org.example.securitydemo;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Component
public class CustomJwtParser {

    public JWT parseJwt(String token) throws ParseException {
        return JWTParser.parse(token);
    }

    public Map<String, Object> extractClaims(JWT jwt) throws ParseException {
        return jwt.getJWTClaimsSet().getClaims();
    }

    public List<String> extractRolesFromClaims(Map<String, Object> claims, String realmAccess) {
        if (claims == null || !claims.containsKey(realmAccess)) { return Collections.emptyList(); }

        Map<String, Object> resourceAccess = (Map<String, Object>) claims.get(realmAccess);
        if (resourceAccess == null) { return Collections.emptyList(); }

        Object rolesObj = resourceAccess.get("roles");
        if (rolesObj instanceof List) { return (List<String>) rolesObj; }
        else { return Collections.emptyList(); }

        /*Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
        if (resourceAccess == null || !resourceAccess.containsKey(resourceId)) {
            return Collections.emptyList();
        }
        Map<String, Object> clientRoles = (Map<String, Object>) resourceAccess.get(resourceId);
        return (List<String>) clientRoles.getOrDefault("roles", Collections.emptyList());*/
    }
}
