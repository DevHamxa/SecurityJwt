package org.example.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.models.AssignRole;
import org.example.service.HelloService;
import org.example.service.KeycloakService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@Slf4j
public class AdminController {

    private final HelloService helloService;
    private final KeycloakService keycloakAdminService;

    @GetMapping("/check")
    public String publicEndpoint() {
        return helloService.getPublicMessage();
    }

    @GetMapping("/check2")
    public String secureEndpoint() {
        return helloService.getSecureMessage();
    }

    @PostMapping("/users/assign-role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> assignRole(
            @RequestBody AssignRole request,
            Authentication authentication) {

        String actor = authentication.getName();

        keycloakAdminService.assignRoleToUser(request.getUserName(), request.getRole());

        log.info("AUDIT: Admin {} assigned role {} to user {}", actor, request.getRole(), request.getUserName());

        return ResponseEntity.ok("Role assigned successfully");
    }
}
