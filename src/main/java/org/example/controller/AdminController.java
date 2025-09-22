package org.example.controller;

import lombok.RequiredArgsConstructor;
import org.example.models.AssignRole;
import org.example.models.SuccessResponse;
import org.example.service.AdminService;
import org.example.service.HelloService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin")
/*Do not include in jiffy*/
public class AdminController {

    private final HelloService helloService;

    private final AdminService adminService;

    @GetMapping("/check")
    public String publicEndpoint() {
        return helloService.getPublicMessage();
    }

    @GetMapping("/check2")
    public String secureEndpoint() {
        return helloService.getSecureMessage();
    }

    @PostMapping("/users/assign-role")
    public ResponseEntity<SuccessResponse> assignRole(@RequestBody AssignRole assignRole) {
        return ResponseEntity.ok(adminService.assignNewRole(assignRole.getUserName(), assignRole.getRole()));
    }
}
