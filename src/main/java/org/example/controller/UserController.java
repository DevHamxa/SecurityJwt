package org.example.controller;

import lombok.RequiredArgsConstructor;
import org.example.keycloakmodels.LoginResponse;
import org.example.keycloakmodels.SignUpResponse;
import org.example.models.UserModel;
import org.example.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
            return ResponseEntity.ok(userService.login(username, password));
    }

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponse> signup(@RequestBody UserModel userModel) {
        return ResponseEntity.ok(userService.signUp(userModel));
    }

}
