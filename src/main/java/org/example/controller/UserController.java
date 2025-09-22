package org.example.controller;

import lombok.RequiredArgsConstructor;
import org.example.models.SuccessResponse;
import org.example.models.UserModel;
import org.example.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<SuccessResponse> signup(@RequestBody UserModel userModel) {
        return ResponseEntity.ok(userService.signUp(userModel));
    }

}
