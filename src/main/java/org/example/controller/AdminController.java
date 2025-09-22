package org.example.controller;

import org.example.service.HelloService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final HelloService helloService;

    public AdminController(HelloService helloService) {
        this.helloService = helloService;
    }

    @GetMapping("/check")
    public String publicEndpoint() {
        return helloService.getPublicMessage();
    }

    @GetMapping("/check2")
    public String secureEndpoint() {
        return helloService.getSecureMessage();
    }
}
