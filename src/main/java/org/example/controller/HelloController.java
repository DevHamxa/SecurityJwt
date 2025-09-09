package org.example.controller;

import org.example.service.HelloService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    private final HelloService helloService;

    public HelloController(HelloService helloService) {
        this.helloService = helloService;
    }

    @GetMapping("/api/public")
    public String publicEndpoint() {
        return helloService.getPublicMessage();
    }

    @GetMapping("/api/secure")
    public String secureEndpoint() {
        return helloService.getSecureMessage();
    }
}
