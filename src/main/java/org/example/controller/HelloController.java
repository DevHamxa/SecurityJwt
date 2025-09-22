package org.example.controller;

import org.example.service.HelloService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/autocsr")
/*Do not include in jiffy*/
public class HelloController {

    private final HelloService helloService;

    public HelloController(HelloService helloService) {
        this.helloService = helloService;
    }

    @GetMapping("/health")
    public String publicEndpoint() {
        return helloService.getPublicMessage();
    }

    @GetMapping("/csrf-token")
    public CsrfToken csrfToken(CsrfToken token) {
        return token;
    }

    @GetMapping("/secure")
    public String secureEndpoint() {
        return helloService.getSecureMessage();
    }
}
