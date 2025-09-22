package org.example.service;

import org.springframework.stereotype.Service;

@Service
public class HelloService {

    public String getPublicMessage() {
        return "Hello from public API!";
    }

    public String getSecureMessage() {
        return "Hello from secured API!";
    }
}

