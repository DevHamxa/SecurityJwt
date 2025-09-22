package org.example.securitydemo;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class StrictCsrfHeaderFilter extends OncePerRequestFilter {
    private static final List<String> CSRF_IGNORED = List.of(
            "/user/login",
            "/user/signup",
            "/autocsr/csrf-token"
    );
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();

        if (CSRF_IGNORED.stream().anyMatch(path::startsWith)) {
            filterChain.doFilter(request, response);
            return;
        }

        if ("POST".equalsIgnoreCase(request.getMethod()) ||
                "PUT".equalsIgnoreCase(request.getMethod()) ||
                "DELETE".equalsIgnoreCase(request.getMethod())) {

            String header = request.getHeader("X-XSRF-TOKEN");
            if (header == null || header.isBlank()) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"Missing CSRF header\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}