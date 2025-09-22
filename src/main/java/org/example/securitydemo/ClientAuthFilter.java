package org.example.securitydemo;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.exception.UnAuthorizedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ClientAuthFilter extends OncePerRequestFilter {

    private final AuthenticationManager authManager;
    private final AuthenticationEntryPoint entryPoint;

    public ClientAuthFilter(AuthenticationManager authManager, AuthenticationEntryPoint entryPoint) {
        this.authManager = authManager;
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String clientId = request.getHeader("X-Client-Id");
        String clientSecret = request.getHeader("X-Client-Secret");

        if (clientId != null && clientSecret != null) {
            Authentication authRequest = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
            try {
                Authentication authResult = authManager.authenticate(authRequest);
                SecurityContextHolder.getContext().setAuthentication(authResult);
            } catch (AuthenticationException e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                //response.getWriter().write("Unauthorized: " + e.getMessage());

                SecurityContextHolder.clearContext();
                entryPoint.commence(
                        request,
                        response,
                        new UnAuthorizedException("Please provide valid X-Client-ID and X-Client-Secret headers")
                        );
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
