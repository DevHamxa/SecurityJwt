package org.example.securitydemo;

import com.google.gson.JsonObject;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(ClientProperties.class)
public class SecurityConfig {

    private final ClientProperties clientProperties;

    public SecurityConfig(ClientProperties clientProperties) {
        this.clientProperties = clientProperties;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter, AuthenticationManager authManager) throws Exception {
        CookieCsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository)
                        .ignoringRequestMatchers("/user/login", "/user/signup", "/autocsr/csrf-token")
                )

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/autocsr/health", "/autocsr/csrf-token").permitAll()
                        .requestMatchers("/user/login", "/user/signup").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

            // JWT validation with role mapping
            .oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
            )

            // custom filter before UsernamePasswordAuthenticationFilter
            .addFilterBefore(new ClientAuthFilter(authManager, customAuthEntryPoint()),
                    UsernamePasswordAuthenticationFilter.class)

            // exception handling
            .exceptionHandling(ex -> ex.authenticationEntryPoint(customAuthEntryPoint()));
        http.addFilterAfter(new CsrfFilter(csrfTokenRepository), CsrfFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String clientId = authentication.getName();
                String clientSecret = authentication.getCredentials().toString();

                // lookup in yaml-configured clients
                boolean valid = clientProperties.getClients().stream()
                        .anyMatch(c -> c.getId().equals(clientId) && c.getSecret().equals(clientSecret) && c.getStatus().equalsIgnoreCase("Active"));

                if (valid) {
                    return new UsernamePasswordAuthenticationToken(
                            clientId,
                            clientSecret,
                            List.of(new SimpleGrantedAuthority("ROLE_CLIENT"))
                    );
                }

                throw new BadCredentialsException("Invalid Client ID or Secret");
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
            }
        };
    }

    @Bean
    public AuthenticationManager authManager(AuthenticationProvider provider) {
        return new ProviderManager(provider);
    }

    @Bean
    public AuthenticationEntryPoint customAuthEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");

            String message = authException.getMessage();

            JsonObject errorResponse = new JsonObject();
            errorResponse.addProperty("error", "Invalid client credentials");
            errorResponse.addProperty("message", message);

            response.getWriter().write(errorResponse.toString());
        };
    }
}


