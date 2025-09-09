package org.example.security2;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@EnableConfigurationProperties(ClientProperties.class)
public class SecurityConfig {

    private final ClientProperties clientProperties;

    public SecurityConfig(ClientProperties clientProperties) {
        this.clientProperties = clientProperties;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationManager authManager) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/autocsr/health").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new ClientAuthFilter(authManager), UsernamePasswordAuthenticationFilter.class)
                .build();
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
                        .anyMatch(c -> c.getId().equals(clientId) && c.getSecret().equals(clientSecret));

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
}


