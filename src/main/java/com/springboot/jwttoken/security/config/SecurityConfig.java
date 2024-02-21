package com.springboot.jwttoken.security.config;

import com.springboot.jwttoken.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

// Habilita la configuracion de spring security
@EnableWebSecurity
// Habilita la configuracion para hacer uso de de @anotaciones
@EnableMethodSecurity(prePostEnabled = true)
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    // FIltro que se encargara de validar el token
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    // FIltro que se encargara de validar las credenciales
    private final AuthenticationProvider authenticationProvider;

    // Primer filtro que es filterchain
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity.authorizeHttpRequests(http -> {
            http
                    .requestMatchers("/auth/**", "/app/publica").permitAll()
                    .anyRequest().authenticated();
        })
                .csrf(csrf -> csrf.disable())
                .sessionManagement(
                        sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                // FIltro de jwt
                .addFilterAfter(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

}
