package com.springboot.jwttoken.app.controllers;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/app")
public class App {

    // Ruta que puede acceder sin autenticacion
    @GetMapping("/publica")
    public ResponseEntity<?> publicRoute() {
        return ResponseEntity.ok("Ruta publica para todos");
    }

    // Ruta que puede acceder usuarios con rol admin y users
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @GetMapping("/privada")
    public ResponseEntity<?> privateRoute() {
        return ResponseEntity.ok("¡Te haz logeado correctamente!");
    }

    // Ruta que solo puede acceder usuarios admin
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<?> adminRoute() {
            return ResponseEntity.ok("Ruta solo para admin");
    }

}
