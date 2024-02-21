package com.springboot.jwttoken.security.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;

import java.util.Collection;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private static final SecretKey SECRET_KEY = Jwts.SIG.HS256.key().build();

    // Genera el token
    public String generateToken(UserDetails userDetails) {
        // Obtiene los reoles del usuario
        Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();
        Claims claims = Jwts.claims().add("authorities", roles).build();

        // Genera el token
        String token = Jwts.builder()
                .subject(userDetails.getUsername())
                .claims(claims)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(SECRET_KEY)
                .compact();
        // Devuelve el token
        return token;
    }

    // Extrae el subjec del token
    public static String extractUsername(String token) {
        return getTokenBody(token).getSubject();
    }

    // Valida el token
    public static Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    // Obtiene el token del request y lo verify
    private static Claims getTokenBody(String token) {
        try {
            return Jwts
                    .parser()
                    .verifyWith(SECRET_KEY)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (SignatureException | ExpiredJwtException e) {
            throw new AccessDeniedException("Acceso denegado: El token no es válido o tiene un formato incorrecto ");
        }
    }

    // Comprueba que el token no haya expirado
    private static boolean isTokenExpired(String token) {
        Claims claims = getTokenBody(token);
        return claims.getExpiration().before(new Date());
    }

}
