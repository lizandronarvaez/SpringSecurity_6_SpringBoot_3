package com.springboot.jwttoken.security.services;

import com.springboot.jwttoken.security.controllers.AuthResponse;
import com.springboot.jwttoken.security.entities.dto.LoginDto;
import com.springboot.jwttoken.security.entities.dto.RegisterDto;
import com.springboot.jwttoken.security.entities.models.RoleEnum;
import com.springboot.jwttoken.security.entities.models.UserEntity;
import com.springboot.jwttoken.security.repository.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

        // Repositorio consulta base de datos
        private final UserRepository userRepository;
        // Respositorio consultar servicio Jwt
        private final JwtService jwtService;
        // Encriptar la contraseña
        private final PasswordEncoder passwordEncoder;
        // Auhehnticacion
        private final AuthenticationManager authenticationManager;

        @Transactional
        public AuthResponse login(LoginDto loginDto) {
                        // Limpieza de datos
                        String email = loginDto.getEmail().trim().toLowerCase();
                        // Busca el usuario
                        Optional<UserEntity> existingUser = userRepository.findByEmail(email);
                        // Verifica el usuario
                        if (existingUser.isEmpty()) {
                                throw new UsernameNotFoundException(String.format("El email '%s' no esta registrado ", email));
                        }
                        // Toda peticion debe pasar por este primer filtro
                        authenticationManager
                                        .authenticate(new UsernamePasswordAuthenticationToken(email,
                                                        loginDto.getPassword()));
                        // Busca el usuario con el email y lo convierte en un userDetails
                        UserDetails userDetails = existingUser.get();
                        // Nombre de el usuario
                        String fullName=existingUser.get().getFullname();
                        // Reponse con el autheResponse
                        return AuthResponse
                                        .builder()
                                        .fullname(fullName)
                                        .token(jwtService.generateToken(userDetails))
                                        .ok(true)
                                        .build();
        }

        @SuppressWarnings("null")
        @Transactional
        public AuthResponse register(RegisterDto registerDto){
                // Limpieza de datos
                String email = registerDto.getEmail().trim().toLowerCase();
                String fullname = registerDto.getFullname().trim().toLowerCase();
                // Buscamos que el email no esté registrado
                Optional<UserEntity> existingUser = userRepository.findByEmail(email);
                if (existingUser.isPresent()) {
                        throw new DuplicateKeyException(String.format("El email '%s' ya está registrado", email));
                }

                // Crear un objeto UserEntity
                UserEntity userEntity = UserEntity
                                .builder()
                                .fullname(fullname)
                                .email(email)
                                .password(passwordEncoder.encode(registerDto.getPassword()))
                                .role(RoleEnum.ROLE_USER)
                                .build();
                // Guardar el objeto en la base de datos
                userRepository.save(userEntity);
                // Devuelve una respuesta con el token y respuesta
                return AuthResponse
                                .builder()
                                .token(jwtService.generateToken(userEntity))
                                .fullname(fullname)
                                .ok(true)
                                .build();

        }

}
