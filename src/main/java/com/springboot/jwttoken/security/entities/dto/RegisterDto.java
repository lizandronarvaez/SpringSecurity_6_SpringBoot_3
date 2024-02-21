package com.springboot.jwttoken.security.entities.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterDto {

    @NotBlank(message = "Campo nombre no puede estar vacío")
    private String fullname;

    @Email(message = "Formato de Email incorrecto")
    @NotBlank(message = "Campo email no puede estar vacío")
    private String email;

    @NotBlank(message = "Campo password no puede estar vacío")
    @Size(min = 6,max = 20,message = "El password debe tener una longitud entre 6 y 20 carácteres")
    private String password;
}
