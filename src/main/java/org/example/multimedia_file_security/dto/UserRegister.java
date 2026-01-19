package org.example.multimedia_file_security.dto;


import lombok.Data;

@Data
public class UserRegister {

    private String username;

    private String email;

    private String password;

    private String confirmPassword;
}