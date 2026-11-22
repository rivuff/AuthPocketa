package com.Authentication.AuthPocketa.Dto;

import org.springframework.stereotype.Component;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data 
public class RegisterUserRequestDTO {
    
    private final String username;
    private final String password;
}
