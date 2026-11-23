package com.Authentication.AuthPocketa.controller;

import java.util.Set;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthPocketa.Dto.LoginUserRequestDTO;
import com.Authentication.AuthPocketa.Dto.RegisterUserRequestDTO;
import com.Authentication.AuthPocketa.configs.security.JwtUtil;
import com.Authentication.AuthPocketa.entity.Role;
import com.Authentication.AuthPocketa.entity.User;
import com.Authentication.AuthPocketa.service.RegisterUserService;
import com.Authentication.AuthPocketa.service.UserService;

import lombok.RequiredArgsConstructor;

@RestController 
@RequestMapping("/api/v1")
@RequiredArgsConstructor 
public class AuthController {
    
    private final UserService userService;
    private final RegisterUserService registerUserService;

    private final JwtUtil jwtUtil;

    private final AuthenticationManager authenticationManager;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody RegisterUserRequestDTO registerUserRequestDTO){
        User user = registerUserService.registerUser(registerUserRequestDTO.getUsername(), registerUserRequestDTO.getPassword());
        return ResponseEntity.ok(user);
    }

    @GetMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginUserRequestDTO loginUserRequestDTO){

        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginUserRequestDTO.getUsername(), loginUserRequestDTO.getPassword())
        );



        UserDetails userDetails = userService.loadUserByUsername(loginUserRequestDTO.getUsername());

        Set<Role> roles = userDetails.getAuthorities().stream().map(auth -> Role.valueOf(auth.getAuthority())).collect(Collectors.toSet());

        String token = jwtUtil.generateToken(loginUserRequestDTO.getUsername(), roles);

        System.out.println("Token generated successfully");


        return ResponseEntity.ok(token);
    }
}
