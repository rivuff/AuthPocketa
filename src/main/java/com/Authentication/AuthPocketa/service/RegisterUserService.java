package com.Authentication.AuthPocketa.service;

import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.Authentication.AuthPocketa.entity.Role;
import com.Authentication.AuthPocketa.entity.User;
import com.Authentication.AuthPocketa.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service 
@RequiredArgsConstructor 
public class RegisterUserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public User registerUser(String email, String password){

        if(userRepository.existsByEmail(email)){
            throw new RuntimeException("User already exists");
        }

        User user = new User();

        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));

        user.setRoles(Set.of(Role.USER));

        return userRepository.save(user);
    }

    public User findByEmail(String email){
        if(!userRepository.existsByEmail(email)){
            throw new RuntimeException("User not found");
        }

        return userRepository.findByEmail(email).get();

    }
}
