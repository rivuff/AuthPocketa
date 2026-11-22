package com.Authentication.AuthPocketa.configs.security;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component 
@RequiredArgsConstructor 
public class JwtAuthFilter extends OncePerRequestFilter{

    private final JwtUtil jwtUtil;
    @Override 
    protected void doFilterInternal(
        HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{
            final String authheader = request.getHeader("Authorization");

            String jwt = null;
            String email = null;

            if(authheader !=null && authheader.startsWith("bearer ")){
                jwt = authheader.substring(7);

                if(jwt == null && jwt.trim().isEmpty()){
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid JWT token");
                    return;
                }

                try {
                    email = jwtUtil.extractEmail(jwt);
                } catch (Exception e) {
                    // TODO: handle exception
                }
            }
        }
}
