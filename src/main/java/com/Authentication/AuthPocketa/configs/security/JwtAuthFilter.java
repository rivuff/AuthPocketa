package com.Authentication.AuthPocketa.configs.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.Authentication.AuthPocketa.service.UserService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component 
@RequiredArgsConstructor 
public class JwtAuthFilter extends OncePerRequestFilter{

    private final JwtUtil jwtUtil;
    private final UserService userService;
    @Override 
    protected void doFilterInternal(
        HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{
            final String authheader = request.getHeader("Authorization");

            String jwt = null;
            String email = null;

            if(authheader !=null && authheader.startsWith("Bearer ")){
                jwt = authheader.substring(7);

                if(jwt == null || jwt.trim().isEmpty()){
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid JWT token");
                    return;
                }

                try {
                    email = jwtUtil.extractEmail(jwt);
                } catch (Exception e) {
                    // TODO: handle exception
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid JWT token");
                    return;
                }
            }

            if(email!=null && SecurityContextHolder.getContext().getAuthentication() == null){
                try {
                    UserDetails userDetails = userService.loadUserByUsername(email);

                    if(jwtUtil.validateToken(jwt, userDetails)){
                        UsernamePasswordAuthenticationToken authenticationToken = 
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                            

                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }else{
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("Invalid JWT token");
                        return;
                    }
                } catch (Exception e) {
                    // TODO: handle exception
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid JWT token");
                    return;
                }

                

            }

            filterChain.doFilter(request, response);
        }
}
