package com.Authentication.AuthPocketa.configs.security;

import java.security.Key;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.Authentication.AuthPocketa.entity.Role;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.SignatureException;

@Component 
public class JwtUtil {
    
    @Value("${jwt.secret}")
    private String secret;

    @Value ("${jwt.expiration}")
    private Long expiration;

    public String generateToken(String email, Set<Role> roles){
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("role", roles.stream().map(Role::name).collect(Collectors.toList()));
        return createToken(claims, email);
    }

    public String extractEmail(String token){
        return extractCLaims(token).get("email").toString();
    }

    public Date extractExpiration(String token){
        return extractCLaims(token).getExpiration();
    }

    public boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private SecretKey getSigningKey(){
        byte[] bytes = secret.getBytes();
        return Keys.hmacShaKeyFor(bytes);
    }

    public boolean validateToken(String token, UserDetails userDetails){
        final String email = extractEmail(token);

        boolean isTokenExpired = isTokenExpired(token);

        boolean userNameMatches = userDetails.getUsername().equals(email);
        
        if (userNameMatches && isTokenExpired) {
            return true;
        }

        return false;
    }

    private String createToken(Map<String, Object> claims, String email){
        return Jwts.builder()
                    .claims(claims)
                    .subject(email)
                    .issuedAt(new Date(System.currentTimeMillis()))
                    .expiration(new Date(System.currentTimeMillis()+ expiration))
                    .signWith(getSigningKey())
                    .compact();
    }

    public Claims extractCLaims(String token) throws JwtException{

        try {
            return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).getPayload();
        } catch (SignatureException e) {
            // TODO: handle exception
            throw new JwtException("Invalid JWT signature exception");
        }catch(MalformedKeyException e){
            throw new JwtException("Key is malformed");
        }catch(ExpiredJwtException e){
            throw new JwtException("Key is already expired");
        }catch(UnsupportedJwtException e){
            throw new JwtException("Unsupported JWT token");
        }
    }
}
