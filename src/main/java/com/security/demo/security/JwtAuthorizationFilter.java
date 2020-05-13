package com.security.demo.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.security.demo.exceptions.InvalidJwtTokenException;
import com.security.demo.models.User;
import com.security.demo.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
  private UserRepository userRepository;

  public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
    super(authenticationManager);
    this.userRepository = userRepository;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    // Read the Authorization header, where the JWT token should be
    String header = request.getHeader(JwtProperties.HEADER_STRING);

    // If header does not contain BEARER or is null delegate to Spring impl and exit
    if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
      chain.doFilter(request, response);
      return;
    }

    // If header is present, try grab user principal from database and perform authorization
    Authentication authentication = null;
    try {
      authentication = getUsernamePasswordAuthentication(request);
    } catch (InvalidJwtTokenException e) {
      e.printStackTrace();
    }
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // Continue filter execution
    chain.doFilter(request, response);
  }

  private Authentication getUsernamePasswordAuthentication(HttpServletRequest request) throws InvalidJwtTokenException {
    String token = request.getHeader(JwtProperties.HEADER_STRING)
            .replace(JwtProperties.TOKEN_PREFIX,"");

    if (token != null) {
      // parse the token and validate it
      try {
        String userName = JWT.require(HMAC512(JwtProperties.SECRET.getBytes()))
                .build()
                .verify(token)
                .getSubject();
        if (userName != null) {
          User user = userRepository.findByUsername(userName);
          UserPrincipal principal = new UserPrincipal(user);
          UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userName, null, principal.getAuthorities());
          return auth;
        }
        return null;
      }catch (JWTDecodeException e){
        throw new InvalidJwtTokenException(HttpStatus.INTERNAL_SERVER_ERROR, "Invalid token", new JWTDecodeException("kaki"));
      }


      // Search in the DB if we find the user by token subject (username)
      // If so, then grab user details and create spring auth token using username, pass, authorities/roles

    }
    return null;
  }
}
