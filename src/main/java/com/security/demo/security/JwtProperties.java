package com.security.demo.security;

public class JwtProperties {
  public static final String SECRET = System.getenv("MY_SECRET_KEY");
  public static final int EXPIRATION_TIME = 180000;
  public static final String TOKEN_PREFIX = "Bearer ";
  public static final String HEADER_STRING = "Authorization";
}
