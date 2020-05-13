package com.security.demo.exceptions;

import org.springframework.http.HttpStatus;

public class InvalidJwtTokenException extends Exception{
  private HttpStatus httpStatus;
  private Exception exception;
  private String reason;

  public InvalidJwtTokenException(HttpStatus httpStatus, String reason, Exception ex){
    this.httpStatus = httpStatus;
    this.exception = ex;
    this.reason = reason;
  }
}
