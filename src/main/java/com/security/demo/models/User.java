package com.security.demo.models;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.validation.constraints.NotEmpty;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
public class User extends Object {

  @Id
  @GeneratedValue
  private long id;

  @Column(nullable = false)
  @NotEmpty
  private String username;
  @Column(nullable = false)
  @NotEmpty
  private String password;

  private int active;

  private String roles = "";
  private String authorities = "";

  public User() {
    this.active = 1;
  }

  public User(String username, String password) {
    this.username = username;
    this.password = password;
    this.roles = "USER";
    this.active = 1;
  }

  public User(String username, String password, String roles, String authorities) {
    this.username = username;
    this.password = password;
    this.roles = roles;
    this.authorities = authorities;
    this.active = 1;
  }

  public long getId() {
    return id;
  }

  public void setId(long id) {
    this.id = id;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public int getActive() {
    return active;
  }

  public void setActive(int active) {
    this.active = active;
  }

  public List<String> getRolesList() {
    if (this.roles.length() > 0) {
      return Arrays.asList(this.roles.split(","));
    }
    return new ArrayList<>();
  }

  public List<String> getAuthoritiesList() {
    if (this.authorities.length() > 0) {
      return Arrays.asList(this.authorities.split(","));
    }
    return new ArrayList<>();
  }

  public void setRoles(String roles) {
    this.roles = roles;
  }

  public String getAuthorities() {
    return authorities;
  }

  public void setAuthorities(String authorities) {
    this.authorities = authorities;
  }

  public String getRoles() {
    return roles;
  }

}
