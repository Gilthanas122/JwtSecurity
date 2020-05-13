package com.security.demo.security;

import com.security.demo.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserPrincipal implements UserDetails {
  private User user;

  public UserPrincipal(User user) {
    this.user = user;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    List<GrantedAuthority> authorityList = new ArrayList<>();

    this.user.getAuthoritiesList()
            .forEach(p -> {
              GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(p);
              authorityList.add(grantedAuthority);
            });

    this.user.getRolesList()
            .forEach(p -> {
              GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_" + p);
              authorityList.add(grantedAuthority);
            });
    return authorityList;
  }

  @Override
  public String getPassword() {
    return this.user.getPassword();
  }

  @Override
  public String getUsername() {
    return this.user.getUsername();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return this.user.getActive() == 1;
  }
}
