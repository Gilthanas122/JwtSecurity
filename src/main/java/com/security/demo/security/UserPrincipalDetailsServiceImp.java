package com.security.demo.security;

import com.security.demo.models.User;
import com.security.demo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserPrincipalDetailsServiceImp implements UserDetailsService {
  private UserService userService;

  @Autowired
  public UserPrincipalDetailsServiceImp(UserService userService) {
    this.userService = userService;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    if (userService.findByUserName(username) == null) {
      throw new UsernameNotFoundException("Could not find user with userName " + username);
    }
    User user = userService.findByUserName(username);
    UserPrincipal userPrincipal = new UserPrincipal(user);
    return userPrincipal;
  }
}
