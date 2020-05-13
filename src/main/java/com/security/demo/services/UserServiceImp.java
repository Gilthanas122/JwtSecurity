package com.security.demo.services;

import com.security.demo.models.User;
import com.security.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class UserServiceImp implements UserService {
  private UserRepository userRepository;

  @Autowired
  public UserServiceImp(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public List<User> findAllUsers() {
    return (List<User>) userRepository.findAll();
  }

  @Override
  public User findByUserName(String username) {
    return userRepository.findByUsername(username);
  }

  @Override
  public void saveUser(User user) {
    user.setPassword(passwordEncoder().encode(user.getPassword()));
    userRepository.save(user);
  }

  @Override
  public boolean isUserNameUnique(String username) {
    return findAllUsers()
            .stream()
            .anyMatch(user -> user.getUsername().equals(username));
  }

  @Override
  public String getLoggedinUserName() {
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    String username = "";
    if (principal instanceof UserDetails) {
      username = ((UserDetails) principal).getUsername();
    }else {
      username = principal.toString();
    }
    return username;
  }

  @Override
  public User findById(Long id) {
    return userRepository.findById(id).orElse(null);
  }

  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
