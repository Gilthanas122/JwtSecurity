package com.security.demo.services;

import com.security.demo.models.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface UserService {

  List<User> findAllUsers();
  User findByUserName(String username);
  void saveUser(User user);
  boolean isUserNameUnique(String username);
  String getLoggedinUserName();

  User findById(Long id);
}
