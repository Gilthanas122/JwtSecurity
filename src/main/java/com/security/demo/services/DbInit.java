package com.security.demo.services;

import com.security.demo.models.User;
import com.security.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DbInit implements CommandLineRunner {
  @Autowired
  private UserRepository userRepository;
  @Override
  public void run(String... args) throws Exception {
    userRepository.save(new User("pityu",passwordEncoder().encode("pityu123"), "USER", "" ));
  }
  
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
