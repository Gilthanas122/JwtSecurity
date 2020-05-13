package com.security.demo.controllers;

import com.security.demo.models.User;
import com.security.demo.services.UserService;
import org.springframework.security.access.annotation.Secured;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
public class Controller {
  private UserService userService;

  public Controller(UserService userService) {
    this.userService = userService;
  }

  @GetMapping("/")
  @ResponseBody
  public String tryMe(){
    return "ll";
  }

  @PostMapping("user")
  public Long createUser(@RequestBody User user){
    if (!userService.isUserNameUnique(user.getUsername())){
      user.setRoles("USER");
      userService.saveUser(user);
    }
    return userService.findByUserName(user.getUsername()).getId();
  }


  @GetMapping("user/{id}")
  @ResponseBody
  @Secured("ROLE_USER")
  public String getUserById(@PathVariable("id") Long id){
    if (userService.findById(id) != null){
      return userService.findById(id).getUsername();
    }
    return null;
  }
}
