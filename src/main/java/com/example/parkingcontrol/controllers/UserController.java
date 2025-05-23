package com.example.parkingcontrol.controllers;

import com.example.parkingcontrol.models.UserModel;
import com.example.parkingcontrol.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping
    public ResponseEntity<Object> saveUser(@RequestBody UserModel userModel){
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.save(userModel));
    }
}
